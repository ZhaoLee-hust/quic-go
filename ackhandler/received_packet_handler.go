package ackhandler

import (
	"errors"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

var errInvalidPacketNumber = errors.New("ReceivedPacketHandler: Invalid packet number")

type receivedPacketHandler struct {
	// 被观测到的最大数据包号
	largestObserved protocol.PacketNumber
	lowerLimit      protocol.PacketNumber
	// 最大观测到数据包时间
	largestObservedReceivedTime time.Time

	// history只存pn，不存内容
	packetHistory          *receivedPacketHistory  // history只存pn，不存内容
	recoveredPacketHistory *recoveredPacketHistory // history只存pn，不存内容

	ackSendDelay time.Duration // ack延时，设置为25ms
	// 什么延时这是
	recoveredSendDelay time.Duration

	packetsReceivedSinceLastAck int // 从上一次ack之后，接收的数据包个数

	packetsReceivedSinceLastRecovered int // 从上一次恢复之后，接收的数据包个数

	retransmittablePacketsReceivedSinceLastAck int // 从上一次ack之后，可重传的数据包个数

	ackQueued bool // ack队列

	recoveredQueued bool // 恢复队列

	ackAlarm time.Time // ack报警时间

	recoveredAlarm time.Time // 恢复时间

	lastAck *wire.AckFrame // 最新的ack帧

	lastRecovered *wire.RecoveredFrame // 最新的恢复帧
	// 如果设置为true，则在恢复源符号时将发送恢复的帧，在之前的测试中都设置为true了
	disableRecoveredFrames bool
	version                protocol.VersionNumber

	packets          uint64
	recoveredPackets uint64
}

// NewReceivedPacketHandler creates a new receivedPacketHandler
func NewReceivedPacketHandler(version protocol.VersionNumber, disableRecoveredFrames bool) ReceivedPacketHandler {
	return &receivedPacketHandler{
		packetHistory:          newReceivedPacketHistory(),
		recoveredPacketHistory: newRecoveredPacketHistory(),
		ackSendDelay:           protocol.AckSendDelay,
		recoveredSendDelay:     protocol.AckSendDelay,
		disableRecoveredFrames: disableRecoveredFrames,
		version:                version,
	}
}

// returns (receivedPackets, recoveredPackets)
func (h *receivedPacketHandler) GetStatistics() (uint64, uint64) {
	return h.packets, h.recoveredPackets
}

/*
shouldInstigateAck=!pkt.recovered && (isRetransmittable || containsOnlyFECFrames)
满足条件1：数据包未被恢复且
满足条件2：可重传，或只包含FEC帧
即：恢复的数据包不触发ACK；数据包可重传，或者只包含FEC帧，会触发ACK。恢复的数据包来自FEC框架
只包含FEC帧的数据包需要触发ACK，因为可能这个路径是专门用来发送FEC帧的
*/
func (h *receivedPacketHandler) ReceivedPacket(packetNumber protocol.PacketNumber, shouldInstigateAck bool, recovered bool) error {
	if packetNumber == 0 {
		return errInvalidPacketNumber
	}

	// A new packet was received on that path and passes checks, so count it for stats
	h.packets++
	if recovered {
		h.recoveredPackets++
	}

	if packetNumber > h.largestObserved {
		h.largestObserved = packetNumber
		h.largestObservedReceivedTime = time.Now()
	}

	// 说明了什么？
	if packetNumber <= h.lowerLimit {
		return nil
	}

	//disableRecoveredFrames之前的实验中都设置为了true
	// 当设置为false，可以正常地考虑recover，如果设置为true，就不会考虑数据包的恢复
	if h.disableRecoveredFrames || !recovered {
		// we received a packet normally
		if err := h.packetHistory.ReceivedPacket(packetNumber); err != nil {
			return err
		}
		h.maybeQueueAck(packetNumber, shouldInstigateAck)
	} else {
		utils.Infof("MAYBE QUEUE RECOVERED FRAME")
		// we received a packet by recovering it
		if err := h.recoveredPacketHistory.RecoveredPacket(packetNumber); err != nil {
			return err
		}
		h.maybeQueueRecovered(packetNumber, recovered)
	}
	return nil
}

// SetLowerLimit sets a lower limit for acking packets.
// Packets with packet numbers smaller or equal than p will not be acked.
// 接收到StopWaitingFrame后调用，删除history在这之前的数据包
func (h *receivedPacketHandler) SetLowerLimit(p protocol.PacketNumber) {
	h.lowerLimit = p
	h.packetHistory.DeleteUpTo(p)
	h.recoveredPacketHistory.DeleteUpTo(p)
}

// 当接收了一个非恢复的数据包即正常发送的数据包时，或者当disableRecoveredFrames设置为true，就忽略recover字段
func (h *receivedPacketHandler) maybeQueueAck(packetNumber protocol.PacketNumber, shouldInstigateAck bool) {
	h.packetsReceivedSinceLastAck++

	if shouldInstigateAck {
		h.retransmittablePacketsReceivedSinceLastAck++
	}

	// always ack the first packet
	if h.lastAck == nil {
		h.ackQueued = true
	}

	if h.version < protocol.Version39 {
		/*
			始终每20个数据包发送一次ack，以允许对等方丢弃SentPacketManager中的信息并提供RTT测量。
			从QUIC39，这不再需要，因为对等体将定期发送可重传的数据包。
		*/
		// Always send an ack every 20 packets in order to allow the peer to discard
		// information from the SentPacketManager and provide an RTT measurement.
		// From QUIC 39, this is not needed anymore, since the peer will regularly send a retransmittable packet.
		if h.packetsReceivedSinceLastAck >= protocol.MaxPacketsReceivedBeforeAckSend {
			h.ackQueued = true
		}
	}

	// if the packet number is smaller than the largest acked packet, it must have been reported missing with the last ACK
	// note that it cannot be a duplicate because they're already filtered out by ReceivedPacket()
	if h.lastAck != nil && packetNumber < h.lastAck.LargestAcked {
		h.ackQueued = true
	}

	// check if a new missing range above the previously was created
	if h.lastAck != nil && h.packetHistory.GetHighestAckRange().First > h.lastAck.LargestAcked {
		h.ackQueued = true
	}

	if !h.ackQueued && shouldInstigateAck {
		if h.retransmittablePacketsReceivedSinceLastAck >= protocol.RetransmittablePacketsBeforeAck {
			h.ackQueued = true
		} else {
			if h.ackAlarm.IsZero() {
				h.ackAlarm = time.Now().Add(h.ackSendDelay)
			}
		}
	}

	if h.ackQueued {
		// cancel the ack alarm
		h.ackAlarm = time.Time{}
	}
}
func (h *receivedPacketHandler) maybeQueueRecovered(packetNumber protocol.PacketNumber, hasbeenRecovered bool) {
	h.packetsReceivedSinceLastRecovered++

	if !hasbeenRecovered {
		return
	}
	utils.Infof("queue recovered packet %d", packetNumber)

	// always ack the first packet
	if h.lastRecovered == nil {
		h.recoveredQueued = true
	}

	if h.version < protocol.Version39 {
		// Always send an ack every 20 packets in order to allow the peer to discard
		// information from the SentPacketManager and provide an RTT measurement.
		// From QUIC 39, this is not needed anymore, since the peer will regularly send a retransmittable packet.
		if h.packetsReceivedSinceLastRecovered >= protocol.MaxPacketsReceivedBeforeAckSend {
			h.recoveredQueued = true
		}
	}

	// if the packet number is smaller than the largest acked packet, it must have been reported missing with the last ACK
	// note that it cannot be a duplicate because they're already filtered out by ReceivedPacket()
	if h.lastRecovered != nil && packetNumber < h.lastRecovered.RecoveredRanges[0].Last {
		h.recoveredQueued = true
	}

	// check if a new missing range above the previously was created
	if h.lastRecovered != nil && h.recoveredPacketHistory.GetHighestRecoveredRange().First > h.lastRecovered.RecoveredRanges[0].Last {
		h.recoveredQueued = true
	}

	if !h.recoveredQueued {
		if h.recoveredAlarm.IsZero() {
			h.recoveredAlarm = time.Now().Add(h.recoveredSendDelay)
		}
	}

	if h.recoveredQueued {
		// cancel the ack alarm
		h.recoveredAlarm = time.Time{}
	}
}

func (h *receivedPacketHandler) GetAckFrame() *wire.AckFrame {
	if !h.ackQueued && (h.ackAlarm.IsZero() || h.ackAlarm.After(time.Now())) {
		return nil
	}

	// 如果ackqueued，会往下运行
	// acklarm不是zero且已经超时，会往下运行

	ackRanges := h.packetHistory.GetAckRanges()
	ack := &wire.AckFrame{
		LargestAcked:       h.largestObserved,
		LowestAcked:        ackRanges[len(ackRanges)-1].First,
		PacketReceivedTime: h.largestObservedReceivedTime,
	}

	if len(ackRanges) > 1 {
		ack.AckRanges = ackRanges
	}

	h.lastAck = ack
	h.ackAlarm = time.Time{}
	h.ackQueued = false
	h.packetsReceivedSinceLastAck = 0
	h.retransmittablePacketsReceivedSinceLastAck = 0

	return ack
}

// session调用，get之后立刻发送
func (h *receivedPacketHandler) GetRecoveredFrame() *wire.RecoveredFrame {
	if !h.recoveredQueued {
		return nil
	} //如果recoveredQueued，继续运行
	if !h.recoveredQueued && (h.recoveredAlarm.IsZero() || h.recoveredAlarm.After(time.Now())) {
		return nil
	} //RecoveryAlarm不是zero且已经超时，会往下运行

	recoveredRanges := h.recoveredPacketHistory.GetRecoveredRanges()
	recovered := &wire.RecoveredFrame{}

	if len(recoveredRanges) >= 1 {
		recovered.RecoveredRanges = recoveredRanges
	} else {
		utils.Infof("no range")
		h.recoveredQueued = false
		return nil
	}

	h.lastRecovered = recovered
	h.recoveredAlarm = time.Time{}
	h.recoveredQueued = false
	h.packetsReceivedSinceLastRecovered = 0

	return recovered
}

func (h *receivedPacketHandler) GetAlarmTimeout() time.Time { return h.ackAlarm }

// 只是log一下，没有真的发送
func (h *receivedPacketHandler) SentRecoveredFrame(f *wire.RecoveredFrame) {
	if f == nil {
		return
	}
	utils.Infof("sent recovered frame")
}
