package ackhandler

import (
	"errors"
	"fmt"
	"time"

	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/qerr"
)

const (
	// Maximum reordering in time space before time based loss detection considers a packet lost.
	// In fraction of an RTT.
	// 乱序时间阈值的倍率
	timeReorderingFraction = 1.0 / 8
	// The default RTT used before an RTT sample is taken.
	// Note: This constant is also defined in the congestion package.
	defaultInitialRTT = 100 * time.Millisecond
	// defaultRTOTimeout is the RTO time on new connections
	defaultRTOTimeout = 500 * time.Millisecond
	// Minimum time in the future a tail loss probe alarm may be set for.
	minTPLTimeout = 10 * time.Millisecond
	// Minimum time in the future an RTO alarm may be set for.
	minRTOTimeout = 200 * time.Millisecond
	// maxRTOTimeout is the maximum RTO time
	maxRTOTimeout = 60 * time.Second
	// Sends up to two tail loss probes before firing a RTO, as per
	// draft RFC draft-dukkipati-tcpm-tcp-loss-probe
	maxTailLossProbes = 2
	// TCP RFC calls for 1 second RTO however Linux differs from this default and
	// define the minimum RTO to 200ms, we will use the same until we have data to
	// support a higher or lower value
	minRetransmissionTime = 200 * time.Millisecond
	// Minimum tail loss probe time in ms
	minTailLossProbeTimeout = 10 * time.Millisecond

	// EXPERIMENTAL (see draft quic-recovery version 16)
	kReorderingThreshold = 3
)

var (
	// ErrDuplicateOrOutOfOrderAck occurs when a duplicate or an out-of-order ACK is received
	ErrDuplicateOrOutOfOrderAck = errors.New("SentPacketHandler: Duplicate or out-of-order ACK")
	// ErrTooManyTrackedSentPackets occurs when the sentPacketHandler has to keep track of too many packets
	ErrTooManyTrackedSentPackets = errors.New("Too many outstanding non-acked and non-retransmitted packets")
	// ErrAckForSkippedPacket occurs when the client sent an ACK for a packet number that we intentionally skipped
	ErrAckForSkippedPacket = qerr.Error(qerr.InvalidAckData, "Received an ACK for a skipped packet number")
	errAckForUnsentPacket  = qerr.Error(qerr.InvalidAckData, "Received ACK for an unsent package")
)

var errPacketNumberNotIncreasing = errors.New("Already sent a packet with a higher packet number")

type sentPacketHandler struct {
	// 上一个发送的数据包的pn
	lastSentPacketNumber protocol.PacketNumber
	// 注意：递增排序
	// 一次发送的数据包的pn和本数据包的pn之间的数据包，标记为跳过的数据包号
	// 也为其设置了gc
	skippedPackets []protocol.PacketNumber
	// 自上一个可重传的数据包开始的不可重传的数据包
	numNonRetransmittablePackets int // number of non-retransmittable packets since the last retransmittable packet
	// the largest packetnumber that has been acked
	LargestAcked protocol.PacketNumber

	largestReceivedPacketWithAck protocol.PacketNumber

	// 是一个packet的list
	packetHistory      *PacketList
	stopWaitingManager stopWaitingManager

	// 阈值控制器
	QUICLRController *QUICLRController

	retransmissionQueue []*Packet
	// 类型为ByteCount
	bytesInFlight protocol.ByteCount
	// 拥塞算法
	congestion congestion.SendAlgorithm
	// 统计rtt
	rttStats *congestion.RTTStats

	// RTO的回调函数，func(time.Time) bool
	onRTOCallback func(time.Time) bool

	handshakeComplete bool
	// The number of times the handshake packets have been retransmitted without receiving an ack.
	// 没有接收到ACK的握手包的被重传次数
	handshakeCount uint32
	// The number of times an RTO has been sent without receiving an ack.
	rtoCount uint32

	// The number of times a TLP has been sent without receiving an ACK
	tlpCount uint32

	// TLP:tail loss probe
	// Was the alarm coming from the TLP computation?
	// TLP算法会在TCP还是Open状态的时候，设置一个Probe TimeOut (PTO)。
	// 当链路中有未被确认的数据包，同时在PTO时间内未收到任何ACK，则会触发PTO
	// 超时处理机制。
	// TLP会选择传输序号最大的一个数据包作为tail loss probe包，这个序号最大的包可能是
	// 一个可以发送的新的数据包，也可能是一个重传包。
	// TLP通过这样一个tail loss probe包，如果能够收到相应的ACK，则会触发FR机制，而不是RTO机制。
	tlpAlarm bool

	// The time at which the next packet will be considered lost based on early transmit or exceeding the reordering window in time.
	lossTime time.Time

	// The time the last packet was sent, used to set the retransmission timeout
	// 用于设置重传超时
	lastSentTime time.Time

	// The alarm timeout
	alarm time.Time

	// Packet Lost call back for FEC RedundancyController
	// FEC冗余控制器的丢包回调函数
	onPacketLost func(protocol.PacketNumber)
	// Packet Received call back for FEC RedundancyController
	// FEC冗余控制器的收包回调函数
	onPacketReceived func(protocol.PacketNumber)

	// uint64，指示数据包个数
	packets uint64
	// 重传个数
	retransmissions uint64
	// 丢失个数
	losses uint64
	// 确认的symbol数量
	ackedSymbol uint64

	// 是否启用FR，tlp必须启用FR
	useFastRetransmit bool

	// 直接把RDFrame放在这里就可以了
	rdFrame *wire.RDFrame

	// FOR TEST
	RDFrames        [][2]uint16 // dPn,dTn
	SymbolACKFrames [][2]uint64 // nSymbols MaxSymbol
	Thresholds      [][2]uint64 // TimeThreshol PacketThrehsold
	Statistic       [][3]uint64 // Packets Retrans Loss
	SRTTS           []time.Duration
}

var _ SentPacketHandler = &sentPacketHandler{}

// NewSentPacketHandler creates a new sentPacketHandler
// 在path中调用
func NewSentPacketHandler(
	rttStats *congestion.RTTStats,
	cong congestion.SendAlgorithm,
	onRTOCallback func(time.Time) bool,
	onPacketLost func(protocol.PacketNumber),
	onPacketAcked func(protocol.PacketNumber),
	useFastRetransmit bool) SentPacketHandler {
	var congestionControl congestion.SendAlgorithm
	// conn==nil
	// log.Println("cong != nil", cong != nil)
	if cong != nil {
		congestionControl = cong
	} else {
		congestionControl = congestion.NewCubicSender(
			congestion.DefaultClock{},
			rttStats,
			false, /* don't use reno since chromium doesn't (why?) */
			protocol.InitialCongestionWindow,
			protocol.DefaultMaxCongestionWindow,
		)
	}

	handler := &sentPacketHandler{
		packetHistory:      NewPacketList(),
		stopWaitingManager: stopWaitingManager{},
		rttStats:           rttStats,
		congestion:         congestionControl,
		onRTOCallback:      onRTOCallback,
		onPacketLost:       onPacketLost,
		onPacketReceived:   onPacketAcked,
		useFastRetransmit:  useFastRetransmit,
		// QUICLRController: NewThreshController(),
	}

	if protocol.QUIC_LR {
		handler.QUICLRController = NewThreshController(handler.GetStatistics, handler.rttStats)
	}
	return handler
}

// FOR QUIC-RD
func (h *sentPacketHandler) HandleRDFrame(frame *wire.RDFrame) {
	h.rdFrame = frame
	// FOR TEST!
	h.RDFrames = append(h.RDFrames, [2]uint16{frame.MaxDisPlacement, frame.MaxDelay})
}

// FOR QUIC-LR
func (h *sentPacketHandler) ReceiveSymbolAck(frame *wire.SymbolAckFrame, nNumberOfSymbolsSent uint64) {
	h.ackedSymbol = uint64(frame.SymbolReceived)
	if h.QUICLRController != nil {
		h.QUICLRController.updateThreshold(frame)
		utils.Debugf("最新TT: %v, 最新PT: %v \n", h.QUICLRController.getTimeThreshold(), h.QUICLRController.getPacketThreshold())
	}
	// FOR TEST!
	h.SymbolACKFrames = append(h.SymbolACKFrames, [2]uint64{uint64(frame.SymbolReceived), uint64(frame.MaxSymbolReceived)})
}

func (h *sentPacketHandler) GetAckedSymbols() uint64 {
	return h.ackedSymbol
}

// 针对QUIC LR
func (h *sentPacketHandler) GetTransmissionStatistic() ([][2]uint16, [][2]uint64, [][2]uint64, [][3]uint64, []time.Duration) {
	return h.RDFrames, h.SymbolACKFrames, h.Thresholds, h.Statistic, h.SRTTS
}

func (h *sentPacketHandler) GetStatistics() (uint64, uint64, uint64) {
	return h.packets, h.retransmissions, h.losses
}

// 最大按序确认，返回了packetHistory第一个包(除root外)的pn-1，或者LargestAcked
func (h *sentPacketHandler) largestInOrderAcked() protocol.PacketNumber {
	if f := h.packetHistory.Front(); f != nil {
		return f.Value.PacketNumber - 1
	}
	return h.LargestAcked
	// 返回了packetHistory第一个包(除root外)的pn-1，或者LargestAcked
}

// 函数名：应该发送可重传的包
// 返回值：自上次可重传数据包以来不可重传的数据包数 >= 一行中发送的不可重传数据包的最大数量(const 19)？
// 即：若自上次可重传数据包以来不可重传的数据包数大于19,则发送可重传的包
func (h *sentPacketHandler) ShouldSendRetransmittablePacket() bool {
	return h.numNonRetransmittablePackets >= protocol.MaxNonRetransmittablePackets
	// 自上次可重传数据包以来不可重传的数据包数 >= 一行中发送的不可重传数据包的最大数量(const 19)
}

// 设置h.handshakeComplete = true
func (h *sentPacketHandler) SetHandshakeComplete() {
	h.handshakeComplete = true
}

// session直接调用接口，引发一系列操作
func (h *sentPacketHandler) SentPacket(packet *Packet) error {
	// 如果pn比上一次发送的数据包号更小
	if packet.PacketNumber <= h.lastSentPacketNumber {
		// Already sent a packet with a higher packet number
		return errPacketNumberNotIncreasing
	}

	// 如果重传队列长度+数据包历史长度+1(也是pn) > MaxTrackedSentPackets(5000)最大跟踪发送数据包数
	if protocol.PacketNumber(len(h.retransmissionQueue)+h.packetHistory.Len()+1) > protocol.MaxTrackedSentPackets {
		return ErrTooManyTrackedSentPackets
		// Too many outstanding non-acked and non-retransmitted packets
	}

	// 记录下上一次发送的数据包的pn和本数据包的pn之间的数据包，标记为跳过的数据包号
	for p := h.lastSentPacketNumber + 1; p < packet.PacketNumber; p++ {
		h.skippedPackets = append(h.skippedPackets, p)

		// 如果跳过了超过10个
		if len(h.skippedPackets) > protocol.MaxTrackedSkippedPackets {
			// 丢掉第一个
			// 因为是循环，所以是始终最多保留10个，且数据包号最大的10个
			h.skippedPackets = h.skippedPackets[1:]
		}
	}

	// 更新最后一次发送的pn
	// 将本次的这个pn更新为lastSentPacketNumber
	h.lastSentPacketNumber = packet.PacketNumber
	// 并记录下当前时间
	now := time.Now()

	// Update some statistics
	h.packets++

	// XXX RTO and TLP are recomputed based on the possible last sent retransmission. Is it ok like this?
	h.lastSentTime = now
	// 将当前记录的时间记为最后一个数据包的发送时间

	// 从packet的frames判断是否具有可重传或不可靠的流帧，挑选出流帧和其他可重传的帧
	hasRetransmittableOrUnreliableFrames := HasRetransmittableOrUnreliableStreamFrames(packet.Frames)
	// 从packet的frames判断是否具有FEC相关的帧，挑选出FECFrame和RecoveredFrame
	// 挑选RecoveredFrame和FECFrame
	hasFECRelatedFrames := HasFECRelatedFrames(packet.Frames)
	// 剥离不可重传帧，除了不可靠流帧和FEC相关帧，即：挑选出流帧、可重传的帧、与FEC相关的帧，基本上只去掉了StopWaitingFrame、AckFrame
	packet.Frames = stripNonRetransmittableExceptedUnrealiableStreamFramesOrFECRelatedFrames(packet.Frames)
	// 也就是说，本实现中FEC帧属于需要重传的帧？
	isRetransmittable := len(packet.Frames) != 0

	// 如果有流帧、其他可重传的帧、FEC相关的帧
	if hasRetransmittableOrUnreliableFrames || hasFECRelatedFrames {
		// 记录发送时间
		packet.SendTime = now
		// 增加飞翔中的比特
		h.bytesInFlight += packet.Length
		// 将数据包加到Packetist的队尾
		h.packetHistory.PushBack(*packet)
		// 不可重传数据包的数量
		h.numNonRetransmittablePackets = 0
	} else {
		// 如果没有，则不可重传数据包的数量加一
		h.numNonRetransmittablePackets++
	}

	// 调用拥塞控制算法
	// cubic: basically, if isRetransmittable return true
	h.congestion.OnPacketSent(
		now,
		h.bytesInFlight,
		packet.PacketNumber,
		packet.Length,
		isRetransmittable,
	)
	h.updateLossDetectionAlarm()
	return nil
}

// 由session handleRecoveredFrame函数直接调用
func (h *sentPacketHandler) ReceivedRecoveredFrame(frame *wire.RecoveredFrame, encLevel protocol.EncryptionLevel) error {
	// don't update the rtt because the recovery may have delayed the ack
	// 不要更新rtt，因为恢复可能会延迟ack
	ackedPackets, err := h.determineRecoveredPackets(frame)
	if err != nil {
		return err
	}
	utils.Infof("recovered packets = %+v", ackedPackets)

	// frame.RecoveredRanges[0].Last是最大的，frame.RecoveredRanges[-1].first是最小的
	// 更新最大acked的数据包
	if frame.RecoveredRanges[0].Last > h.LargestAcked {
		h.LargestAcked = frame.RecoveredRanges[0].Last
	}
	if len(ackedPackets) > 0 {
		for _, p := range ackedPackets {
			if encLevel < p.Value.EncryptionLevel {
				return fmt.Errorf("Received ACK with encryption level %s that acks a packet %d (encryption level %s)", encLevel, p.Value.PacketNumber, p.Value.EncryptionLevel)
			}
			// 从history删除这个数据包;如果这个数据包有可重传帧或者FEC帧,则bytesInFlight减少一个数据包
			h.onPacketRecovered(p) // =h.onPacketAcked(p)
			// TODO: maybe trigger the onPacketLost for the redundancy controller
			// the packet has been lost, then recovered. This might be due to congestion.
			utils.Infof("consider the recovered packet %d as lost for the congestion control", p.Value.PacketNumber)
			// (n,k)的n丢失了然后被恢复了，发送端要考虑到n的丢失
			h.congestion.OnPacketLost(p.Value.PacketNumber, p.Value.Length, h.bytesInFlight)
		}
	}

	h.detectLostPackets()
	utils.Infof("running in func ReceivedRecoveredFrame,sent_packet_handler.go, line =?233")
	h.updateLossDetectionAlarm()

	h.garbageCollectSkippedPackets()
	h.stopWaitingManager.ReceivedRecovered(frame)

	return nil
}

// session中handleAckFrame调用,第二个参数是最新收到的PN
func (h *sentPacketHandler) ReceivedAck(ackFrame *wire.AckFrame, withPacketNumber protocol.PacketNumber, encLevel protocol.EncryptionLevel, rcvTime time.Time) error {
	// ack了还未发送的数据包
	if ackFrame.LargestAcked > h.lastSentPacketNumber {
		println("Ack saw largest was 0x%x but path actually saw 0x%x\n", ackFrame.LargestAcked, h.lastSentPacketNumber)
		return errAckForUnsentPacket
	}

	// duplicate or out-of-order ACK
	// withPacketNumber是最大接收,如果小于handler统计过的最大接收,说明重复ack了,这个参数从path传过来的
	if withPacketNumber <= h.largestReceivedPacketWithAck {
		return ErrDuplicateOrOutOfOrderAck
	}
	// 并更新,回退
	h.largestReceivedPacketWithAck = withPacketNumber

	// ignore repeated ACK (ACKs that don't have a higher LargestAcked than the last ACK)
	// 没有比上次ACK更高LargestAcked的ACK
	if ackFrame.LargestAcked <= h.largestInOrderAcked() {
		// 如果最大确认小于history记录的最大pn(或largest acked)
		return nil
	}
	// 并更新,以frame为准
	h.LargestAcked = ackFrame.LargestAcked

	// 如果ackFrame确认了本应跳过的某个数据包
	if h.skippedPacketsAcked(ackFrame) {
		// Received an ACK for a skipped packet number
		return ErrAckForSkippedPacket
	}

	// 传入:最新确认的pn,delaytime,接收时间
	rttUpdated := h.maybeUpdateRTT(ackFrame.LargestAcked, ackFrame.DelayTime, rcvTime)

	// 如果更新了rtt,需要判断是否退出慢启动
	if rttUpdated {
		h.congestion.MaybeExitSlowStart()
	}

	// 找到最新确认的数据包
	ackedPackets, err := h.determineNewlyAckedPackets(ackFrame)
	if err != nil {
		return err
	}

	// if newly acked pkts
	if len(ackedPackets) > 0 {
		for _, p := range ackedPackets {
			if encLevel < p.Value.EncryptionLevel {
				return fmt.Errorf("Received ACK with encryption level %s that acks a packet %d (encryption level %s)", encLevel, p.Value.PacketNumber, p.Value.EncryptionLevel)
			}
			h.onPacketAcked(p)
			// 调用的冗余控制器的方法
			h.onPacketReceived(p.Value.PacketNumber)
			h.congestion.OnPacketAcked(p.Value.PacketNumber, p.Value.Length, h.bytesInFlight)
		}
	}

	h.detectLostPackets()
	// log.Printf("Modify:running in func ReceivedAck,sent_packet_handler.go, line =?286")
	h.updateLossDetectionAlarm()

	h.garbageCollectSkippedPackets()
	h.stopWaitingManager.ReceivedAck(ackFrame)

	return nil
}

// 返回ackedPackets
// 对于history的每个数据包，如果记录在ackrange里面则append上去
func (h *sentPacketHandler) determineRecoveredPackets(recoveredFrame *wire.RecoveredFrame) ([]*PacketElement, error) {
	var recoveredPackets []*PacketElement
	recoveredRangeIndex := 0
	// 找到这个recoverFrame显示的恢复的数据包的起始序号
	// lowestRecovered取最后一个range的头(first)
	lowestRecovered := recoveredFrame.RecoveredRanges[len(recoveredFrame.RecoveredRanges)-1].First
	// largestRecovered取第一个range的尾(last)
	largestRecovered := recoveredFrame.RecoveredRanges[0].Last
	utils.Infof("determine recovered packets: lowest = %d, largest = %d", lowestRecovered, largestRecovered)
	for el := h.packetHistory.Front(); el != nil; el = el.Next() {
		packet := el.Value
		packetNumber := packet.PacketNumber
		utils.Infof("CHECK FOR PACKET NUMBER %d", packetNumber)
		// Ignore packets below the LowestAcked
		// 如果在history中找到了比ack的最小的数据包号还小的数据包，则不管，遍历下一个
		if packetNumber < lowestRecovered {
			continue
		}
		// 如果在history找到了比ack的最大的数据包号还大的数据包，则直接退出——说明？？？？(待补充)
		// Break after LargestAcked is reached
		if packetNumber > largestRecovered {
			break
		}

		// 取出第recoveredRangeIndex个range
		recoveredRange := recoveredFrame.RecoveredRanges[len(recoveredFrame.RecoveredRanges)-1-recoveredRangeIndex]

		// 定位到当前数据包对应的range
		for packetNumber > recoveredRange.Last && recoveredRangeIndex < len(recoveredFrame.RecoveredRanges)-1 {
			recoveredRangeIndex++
			recoveredRange = recoveredFrame.RecoveredRanges[len(recoveredFrame.RecoveredRanges)-1-recoveredRangeIndex]
		}

		if packetNumber >= recoveredRange.First { // packet i contained in ACK range
			if packetNumber > recoveredRange.Last {
				return nil, fmt.Errorf("BUG: ackhandler would have acked wrong packet 0x%x, while evaluating range 0x%x -> 0x%x", packetNumber, recoveredRange.First, recoveredRange.Last)
			}
			recoveredPackets = append(recoveredPackets, el)
		}
	}

	return recoveredPackets, nil
}

// 找出最新ack的数据包
func (h *sentPacketHandler) determineNewlyAckedPackets(ackFrame *wire.AckFrame) ([]*PacketElement, error) {
	var ackedPackets []*PacketElement
	ackRangeIndex := 0
	// 遍历history
	for el := h.packetHistory.Front(); el != nil; el = el.Next() {
		packet := el.Value
		// 取到pn
		packetNumber := packet.PacketNumber

		// Ignore packets below the LowestAcked
		if packetNumber < ackFrame.LowestAcked {
			continue
		}
		// Break after LargestAcked is reached
		if packetNumber > ackFrame.LargestAcked {
			// 由于是按照pn排列的,说明后面的pn都大于LargestAcked
			break
		}

		// 遍历ranges
		if ackFrame.HasMissingRanges() {
			// 取出第(最后一个-index)个range
			ackRange := ackFrame.AckRanges[len(ackFrame.AckRanges)-1-ackRangeIndex]

			// //定位到这个pn所在的range
			// 当pn大于range的最大值,且index不超过ranges的个数
			for packetNumber > ackRange.Last && ackRangeIndex < len(ackFrame.AckRanges)-1 {
				ackRangeIndex++
				ackRange = ackFrame.AckRanges[len(ackFrame.AckRanges)-1-ackRangeIndex]
			}

			if packetNumber >= ackRange.First { // packet i contained in ACK range
				if packetNumber > ackRange.Last {
					// 出现了bug,和上面的不符合
					return nil, fmt.Errorf("BUG: ackhandler would have acked wrong packet 0x%x, while evaluating range 0x%x -> 0x%x", packetNumber, ackRange.First, ackRange.Last)
				}
				ackedPackets = append(ackedPackets, el)
			}
		} else {
			// means:len(f.AckRanges) = 0, 这个ackrame没有确认任何数据包
			// ????表示怀疑
			ackedPackets = append(ackedPackets, el)
		}
	}

	return ackedPackets, nil
}

// 遍历history,如果发现了某个数据包就是最新确认的,就根据这个数据包来更新rtt
func (h *sentPacketHandler) maybeUpdateRTT(largestAcked protocol.PacketNumber, ackDelay time.Duration, rcvTime time.Time) bool {
	// 遍历history
	for el := h.packetHistory.Front(); el != nil; el = el.Next() {
		packet := el.Value
		// 如果发现了某个数据包就是最新确认的
		if packet.PacketNumber == largestAcked {
			// 就根据这个数据包来更新rtt
			h.rttStats.UpdateRTT(rcvTime.Sub(packet.SendTime), ackDelay, time.Now())
			return true
		}
		// Packets are sorted by number, so we can stop searching
		if packet.PacketNumber > largestAcked {
			break
		}
	}
	return false
}

// 遍历history,如果有某个数据包应该重传,则返回true.注意:FECframe不包含,RecoverFrame不包含
func (h *sentPacketHandler) hasOutstandingRetransmittablePacket() bool {
	// outstanding pakets 指的是history中的可重传的数据包
	for el := h.packetHistory.Front(); el != nil; el = el.Next() {
		if el.Value.IsRetransmittable() {
			return true
		}
	}
	return false
}

// updateLossDetectionAlarm更新丢失检测报警，计算h.alarm的值以及设定tlpAlarm=true/false
func (h *sentPacketHandler) updateLossDetectionAlarm() {
	// 取消警报
	h.tlpAlarm = false
	// Cancel the alarm if no packets are outstanding
	if h.packetHistory.Len() == 0 {
		// 设为0
		h.alarm = time.Time{}
		return
	}
	// 还没完成握手时
	if !h.handshakeComplete {
		// 计算alarm时间，每次翻倍
		h.alarm = time.Now().Add(h.computeHandshakeTimeout())
	} else if !h.lossTime.IsZero() {
		// Early retransmit timer or time loss detection.
		// 用来判断丢失的时间
		h.alarm = h.lossTime
	} else if h.rttStats.SmoothedRTT() != 0 && h.tlpCount < maxTailLossProbes {
		// TLP
		// 设置TLP
		h.tlpAlarm = true
		h.alarm = h.lastSentTime.Add(h.computeTLPTimeout())
	} else {
		// RTO
		// check RTO timer...

		firstPacketTime := h.packetHistory.Front().Value.SendTime
		rtoAlarm := firstPacketTime.Add(utils.MaxDuration(h.ComputeRTOTimeout(), minRetransmissionTime))
		h.alarm = utils.MaxTime(rtoAlarm, time.Now().Add(1*time.Microsecond))

		// ... then look for TLP
		tlpAlarm := h.lastSentTime.Add(utils.MaxDuration(h.ComputeRTOTimeout(), minRetransmissionTime))
		// 如果TLP在RTO之前
		if tlpAlarm.Before(h.alarm) {
			h.alarm = utils.MaxTime(tlpAlarm, time.Now().Add(1*time.Microsecond))
			h.tlpAlarm = true
		}

	}
}

// 根据history,可能会判断loss++,对于丢包,如果不需要重传,则直接ack,否则排队重传并调用冗余控制和拥塞控制
// 当发送时间大于1.25个rtt会被标记为丢包;快传被确认3个包也会
// 全部loss都是从此而来
func (h *sentPacketHandler) detectLostPackets() {
	h.lossTime = time.Time{}
	now := time.Now()

	// maxRTT是LatestRTT和SmoothedRTT的较大者
	maxRTT := float64(utils.MaxDuration(h.rttStats.LatestRTT(), h.rttStats.SmoothedRTT()))

	var timeThreshold float64 = timeReorderingFraction
	var packetThreshold uint16 = kReorderingThreshold

	// QUIC-LR
	if h.QUICLRController != nil {
		timeThreshold = h.QUICLRController.getTimeThreshold()
		pt := h.QUICLRController.getPacketThreshold()
		packetThreshold = uint16(pt)
	}

	delayUntilLost := time.Duration((1.0 + timeThreshold) * maxRTT)

	// QUIC-RD
	if protocol.QUIC_RD && h.rdFrame != nil {
		delayUntilLost = delayUntilLost + time.Millisecond*time.Duration(h.rdFrame.MaxDelay)
		packetThreshold += h.rdFrame.MaxDisPlacement
		utils.Debugf("QUIC-RD Controlling! New time = %v(%v Increased), New PT = %v\n", delayUntilLost.Milliseconds(), h.rdFrame.MaxDelay, packetThreshold)
	}

	if protocol.QUIC_D {
		delayUntilLost = time.Duration((1.0+timeThreshold)*maxRTT + float64(4*h.rttStats.RttVar()))
		utils.Debugf("QUIC-D Controlling! New time = %v(%v Increased)", delayUntilLost.Milliseconds(), 4*h.rttStats.RttVar().Milliseconds())
	}

	// FOR TEST
	h.Thresholds = append(h.Thresholds, [2]uint64{uint64(delayUntilLost.Microseconds()), uint64(packetThreshold)})
	h.Statistic = append(h.Statistic, [3]uint64{h.packets, h.retransmissions, h.losses})
	h.SRTTS = append(h.SRTTS, utils.MaxDuration(h.rttStats.LatestRTT(), h.rttStats.SmoothedRTT()))

	var lostPackets []*PacketElement
	// 遍历history
	for el := h.packetHistory.Front(); el != nil; el = el.Next() {
		packet := el.Value

		// 数据包号大于最大确认,说明还没被确认
		if packet.PacketNumber > h.LargestAcked {
			break
		}

		// 数据包传输时间,是time.duration类
		timeSinceSent := now.Sub(packet.SendTime)
		// 如果使用快传,且最大被确认数大于3,且当前数据包号小于最大确认数-3;从发送到现在的时间大于1.25个maxRTT
		// if (h.useFastRetransmit && h.LargestAcked >= kReorderingThreshold && packet.PacketNumber <= h.LargestAcked-kReorderingThreshold) || timeSinceSent > delayUntilLost {
		if h.QUICLRController != nil {
			var reason LossTrigger
			if h.LargestAcked >= protocol.PacketNumber(packetThreshold) && packet.PacketNumber <= h.LargestAcked-protocol.PacketNumber(packetThreshold) {
				reason = lossByDuplicate
			}
			if timeSinceSent > delayUntilLost {
				reason = lossByDelay
			}
			if reason != noLoss {
				h.QUICLRController.OnPacketLostBy(reason)
			}
		}
		// RACK是默认启用，FACK是可选的，FACK在乱序的时候有很大影响
		if (h.useFastRetransmit &&
			h.LargestAcked >= protocol.PacketNumber(packetThreshold) &&
			packet.PacketNumber <= h.LargestAcked-protocol.PacketNumber(packetThreshold)) ||
			timeSinceSent > delayUntilLost {
			// Update statistics
			// 标记丢包,当发送时间大于1.25个rtt会被标记为丢包;快传被确认3个包也会
			h.losses++
			lostPackets = append(lostPackets, el)
		} else if h.lossTime.IsZero() {
			// Note: This conditional is only entered once per call
			h.lossTime = now.Add(delayUntilLost - timeSinceSent)
		}
	}

	// 对于丢包,如果不需要重传,则直接ack,否则排队重传并调用冗余控制和拥塞控制
	if len(lostPackets) > 0 {
		for _, p := range lostPackets {
			// timeSinceSent := now.Sub(p.Value.SendTime)
			// log.Printf("PACKET LOST: %d, largestAcked = %d, timeSinceSent = %d, delayUntilLost = %d", p.Value.PacketNumber, h.LargestAcked, timeSinceSent, delayUntilLost)
			if !HasRetransmittableFrames(p.Value.Frames) {
				// Copied from h.ReceivedAck
				h.onPacketAcked(p)
			} else {
				h.queuePacketForRetransmission(p)
			}
			// 调用冗余控制器的方法
			h.onPacketLost(p.Value.PacketNumber)
			// 拥塞控制...
			h.congestion.OnPacketLost(p.Value.PacketNumber, p.Value.Length, h.bytesInFlight)
		}
	}
}

// // Specific to multipath operation
// 似乎从来没有运行过
func (h *sentPacketHandler) SetInflightAsLost() {
	// In flight 指的是history的packet,多路径场景被设置为丢包?
	var lostPackets []*PacketElement
	for el := h.packetHistory.Front(); el != nil; el = el.Next() {
		packet := el.Value

		if packet.PacketNumber > h.LargestAcked {
			break
		}

		h.losses++
		lostPackets = append(lostPackets, el)
	}
	// h.tmpcount++
	// log.Println("running in sent_packet_handler, line 777? ,h.tmpcount = ", h.tmpcount)

	if len(lostPackets) > 0 {
		for _, p := range lostPackets {
			h.queuePacketForRetransmission(p)
			// XXX (QDC): should we?
			h.congestion.OnPacketLost(p.Value.PacketNumber, p.Value.Length, h.bytesInFlight)
		}
	}
}

// timerPth调用,在这之前会先调用GetAlarmTimeout
// 会在已经超时后调用
func (h *sentPacketHandler) OnAlarm() {
	// Do we really have packet to retransmit?
	if !h.hasOutstandingRetransmittablePacket() {
		// Cancel then the alarm
		h.alarm = time.Time{}
		return
	}

	// 如果握手未完成,重传+记录重传次数
	if !h.handshakeComplete {
		h.queueHandshakePacketsForRetransmission()
		h.handshakeCount++
	} else if !h.lossTime.IsZero() {
		// Early retransmit or time loss detection
		h.detectLostPackets()
		utils.Infof("Modify:running in func OnAlarm,sent_packet_handler.go,line ?= 507")
		sntPkts, sntRetrans, sntLost := h.GetStatistics()
		utils.Debugf("sntPkts:%d, sntRetrans:%d, sntLost:%d", sntPkts, sntRetrans, sntLost)

	} else if h.tlpAlarm && h.tlpCount < maxTailLossProbes {
		// TLP
		h.retransmitTLP()
		h.tlpCount++
	} else {
		// RTO
		potentiallyFailed := false
		// 判断重传超时
		if h.onRTOCallback != nil {
			// 自从上个发送包之后再无动态
			potentiallyFailed = h.onRTOCallback(h.lastSentTime)
		}
		// 如果超时了,就崇传所有包
		if potentiallyFailed {
			h.retransmitAllPackets()
		} else {
			// 没有超时就重传最久的两个包
			h.retransmitOldestTwoPackets()
		}
		h.rtoCount++
	}

	h.updateLossDetectionAlarm()
}

// timerPth调用
func (h *sentPacketHandler) GetAlarmTimeout() time.Time {
	return h.alarm
}

// 从history删除这个数据包;如果这个数据包有可重传帧或者FEC帧,则bytesInFlight减少一个数据包
func (h *sentPacketHandler) onPacketAcked(packetElement *PacketElement) {
	// 如果这个数据包有可重传帧或者FEC帧
	if HasRetransmittableOrUnreliableStreamFrames(packetElement.Value.Frames) || HasFECRelatedFrames(packetElement.Value.Frames) {
		// bytesInFlight减少一个数据包
		h.bytesInFlight -= packetElement.Value.Length
	}
	h.rtoCount = 0
	h.handshakeCount = 0
	h.tlpCount = 0
	// 从history删除一个数据包
	h.packetHistory.Remove(packetElement)
}

// 返回history的所有包
func (h *sentPacketHandler) GetPacketsInFlight() []*Packet {
	// 返回history的所有包
	var packets = make([]*Packet, 0, h.packetHistory.Len())
	for el := h.packetHistory.Front(); el != nil; el = el.Next() {
		packets = append(packets, &el.Value)
	}
	return packets
}

// 调用h.onPacketAcked(packetElement)
func (h *sentPacketHandler) onPacketRecovered(packetElement *PacketElement) {
	h.onPacketAcked(packetElement)
}

// 取出第一个数据包用于重传并返回该数据包,重传统计加一,在scheduler调用
// 重传全部由此而来
func (h *sentPacketHandler) DequeuePacketForRetransmission() *Packet {
	if len(h.retransmissionQueue) == 0 {
		return nil
	}
	// 取出第一个pkt
	packet := h.retransmissionQueue[0]
	// Shift the slice and don't retain anything that isn't needed.
	copy(h.retransmissionQueue, h.retransmissionQueue[1:])
	h.retransmissionQueue[len(h.retransmissionQueue)-1] = nil
	h.retransmissionQueue = h.retransmissionQueue[:len(h.retransmissionQueue)-1]
	// Update statistics
	h.retransmissions++
	return packet
}

// 返回最小未确认,可能是history的front
func (h *sentPacketHandler) GetLeastUnacked() protocol.PacketNumber {
	return h.largestInOrderAcked() + 1
}

// 返回一个停等frame
func (h *sentPacketHandler) GetStopWaitingFrame(force bool) *wire.StopWaitingFrame {
	return h.stopWaitingManager.GetStopWaitingFrame(force)
}

// 返回bytesInFlight的数量
func (h *sentPacketHandler) GetBytesInFlight() protocol.ByteCount {
	return h.bytesInFlight
}

// 在path、scheduler调用
// return !protocol.APPLY_CONGESTION_CONTROL || !maxTrackedLimited && (!congestionLimited || haveRetransmissions)
func (h *sentPacketHandler) SendingAllowed() bool {
	// 如果history的byte大于CWND,说明被拥塞限制
	congestionLimited := h.bytesInFlight > h.congestion.GetCongestionWindow()
	// 数据包个数限制
	maxTrackedLimited := protocol.PacketNumber(len(h.retransmissionQueue)+h.packetHistory.Len()) >= protocol.MaxTrackedSentPackets
	if congestionLimited {
		utils.Debugf("Congestion limited: bytes in flight %d, window %d",
			h.bytesInFlight,
			h.congestion.GetCongestionWindow())
	}
	// Workaround for #555:
	// Always allow sending of retransmissions. This should probably be limited
	// to RTOs, but we currently don't have a nice way of distinguishing them.
	haveRetransmissions := len(h.retransmissionQueue) > 0
	// 似乎重传不受限于拥塞控制？
	return !protocol.APPLY_CONGESTION_CONTROL || !maxTrackedLimited && (!congestionLimited || haveRetransmissions)
}

// 重传尾部，将history.back加入重传队列
func (h *sentPacketHandler) retransmitTLP() {
	if p := h.packetHistory.Back(); p != nil {
		h.queuePacketForRetransmission(p)
	}
}

// 重传history的所有包,会loss++；h.queueRTO(p)
func (h *sentPacketHandler) retransmitAllPackets() {
	for h.packetHistory.Len() > 0 {
		h.queueRTO(h.packetHistory.Front())
	}
	utils.Debugf("RETRANSMIT ALL PACKETS")
	// 设置重传超时
	h.congestion.OnRetransmissionTimeout(true)
}

// 重传第一个包，会loss++；h.queueRTO(p)
func (h *sentPacketHandler) retransmitOldestPacket() {
	if p := h.packetHistory.Front(); p != nil {
		h.queueRTO(p)
	}
}

// 重传前2个，会loss++；h.queueRTO(p)
func (h *sentPacketHandler) retransmitOldestTwoPackets() {
	utils.Debugf("RETRANSMIT OLDEST TWO")
	h.retransmitOldestPacket()
	h.retransmitOldestPacket()
	h.congestion.OnRetransmissionTimeout(true)
}

// 加入重传队列，并统计丢包，loss++
// 几乎没被调用过
func (h *sentPacketHandler) queueRTO(el *PacketElement) {
	packet := &el.Value
	utils.Debugf(
		"\tQueueing packet 0x%x for retransmission (RTO), %d outstanding",
		packet.PacketNumber,
		h.packetHistory.Len(),
	)
	h.queuePacketForRetransmission(el)
	// 调用冗余控制器的方法
	h.onPacketLost(packet.PacketNumber)
	h.losses++
	// h.tmpcount++
	// log.Println("running in sent_packet_handler, line 777? ,h.tmpcount = ", h.tmpcount)
	h.congestion.OnPacketLost(packet.PacketNumber, packet.Length, h.bytesInFlight)
}

// 根据EncryptionLevel选择性重传HandshakePackets；EncryptionLevel可能是Unencrypted和Secure，但不是ForwardSecure
func (h *sentPacketHandler) queueHandshakePacketsForRetransmission() {
	var handshakePackets []*PacketElement
	for el := h.packetHistory.Front(); el != nil; el = el.Next() {
		if el.Value.EncryptionLevel < protocol.EncryptionForwardSecure {
			handshakePackets = append(handshakePackets, el)
		}
	}
	for _, el := range handshakePackets {
		h.queuePacketForRetransmission(el)
	}
}

// queue之后会从history中删除
func (h *sentPacketHandler) queuePacketForRetransmission(packetElement *PacketElement) {
	packet := &packetElement.Value
	h.bytesInFlight -= packet.Length
	h.retransmissionQueue = append(h.retransmissionQueue, packet)
	h.packetHistory.Remove(packetElement)
	h.stopWaitingManager.QueuedRetransmissionForPacketNumber(packet.PacketNumber)
}

// 将packet添加到retransmissionQueue
func (h *sentPacketHandler) DuplicatePacket(packet *Packet) {
	h.retransmissionQueue = append(h.retransmissionQueue, packet)
}

// 每增加一次握手次数，duration会乘2
func (h *sentPacketHandler) computeHandshakeTimeout() time.Duration {
	duration := 2 * h.rttStats.SmoothedRTT()
	if duration == 0 {
		duration = 2 * defaultInitialRTT
	}
	// duration设置为2个rtt，并取其与minTPLTimeout的最大值
	duration = utils.MaxDuration(duration, minTPLTimeout)
	// exponential backoff
	// There's an implicit limit to this set by the handshake timeout.
	return duration << h.handshakeCount
}

func (h *sentPacketHandler) ComputeRTOTimeout() time.Duration {
	rto := h.congestion.RetransmissionDelay()
	if rto == 0 {
		// 默认500ms
		rto = defaultRTOTimeout
	}
	// minRTOTimeout=200ms
	rto = utils.MaxDuration(rto, minRTOTimeout)
	// Exponential backoff
	rto = rto << h.rtoCount
	// maxRTOTimeout=1min
	return utils.MinDuration(rto, maxRTOTimeout)
}

// history有两个以上的包
func (h *sentPacketHandler) hasMultipleOutstandingRetransmittablePackets() bool {
	return h.packetHistory.Front() != nil && h.packetHistory.Front().Next() != nil
}

// 如果history有两个以上的包，就设置为1.5rtt+0.5minRetransmissionTime(200ms)与2rtt的最大值，否则设置为2rtt和minTailLossProbeTimeout(10ms)的最大值
func (h *sentPacketHandler) computeTLPTimeout() time.Duration {
	rtt := h.congestion.SmoothedRTT()
	if h.hasMultipleOutstandingRetransmittablePackets() {
		return utils.MaxDuration(2*rtt, rtt*3/2+minRetransmissionTime/2)
	}
	return utils.MaxDuration(2*rtt, minTailLossProbeTimeout)
}

// 如果这个ackframe确认了skippedPackets中的某个包,则返回true
func (h *sentPacketHandler) skippedPacketsAcked(ackFrame *wire.AckFrame) bool {
	for _, p := range h.skippedPackets {
		if ackFrame.AcksPacket(p) {
			return true
		}
	}
	return false
}

// 删除跳过的(skippedPackets)序列中已经确认的
func (h *sentPacketHandler) garbageCollectSkippedPackets() {
	lioa := h.largestInOrderAcked()
	deleteIndex := 0
	for i, p := range h.skippedPackets {
		// 如果跳过的数据包的pn小于最新确认的，即已经确认过
		if p <= lioa {
			deleteIndex = i + 1
		}
	}
	// 删除前deleteIndex个
	h.skippedPackets = h.skippedPackets[deleteIndex:]
}

// session会调用,并获取congestion window
func (h *sentPacketHandler) GetSendAlgorithm() congestion.SendAlgorithm {
	return h.congestion
}
