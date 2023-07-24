package quic

import (
	"time"

	"github.com/lucas-clemente/quic-go/ackhandler"
	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/fec"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/qerr"
)

const (
	minPathTimer = 10 * time.Millisecond
	// XXX (QDC): To avoid idling...
	maxPathTimer = 1 * time.Second
)

type path struct {
	pathID protocol.PathID
	conn   connection
	sess   sessionI

	rttStats *congestion.RTTStats

	sentPacketHandler     ackhandler.SentPacketHandler
	receivedPacketHandler ackhandler.ReceivedPacketHandler

	backup utils.AtomicBool

	active    utils.AtomicBool
	closeChan chan *qerr.QuicError

	locAddrID      protocol.AddressID
	remAddrID      protocol.AddressID
	validRemAddrID bool // When the remote announce a lost address, the remAddrID is no more valid until a PATHS frame has been received

	potentiallyFailed utils.AtomicBool
	// The path might be flaky, keep this information
	wasPotentiallyFailed utils.AtomicBool
	// It might be useful to know that this path faced a RTO at some point
	facedRTO utils.AtomicBool

	sentPacket chan struct{}

	// It is now the responsibility of the path to keep its packet number
	packetNumberGenerator *packetNumberGenerator

	lastRcvdPacketNumber protocol.PacketNumber
	// Used to calculate the next packet number from the truncated wire
	// representation, and sent back in public reset packets
	largestRcvdPacketNumber protocol.PacketNumber

	leastUnacked protocol.PacketNumber

	lastNetworkActivityTime time.Time

	timer *utils.Timer

	fec *utils.AtomicBool
}

// FIXME this is why we should change the PathID when network changes...
func (p *path) setupReusePath(oliaSenders map[protocol.PathID]*congestion.OliaSender) {
	var cong congestion.SendAlgorithm

	if p.sess.GetVersion() >= protocol.VersionMP && oliaSenders != nil && p.pathID != protocol.InitialPathID {
		cong = congestion.NewOliaSender(oliaSenders, p.rttStats, protocol.InitialCongestionWindow, protocol.DefaultMaxCongestionWindow)
		oliaSenders[p.pathID] = cong.(*congestion.OliaSender)
	}

	p.active.Set(true)
	p.validRemAddrID = true
	p.potentiallyFailed.Set(false)
	p.wasPotentiallyFailed.Set(false)
	p.facedRTO.Set(false)
}

// setup initializes values that are independent of the perspective
func (p *path) setup(oliaSenders map[protocol.PathID]*congestion.OliaSender, redundancyController fec.RedundancyController) {
	p.rttStats = &congestion.RTTStats{}

	var cong congestion.SendAlgorithm

	if p.sess.GetVersion() >= protocol.VersionMP && oliaSenders != nil && p.pathID != protocol.InitialPathID {
		cong = congestion.NewOliaSender(oliaSenders, p.rttStats, protocol.InitialCongestionWindow, protocol.DefaultMaxCongestionWindow)
		oliaSenders[p.pathID] = cong.(*congestion.OliaSender)
	}

	sentPacketHandler := ackhandler.NewSentPacketHandler(p.rttStats,
		cong,
		p.onRTO,
		// 调用的冗余控制器的方法
		func(pn protocol.PacketNumber) { redundancyController.OnPacketLost(pn) },
		// 调用冗余控制器的方法
		func(pn protocol.PacketNumber) { redundancyController.OnPacketReceived(pn) },
		p.sess.GetConfig().UseFastRetransmit,
	)

	if p.pathID != protocol.InitialPathID {
		// A new path has been created, so the handshake completed
		sentPacketHandler.SetHandshakeComplete()
	}

	now := time.Now()

	p.sentPacketHandler = sentPacketHandler
	p.receivedPacketHandler = ackhandler.NewReceivedPacketHandler(p.sess.GetVersion(), p.sess.GetConfig().DisableFECRecoveredFrames)

	p.packetNumberGenerator = newPacketNumberGenerator(protocol.SkipPacketAveragePeriodLength)

	p.closeChan = make(chan *qerr.QuicError, 1)
	p.sentPacket = make(chan struct{}, 1)

	p.timer = utils.NewTimer()
	p.lastNetworkActivityTime = now

	p.active.Set(true)
	p.potentiallyFailed.Set(false)
	p.wasPotentiallyFailed.Set(false)
	p.facedRTO.Set(false)
	p.validRemAddrID = true

	p.fec = &utils.AtomicBool{}

	// Once the path is setup, run it
	go p.run()
}

func (p *path) run() {
	// XXX (QDC): relay everything to the session, maybe not the most efficient
runLoop:
	for {
		// Close immediately if requested
		select {
		case <-p.closeChan:
			break runLoop
		default:
		}

		p.maybeResetTimer()

		select {
		case <-p.closeChan:
			break runLoop
		case <-p.timer.Chan():
			p.timer.SetRead()
			select {
			case p.sess.PathTimersChan() <- p:
			// XXX (QDC): don't remain stuck here!
			case <-p.closeChan:
				break runLoop
			case <-p.sentPacket:
				// Don't remain stuck here!
			}
		case <-p.sentPacket:
			// Used to reset the path timer
		}
	}
	p.active.Set(false)
	if p.sess.PathManager() != nil {
		p.sess.PathManager().wg.Done()
	}
}

func (p *path) SendingAllowed() bool {
	return p.active.Get() && p.sentPacketHandler.SendingAllowed()
}

func (p *path) GetStopWaitingFrame(force bool) *wire.StopWaitingFrame {
	return p.sentPacketHandler.GetStopWaitingFrame(force)
}

func (p *path) GetAckFrame() *wire.AckFrame {
	ack := p.receivedPacketHandler.GetAckFrame()
	if ack != nil {
		ack.PathID = p.pathID
	}

	return ack
}

func (p *path) maybeResetTimer() {
	deadline := p.lastNetworkActivityTime.Add(p.idleTimeout())

	if ackAlarm := p.receivedPacketHandler.GetAlarmTimeout(); !ackAlarm.IsZero() {
		deadline = ackAlarm
	}
	if lossTime := p.sentPacketHandler.GetAlarmTimeout(); !lossTime.IsZero() {
		deadline = utils.MinTime(deadline, lossTime)
	}

	deadline = utils.MinTime(utils.MaxTime(deadline, time.Now().Add(minPathTimer)), time.Now().Add(maxPathTimer))

	p.timer.Reset(deadline)
}

func (p *path) idleTimeout() time.Duration {
	// TODO (QDC): probably this should be refined at path level
	cryptoSetup := p.sess.GetCryptoSetup()
	if cryptoSetup != nil {
		config := p.sess.GetConfig()
		if p.active.Get() && (p.pathID != 0 || p.sess.IsHandshakeComplete()) {
			return config.IdleTimeout
		}
		return config.HandshakeTimeout
	}
	return time.Second
}

func (p *path) handlePacketImpl(pkt *receivedPacket) (*unpackedPacket, error) {
	if !p.active.Get() {
		// We just got some response from remote!
		p.active.Set(true)
		// If we lost connectivity for local reason, identify the current local address ID
		if p.conn == nil && pkt.rcvPconn != nil {
			p.sess.PathManager().pconnMgr.PconnsLock().RLock()
			p.conn = &conn{pconn: pkt.rcvPconn, currentAddr: pkt.remoteAddr}
			locAddrID, ok := p.sess.PathManager().pconnMgr.GetAddrIDOf(pkt.rcvPconn.LocalAddr())
			if ok {
				p.locAddrID = locAddrID
			}
			p.sess.PathManager().pconnMgr.PconnsLock().RUnlock()
		}
	}

	if !pkt.rcvTime.IsZero() {
		p.lastNetworkActivityTime = pkt.rcvTime
	}
	hdr := pkt.header
	data := pkt.data

	// We just received a new packet on that path, so it works
	p.potentiallyFailed.Set(false)

	// Calculate packet number
	hdr.PacketNumber = protocol.InferPacketNumber(
		hdr.PacketNumberLen,
		p.largestRcvdPacketNumber,
		hdr.PacketNumber,
	)

	// log.Printf("Received New Packet With Packet Number: %d", hdr.PacketNumber)

	packet, err := p.sess.GetUnpacker().Unpack(hdr.Raw, hdr, data, pkt.recovered)
	if utils.Debug() {
		if err != nil {
			utils.Debugf("<- Reading packet 0x%x (%d bytes) for connection %x on path %x", hdr.PacketNumber, len(data)+len(hdr.Raw), hdr.ConnectionID, p.pathID)
		} else {
			utils.Debugf("<- Reading packet 0x%x (%d bytes) for connection %x on path %x, %s", hdr.PacketNumber, len(data)+len(hdr.Raw), hdr.ConnectionID, p.pathID, packet.encryptionLevel)
		}
		hdr.Log()
	}

	// if the decryption failed, this might be a packet sent by an attacker
	// don't update the remote address
	if quicErr, ok := err.(*qerr.QuicError); ok && quicErr.ErrorCode == qerr.DecryptionFailure {
		return nil, err
	}
	if p.sess.GetPerspective() == protocol.PerspectiveServer {
		// update the remote address, even if unpacking failed for any other reason than a decryption error
		p.conn.SetCurrentRemoteAddr(pkt.remoteAddr)
	}
	if err != nil {
		return nil, err
	}

	p.lastRcvdPacketNumber = hdr.PacketNumber
	// Only do this after decrupting, so we are sure the packet is not attacker-controlled
	p.largestRcvdPacketNumber = utils.MaxPacketNumber(p.largestRcvdPacketNumber, hdr.PacketNumber)

	// we should send an ack if we receive only FEC frames: it could be because a path is used only for FEC Frames
	containsOnlyFECFrames := true
	for _, f := range packet.frames {
		if _, ok := f.(*wire.FECFrame); !ok {
			containsOnlyFECFrames = false
		}
	}

	isRetransmittable := ackhandler.HasRetransmittableOrUnreliableStreamFrames(packet.frames)
	// 是否应该触发ACK的设置为：1,数据包不能是恢复的数据包，2、可重传、或者只有FECFrame
	// 即直接接收到的FECFrame组成的包应该触发ACK
	if err = p.receivedPacketHandler.ReceivedPacket(hdr.PacketNumber, !pkt.recovered && (isRetransmittable || containsOnlyFECFrames), pkt.recovered); err != nil {
		return nil, err
	}

	if err != nil {
		return nil, err
	}

	return packet, nil
}

func (p *path) onRTO(lastSentTime time.Time) bool {
	p.facedRTO.Set(true)
	// Was there any activity since last sent packet?
	if p.lastNetworkActivityTime.Before(lastSentTime) {
		//p.potentiallyFailed.Set(true)
		//p.wasPotentiallyFailed.Set(true)
		return true
	}
	return false
}

func (p *path) SetLeastUnacked(leastUnacked protocol.PacketNumber) {
	p.leastUnacked = leastUnacked
}
