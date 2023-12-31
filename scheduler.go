package quic

import (
	"time"

	"math/rand"

	"github.com/lucas-clemente/quic-go/ackhandler"
	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/fec"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type schedulerInterface interface {
	selectPath(s sessionI, hasRetransmission bool, hasStreamRetransmission bool, hasFECFrame bool, fromPth *path) *path
}

var _ schedulerInterface = &scheduler{}

type scheduler struct {
	// XXX Currently round-robin based, inspired from MPTCP scheduler
	quotas               map[protocol.PathID]uint
	lossRateScheduler    *lossBasedScheduler
	redundancyController fec.RedundancyController
}

func (sch *scheduler) setup() {
	sch.quotas = make(map[protocol.PathID]uint)
	if sch.redundancyController != nil {
		sch.lossRateScheduler = newLossBasedScheduler(sch.quotas, sch.redundancyController.GetNumberOfRepairSymbols())
	}
}

func (sch *scheduler) getRetransmission(s sessionI) (hasRetransmission bool, retransmitPacket *ackhandler.Packet, pth *path) {
	// check for retransmissions first
	// 处理重传队列所有的包，直到没有重传数据包
	for {
		// TODO add ability to reinject on another path
		// XXX We need to check on ALL paths if any packet should be first retransmitted
	retransmitLoop:
		for _, pthTmp := range s.Paths() {
			// 取出第一个数据包用于重传并返回该数据包,重传统计加一,在scheduler调用
			retransmitPacket = pthTmp.sentPacketHandler.DequeuePacketForRetransmission()
			if retransmitPacket != nil {
				pth = pthTmp
				break retransmitLoop
			}
		}
		if retransmitPacket == nil {
			break
		}
		hasRetransmission = true

		// EncryptionForwardSecure是最高的
		if retransmitPacket.EncryptionLevel != protocol.EncryptionForwardSecure {
			if s.IsHandshakeComplete() {
				// Don't retransmit handshake packets when the handshake is complete
				continue
			}
			utils.Debugf("\tDequeueing handshake retransmission for packet 0x%x", retransmitPacket.PacketNumber)
			return
		}
		utils.Debugf("\tDequeueing retransmission of packet 0x%x from path %d", retransmitPacket.PacketNumber, pth.pathID)
		// resend the frames that were in the packet
		// 除去ACKFrame和StopWaitingFrame
		for _, frame := range retransmitPacket.GetFramesForRetransmission() {
			// TODO: only retransmit WINDOW_UPDATEs if they actually enlarge the window
			switch f := frame.(type) {
			case *wire.StreamFrame:
				s.GetStreamFramer().AddFrameForRetransmission(f)
			case *wire.PathsFrame:
				// Schedule a new PATHS frame to send
				s.SchedulePathsFrame()
			case *wire.FECFrame:
			default:
				s.GetPacker().QueueControlFrame(frame, pth)
			}
		}
	}
	return
}

func (sch *scheduler) selectPathRoundRobin(s sessionI, hasRetransmission bool, hasStreamRetransmission bool, hasFECFrame bool, fromPth *path) *path {
	if sch.quotas == nil {
		sch.setup()
	}

	paths := s.Paths()

	// XXX Avoid using PathID 0 if there is more than 1 path
	if len(paths) <= 1 {
		if !hasRetransmission && !paths[protocol.InitialPathID].SendingAllowed() {
			return nil
		}
		return paths[protocol.InitialPathID]
	}

	// TODO cope with decreasing number of paths (needed?)
	var selectedPath *path
	var lowerQuota, currentQuota uint
	var ok bool

	// Max possible value for lowerQuota at the beginning
	lowerQuota = ^uint(0)

pathLoop:
	for pathID, pth := range paths {
		// Don't block path usage if we retransmit, even on another path
		if !hasRetransmission && !pth.SendingAllowed() {
			continue pathLoop
		}

		// If this path is potentially failed, do no consider it for sending
		if pth.potentiallyFailed.Get() {
			// comment this line as it blocked some mininet experiments
			//continue pathLoop
		}

		// XXX Prevent using initial pathID if multiple paths
		if pathID == protocol.InitialPathID {
			continue pathLoop
		}

		/// use the FEC path if it exists
		if pth.fec.Get() {
			if hasFECFrame {
				return pth
			}
			continue
		}

		currentQuota, ok = sch.quotas[pathID]
		if !ok {
			sch.quotas[pathID] = 0
			currentQuota = 0
		}

		if currentQuota < lowerQuota {
			selectedPath = pth
			lowerQuota = currentQuota
		}
	}

	return selectedPath

}

func (sch *scheduler) selectPathLowLatency(s sessionI, hasRetransmission bool, hasStreamRetransmission bool, fromPth *path) *path {
	paths := s.Paths()
	// XXX Avoid using PathID 0 if there is more than 1 path
	if len(paths) <= 1 {
		if !hasRetransmission && !paths[protocol.InitialPathID].SendingAllowed() {
			return nil
		}
		return paths[protocol.InitialPathID]
	}

	// FIXME Only works at the beginning... Cope with new paths during the connection
	if hasRetransmission && hasStreamRetransmission && fromPth.rttStats.SmoothedRTT() == 0 {
		// Is there any other path with a lower number of packet sent?
		currentQuota := sch.quotas[fromPth.pathID]
		for pathID, pth := range paths {
			if pathID == protocol.InitialPathID || pathID == fromPth.pathID {
				continue
			}
			// The congestion window was checked when duplicating the packet
			if sch.quotas[pathID] < currentQuota {
				return pth
			}
		}
	}

	var selectedPath *path
	var lowerRTT time.Duration
	var currentRTT time.Duration
	selectedPathID := protocol.PathID(255)

	considerBackup := false
	considerPf := false
	needBackup := true
	havePf := false

pathLoop:
	for pathID, pth := range paths {
		// If this path is potentially failed, do not consider it for sending
		if !considerPf && pth.potentiallyFailed.Get() {
			havePf = true
			continue pathLoop
		}

		// XXX Prevent using initial pathID if multiple paths
		if pathID == protocol.InitialPathID {
			continue pathLoop
		}

		if !considerBackup && pth.backup.Get() {
			continue pathLoop
		}

		// At least one non-backup path is active and did not faced RTO
		if !pth.facedRTO.Get() {
			needBackup = false
		}

		// It the preferred path never faced RTO, and this one did, then ignore it
		if selectedPath != nil && !selectedPath.facedRTO.Get() && pth.facedRTO.Get() {
			continue
		}

		// Don't block path usage if we retransmit, even on another path
		if !hasRetransmission && !pth.SendingAllowed() {
			continue pathLoop
		}

		currentRTT = pth.rttStats.SmoothedRTT()

		// Prefer staying single-path if not blocked by current path
		// Don't consider this sample if the smoothed RTT is 0
		if lowerRTT != 0 && currentRTT == 0 {
			continue pathLoop
		}

		// Case if we have multiple paths unprobed
		if currentRTT == 0 {
			currentQuota, ok := sch.quotas[pathID]
			if !ok {
				sch.quotas[pathID] = 0
				currentQuota = 0
			}
			lowerQuota, _ := sch.quotas[selectedPathID]
			if selectedPath != nil && currentQuota > lowerQuota {
				continue pathLoop
			}
		}

		if currentRTT != 0 && lowerRTT != 0 && selectedPath != nil && currentRTT >= lowerRTT {
			continue pathLoop
		}

		// Update
		lowerRTT = currentRTT
		selectedPath = pth
		selectedPathID = pathID
	}

	if !considerBackup && needBackup {
		// Restart decision, but consider backup paths also, even if an active path was selected
		// Because all current active paths might not be reliable...
		considerBackup = true
		goto pathLoop
	}

	if selectedPath == nil && considerBackup && havePf && !considerPf {
		// All paths are potentially failed... Try to resent!
		considerPf = true
		goto pathLoop
	}

	return selectedPath
}

func (sch *scheduler) selectPathHighestRemainingBytes(s sessionI, hasRetransmission bool, hasStreamRetransmission bool, hasFECFrame bool, fromPth *path) *path {
	paths := s.Paths()
	// XXX Avoid using PathID 0 if there is more than 1 path
	if len(paths) <= 1 {
		if !hasRetransmission && !paths[protocol.InitialPathID].SendingAllowed() {
			return nil
		}
		return paths[protocol.InitialPathID]
	}

	// FIXME Only works at the beginning... Cope with new paths during the connection
	if hasRetransmission && hasStreamRetransmission && fromPth.rttStats.SmoothedRTT() == 0 {
		// Is there any other path with a lower number of packet sent?
		currentQuota := sch.quotas[fromPth.pathID]
		for pathID, pth := range paths {
			if pathID == protocol.InitialPathID || pathID == fromPth.pathID {
				continue
			}
			// The congestion window was checked when duplicating the packet
			if sch.quotas[pathID] < currentQuota {
				return pth
			}
		}
	}

	var selectedPath *path
	var higherRemainingBytes int64 = -1
	var currentRemainingBytes int64 = -1
	selectedPathID := protocol.PathID(255)

	considerBackup := false
	considerPf := false
	needBackup := true
	havePf := false

	mapRemainingBytes := make(map[protocol.PathID]int64)

	var totalRemainingBytes uint64 = 0
	var higherRTT time.Duration
	var selectedPathRTT time.Duration
pathLoop:
	for pathID, pth := range paths {
		// If this path is potentially failed, do not consider it for sending
		if !considerPf && pth.potentiallyFailed.Get() {
			havePf = true
			continue pathLoop
		}

		// XXX Prevent using initial pathID if multiple paths
		if pathID == protocol.InitialPathID {
			continue pathLoop
		}

		if !considerBackup && pth.backup.Get() {
			continue pathLoop
		}

		// At least one non-backup path is active and did not faced RTO
		if !pth.facedRTO.Get() {
			needBackup = false
		}

		// It the preferred path never faced RTO, and this one did, then ignore it
		if selectedPath != nil && !selectedPath.facedRTO.Get() && pth.facedRTO.Get() {
			continue
		}

		// Don't block path usage if we retransmit, even on another path
		if !hasRetransmission && !pth.SendingAllowed() {
			continue pathLoop
		}

		oSender := s.PathManager().oliaSenders[pth.pathID]
		//TODO: use also the bytesinflight
		pathRTT := pth.rttStats.SmoothedRTT()
		currentCwin := oSender.GetCongestionWindow()
		currentBytesInFlight := pth.sentPacketHandler.GetBytesInFlight()
		if currentBytesInFlight >= currentCwin {
			currentRemainingBytes = 0
		} else {
			currentRemainingBytes = int64(currentCwin - currentBytesInFlight)
		}

		mapRemainingBytes[pathID] = currentRemainingBytes
		totalRemainingBytes += uint64(currentRemainingBytes)

		// Prefer staying single-path if not blocked by current path
		// Don't consider this sample if the smoothed RTT is 0
		if higherRemainingBytes != -1 && pathRTT == 0 {
			continue pathLoop
		}

		// Case if we have multiple paths unprobed
		if pathRTT == 0 {
			currentQuota, ok := sch.quotas[pathID]
			if !ok {
				sch.quotas[pathID] = 0
				currentQuota = 0
			}
			lowerQuota, _ := sch.quotas[selectedPathID]
			if selectedPath != nil && currentQuota > lowerQuota {
				continue pathLoop
			}
		}

		if pathRTT != 0 && pathRTT > higherRTT {
			higherRTT = pathRTT
		}

		if pathRTT != 0 && higherRemainingBytes != -1 && selectedPath != nil && currentRemainingBytes <= higherRemainingBytes {
			continue pathLoop
		}

		// Update
		higherRemainingBytes = currentRemainingBytes
		selectedPath = pth
		selectedPathID = pathID
		selectedPathRTT = pathRTT
	}

	if !considerBackup && needBackup {
		// Restart decision, but consider backup paths also, even if an active path was selected
		// Because all current active paths might not be reliable...
		considerBackup = true
		goto pathLoop
	}

	if selectedPath == nil && considerBackup && havePf && !considerPf {
		// All paths are potentially failed... Try to resent!
		considerPf = true
		goto pathLoop
	}

	if totalRemainingBytes > 0 {
		// random pick
		randomThreshold := rand.Int63n(int64(totalRemainingBytes))
		for pathID, val := range mapRemainingBytes {
			if val >= randomThreshold {
				return paths[pathID]
			}
			randomThreshold -= val
		}
	}

	compensate := false
	if compensate && higherRTT > selectedPathRTT {
		// compensate to perceive equal RTTs at the receiver side (we assume OWD = RTT/2)
		time.Sleep(time.Duration((higherRTT.Nanoseconds() - selectedPathRTT.Nanoseconds()) / 2))
	}
	return selectedPath
}

func (sch *scheduler) selectPathLowestLossRate(s sessionI, hasRetransmission bool, hasStreamRetransmission bool, hasFECFrame bool, fromPth *path) *path {

	paths := s.Paths()
	// XXX Avoid using PathID 0 if there is more than 1 path
	if len(paths) <= 1 {
		if !hasRetransmission && !paths[protocol.InitialPathID].SendingAllowed() {
			return nil
		}
		return paths[protocol.InitialPathID]
	}

	hasOliaSender := false
	var oSender *congestion.OliaSender
	if fromPth != nil {
		oSender, hasOliaSender = s.PathManager().oliaSenders[fromPth.pathID]
	}
	// FIXME Only works at the beginning... Cope with new paths during the connection
	if hasRetransmission && hasStreamRetransmission && (!hasOliaSender || oSender.GetSmoothedBytesBetweenTwoLosses() == 0) {
		// Is there any other path with a lower number of packet sent?
		currentQuota := sch.quotas[fromPth.pathID]
		for pathID, pth := range paths {
			if pathID == protocol.InitialPathID || pathID == fromPth.pathID {
				continue
			}
			// The congestion window was checked when duplicating the packet
			if sch.quotas[pathID] < currentQuota {
				return pth
			}
		}
	}

	var selectedPath *path
	var lowerMetric float64 = 2
	var metric float64 = 2
	selectedPathID := protocol.PathID(255)

	considerBackup := false
	considerPf := false
	needBackup := true
	havePf := false

pathLoop:
	for pathID, pth := range paths {
		// If this path is potentially failed, do not consider it for sending
		if !considerPf && pth.potentiallyFailed.Get() {
			havePf = true
			continue pathLoop
		}

		// XXX Prevent using initial pathID if multiple paths
		if pathID == protocol.InitialPathID {
			continue pathLoop
		}

		if !considerBackup && pth.backup.Get() {
			continue pathLoop
		}

		// At least one non-backup path is active and did not faced RTO
		if !pth.facedRTO.Get() {
			needBackup = false
		}

		// It the preferred path never faced RTO, and this one did, then ignore it
		if selectedPath != nil && !selectedPath.facedRTO.Get() && pth.facedRTO.Get() {
			continue
		}

		// Don't block path usage if we retransmit, even on another path
		if !hasRetransmission && !pth.SendingAllowed() {
			continue pathLoop
		}
		pathRTT := pth.rttStats.SmoothedRTT()
		oSender := s.PathManager().oliaSenders[pth.pathID]
		maxN1N2 := float64(oSender.GetSmoothedBytesBetweenTwoLosses())
		metric = ((maxN1N2 + 1) / (2 * (maxN1N2 - 1))) * float64(pth.rttStats.SmoothedRTT())
		//metric = getEstimatedLossRate(oSender.GetSmoothedBytesBetweenTwoLosses(), float64(oSender.GetCurrentPacketsSinceLastLoss()))

		// Prefer staying single-path if not blocked by current path
		// Don't consider this sample if the smoothed RTT is 0
		if lowerMetric != 2 && pathRTT == 0 {
			continue pathLoop
		}

		// Case if we have multiple paths unprobed
		if pathRTT == 0 {
			currentQuota, ok := sch.quotas[pathID]
			if !ok {
				sch.quotas[pathID] = 0
				currentQuota = 0
			}
			lowerQuota, _ := sch.quotas[selectedPathID]
			if selectedPath != nil && currentQuota > lowerQuota {
				continue pathLoop
			}
		}

		if pathRTT != 0 && lowerMetric != 2 && selectedPath != nil && metric >= lowerMetric {
			continue pathLoop
		}

		// Update
		lowerMetric = metric
		selectedPath = pth
		selectedPathID = pathID
	}

	if !considerBackup && needBackup {
		// Restart decision, but consider backup paths also, even if an active path was selected
		// Because all current active paths might not be reliable...
		considerBackup = true
		goto pathLoop
	}

	if selectedPath == nil && considerBackup && havePf && !considerPf {
		// All paths are potentially failed... Try to resent!
		considerPf = true
		goto pathLoop
	}

	return selectedPath
}

// Lock of s.paths must be held
func (sch *scheduler) selectPath(s sessionI, hasRetransmission bool, hasStreamRetransmission bool, hasFECFrame bool, fromPth *path) *path {
	// XXX Currently round-robin
	// TODO select the right scheduler dynamically
	if sch.lossRateScheduler != nil && sch.redundancyController != nil {
		sch.lossRateScheduler.maxNumberOfRepairSymbols = sch.redundancyController.GetNumberOfRepairSymbols()
	}
	// return sch.selectPathLowLatency(s, hasRetransmission, hasStreamRetransmission, fromPth)
	path := sch.selectPathLowLatency(s, hasRetransmission, hasStreamRetransmission, fromPth)
	// path :=  sch.lossRateScheduler.selectPath(s, hasRetransmission, hasStreamRetransmission, hasFECFrame, fromPth)
	//path :=  sch.selectPathRoundRobin(s, hasRetransmission, hasStreamRetransmission, hasFECFrame, fromPth)
	//path :=  sch.selectPathLowestLossRate(s, hasRetransmission, hasStreamRetransmission, hasFECFrame, fromPth)
	//path :=  sch.selectPathHighestRemainingBytes(s, hasRetransmission, hasStreamRetransmission, hasFECFrame, fromPth)

	return path
}

// Lock of s.paths must be free (in case of log print)
func (sch *scheduler) performPacketSending(s sessionI, windowUpdateFrames []wire.Frame, pth *path) (*ackhandler.Packet, bool, error) {
	// add a retransmittable frame
	if pth.sentPacketHandler.ShouldSendRetransmittablePacket() {
		s.GetPacker().QueueControlFrame(&wire.PingFrame{}, pth)
	}

	fecPayloadIDOfPacket := s.GetFECFrameworkSender().GetNextSourceFECPayloadID()

	packet, err := s.GetPacker().PackPacket(pth, fecPayloadIDOfPacket)
	if err != nil || packet == nil {
		return nil, false, err
	}
	if err = s.sendPackedPacket(packet, pth); err != nil {
		return nil, false, err
	}

	// send every window update twice
	for _, f := range windowUpdateFrames {
		s.GetPacker().QueueControlFrame(f, pth)
	}

	// Packet sent, so update its quota
	sch.quotas[pth.pathID]++

	// Provide some logging if it is the last packet
	// modify by zhaolee
	// for _, frame := range packet.frames {
	// 	switch frame := frame.(type) {
	// 	case *wire.StreamFrame:
	// 		if frame.FinBit {
	// 			// Last packet to send on the stream, print stats
	// 			utils.Infof("Info for stream %x of %x", frame.StreamID, s.GetConnectionID())
	// 			for pathID, pth := range s.Paths() {
	// 				sntPkts, sntRetrans, sntLost := pth.sentPacketHandler.GetStatistics()
	// 				rcvPkts, recoveredPkts := pth.receivedPacketHandler.GetStatistics()
	// 				utils.Infof("Path %x: sent %d retrans %d lost %d; rcv %d, recovered %d", pathID, sntPkts, sntRetrans, sntLost, rcvPkts, recoveredPkts)
	// 			}
	// 		}
	// 	default:
	// 	}
	// }

	pkt := &ackhandler.Packet{
		PacketNumber:    packet.header.PacketNumber,
		Frames:          packet.frames,
		Length:          protocol.ByteCount(len(packet.raw)),
		EncryptionLevel: packet.encryptionLevel,
	}

	return pkt, true, nil
}

// Lock of s.paths must be free
func (sch *scheduler) ackRemainingPaths(s sessionI, totalWindowUpdates []wire.Frame) error {
	// Either we run out of data, or CWIN of usable paths are full
	// Send ACKs on paths not yet used, if needed. Either we have no data to send and
	// it will be a pure ACK, or we will have data in it, but the CWIN should then
	// not be an issue.
	// get WindowUpdate frames
	// this call triggers the flow controller to increase the flow control windows, if necessary
	windowUpdates := totalWindowUpdates
	if len(windowUpdates) == 0 {
		windowUpdates = s.getWindowUpdates(s.GetPeerBlocked())
	}
	packer := s.GetPacker()
	for _, pthTmp := range s.Paths() {
		ackTmp := pthTmp.GetAckFrame()
		for _, f := range windowUpdates {
			packer.QueueControlFrame(f, pthTmp)
		}
		if ackTmp != nil || len(windowUpdates) > 0 {
			if pthTmp.pathID == protocol.InitialPathID && ackTmp == nil {
				continue
			}
			swf := pthTmp.GetStopWaitingFrame(false)
			if swf != nil {
				packer.QueueControlFrame(swf, pthTmp)
			}
			packer.QueueControlFrame(ackTmp, pthTmp)
			// XXX (QDC) should we instead call PackPacket to provides WUFs?
			var packet *packedPacket
			var err error
			if ackTmp != nil {
				// Avoid internal error bug
				packet, err = packer.PackAckPacket(pthTmp)
			} else {
				fpid := s.GetFECFrameworkSender().GetNextSourceFECPayloadID()
				packet, err = packer.PackPacket(pthTmp, fpid)
			}
			if err != nil {
				return err
			}
			err = s.sendPackedPacket(packet, pthTmp)
			if err != nil {
				return err
			}
		}
	}
	s.SetPeerBlocked(false)
	return nil
}

// 在session中调用
func (sch *scheduler) sendPacket(s sessionI) error {
	var pth *path

	// Update leastUnacked value of paths
	for _, pthTmp := range s.Paths() {
		pthTmp.SetLeastUnacked(pthTmp.sentPacketHandler.GetLeastUnacked())
	}

	packer := s.GetPacker()
	streamFramer := s.GetStreamFramer()
	fecFramer := s.GetFECFramer()

	// Get MAX_DATA and MAX_STREAM_DATA frames
	// this call triggers the flow controller to increase the flow control windows, if necessary
	windowUpdates := s.getWindowUpdates(false)
	for _, f := range windowUpdates {
		packer.QueueControlFrame(f, pth)
	}

	// Perform this check now to avoid doing lot of time the computation
	for _, pthTmp := range s.Paths() {
		if pthTmp.sentPacketHandler.ComputeRTOTimeout() > time.Duration(500)*time.Millisecond {
			// Even if not
			pthTmp.facedRTO.Set(true)
		}
	}

	// Repeatedly try sending until we don't have any more data, or run out of the congestion window
	for {
		// We first check for retransmissions
		hasRetransmission, retransmitHandshakePacket, fromPth := sch.getRetransmission(s)
		// XXX There might still be some stream frames to be retransmitted
		hasStreamRetransmission := streamFramer.HasFramesForRetransmission()

		hasFECFrames := len(fecFramer.transmissionQueue) > 0

		// Select the path here
		pth = sch.selectPath(s, hasRetransmission, hasStreamRetransmission, hasFECFrames, fromPth)

		// XXX No more path available, should we have a new QUIC error message?
		if pth == nil {
			windowUpdates = s.getWindowUpdates(false)
			return sch.ackRemainingPaths(s, windowUpdates)
		}

		// If we have an handshake packet retransmission, do it directly
		if hasRetransmission && retransmitHandshakePacket != nil {
			packer.QueueControlFrame(pth.sentPacketHandler.GetStopWaitingFrame(true), pth)
			packet, err := packer.PackHandshakeRetransmission(retransmitHandshakePacket, pth)
			if err != nil {
				return err
			}
			// 重传,实施发送
			if err = s.sendPackedPacket(packet, pth); err != nil {
				return err
			}
			continue
			// 即优先处理所有重传
		}

		// XXX Some automatic ACK generation should be done someway
		var ack *wire.AckFrame

		ack = pth.GetAckFrame()
		if ack != nil {
			packer.QueueControlFrame(ack, pth)
		}
		if ack != nil || hasStreamRetransmission {
			// 只有在hasStreamRetransmission==true才会返回swf
			swf := pth.sentPacketHandler.GetStopWaitingFrame(hasStreamRetransmission)
			if swf != nil {
				packer.QueueControlFrame(swf, pth)
			}
		}

		if s.GetVersion() == protocol.VersionMP {
			// Also add ADD ADDRESS frames, if any
			for aaf := streamFramer.PopAddAddressFrame(); aaf != nil; aaf = streamFramer.PopAddAddressFrame() {
				// modify log->infof
				utils.Infof("ADDADDR: %s", aaf.Addr.String())
				packer.QueueControlFrame(aaf, pth)
			}

			// Also add REMOVE ADDRESS frames, if any
			for raf := streamFramer.PopRemoveAddressFrame(); raf != nil; raf = streamFramer.PopRemoveAddressFrame() {
				packer.QueueControlFrame(raf, pth)
			}

			// Also add PATHS frames, if any
			for pf := streamFramer.PopPathsFrame(); pf != nil; pf = streamFramer.PopPathsFrame() {
				packer.QueueControlFrame(pf, pth)
			}
		}
		pkt, sent, err := sch.performPacketSending(s, windowUpdates, pth)
		if err != nil {
			return err
		}
		windowUpdates = nil
		if !sent {
			// Prevent sending empty packets
			return sch.ackRemainingPaths(s, windowUpdates)
		}

		// Duplicate traffic when it was sent on an unknown performing path
		// Don't do this if it is a retransmission to avoid looping here
		// FIXME adapt for new paths coming during the connection
		if !hasRetransmission && pth.rttStats.SmoothedRTT() == 0 {
			currentQuota := sch.quotas[pth.pathID]
			// Was the packet duplicated on all potential paths?
		duplicateLoop:
			for pathID, tmpPth := range s.Paths() {
				if pathID == protocol.InitialPathID || pathID == pth.pathID {
					continue
				}
				// If we duplicate a packet, only do this on paths having the same backup state than the original path
				if sch.quotas[pathID] < currentQuota && pth.backup.Get() == tmpPth.backup.Get() && tmpPth.sentPacketHandler.SendingAllowed() {
					// Duplicate it
					pth.sentPacketHandler.DuplicatePacket(pkt)
					break duplicateLoop
				}
			}
		}

		// And try pinging on potentially failed paths
		if fromPth != nil && fromPth.potentiallyFailed.Get() {
			err = s.SendPing(fromPth)
			if err != nil {
				return err
			}
		}
	}
}
