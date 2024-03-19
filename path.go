package quic

import (
	"fmt"
	"math"
	"sort"
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

const QUICRDWindowSize = 500

type BriefPacket struct {
	PacketNumber protocol.PacketNumber
	RcvTime      time.Time
}

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

	// add by zhaolee
	lastRcvPacketTime time.Time
	dTimeLogger       []time.Duration
	rcvPacketsTime    []map[protocol.PacketNumber]time.Time

	// FOR QUIC-RD
	// AS(Arrive Sequense)
	rcvPacketsHistory []*BriefPacket
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
	// true true false
	// log.Printf("p.sess.GetVersion() >= protocol.VersionMP, %d, %d", p.sess.GetVersion(), protocol.VersionMP)
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
	// added by zhaolee
	// 记录接收间隔,接收时间
	if !p.lastRcvPacketTime.IsZero() {
		p.dTimeLogger = append(p.dTimeLogger, time.Since(p.lastRcvPacketTime))
	}
	p.lastRcvPacketTime = time.Now()
	// 记录收到的数据包
	p.rcvPacketsTime = append(p.rcvPacketsTime, map[protocol.PacketNumber]time.Time{pkt.header.PacketNumber: pkt.rcvTime})

	// QUIC-RD
	// 统计
	p.rcvPacketsHistory = append(p.rcvPacketsHistory, &BriefPacket{
		PacketNumber: pkt.header.PacketNumber,
		RcvTime:      pkt.rcvTime,
	})

	// 解密,返回
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

// add by zhaolee
func (p *path) GetRDFrame() *wire.RDFrame {
	if p.rcvPacketsHistory == nil || len(p.rcvPacketsHistory) < QUICRDWindowSize {
		return nil
	}
	var dPn, dTn int64
	dPn, dTn = p.CalculateDisorder(p.rcvPacketsHistory)
	p.rcvPacketsHistory = []*BriefPacket{}
	return &wire.RDFrame{
		MaxDisPlacement: uint16(dPn),
		MaxDelay:        uint16(dTn),
	}
}

// add by zhaolee
func (p *path) CalculateDisorder(AS []*BriefPacket) (int64, int64) {
	Displacement, Delay := p.GetDisplacementAndDelay(AS)
	if Displacement == nil && Delay == nil {
		return 0, 0
	}
	// 返回最小的dPn和最大的dTn
	// 最小的应该是负的
	sort.Slice(Displacement, func(i, j int) bool {
		return Displacement[i] < Displacement[j]
	})
	// 反转
	dPn := Displacement[0]
	if dPn > 0 {
		fmt.Println("BUG!全部数据包均延后到达!")
	} else {
		// fmt.Printf("dPn返回值:%v\n", -dPn)
		dPn = -dPn
	}
	// 计算延迟时间,最大的就是最大延迟时间
	sort.Slice(Delay, func(i, j int) bool {
		return Delay[i] > Delay[j]
	})
	var dTn int64
	// 单位改为毫秒
	dTn = Delay[0].Milliseconds()
	if Delay[0] < 0 {
		fmt.Println("BUG!全部数据包均延后到达!")
		dTn = 0
	}

	return dPn, dTn
}

// add by zhaolee
func (p *path) GetDisplacementAndDelay(AS []*BriefPacket) ([]int64, []time.Duration) {
	if len(AS) == 0 {
		return nil, nil
	}

	// 将packets按照map的形式存放
	packetMap := make(map[protocol.PacketNumber]*BriefPacket)
	RIs := make([]protocol.PacketNumber, 0)
	for _, packet := range AS {
		pn := packet.PacketNumber
		// 通过存在性判断来去重，存在过的包跳过，不存在的则插入
		if _, ok := packetMap[pn]; !ok {
			packetMap[pn] = packet
			RIs = append(RIs, pn)
		}
	}

	// 将RI增序排列
	sort.Slice(RIs, func(i, j int) bool {
		return RIs[i] < RIs[j]
	})

	// 接下来计算每个数据包的dP(n)
	dPn := make([]int64, 0)
	for i, RI := range RIs {
		// 检测数据包的存在性
		if _, ok := packetMap[RI]; !ok {
			panic("BUG!")
		}
		dPn = append(dPn, int64(RI)-int64(AS[i].PacketNumber))
	}

	// 接下来对乱序的数据包计算dT(n)
	dTn := make([]time.Duration, 0)
	for i, dPni := range dPn {
		p := AS[i]
		var eTn time.Time
		// 如果数据包提前到达，其期望时间不做更改
		if dPni <= 0 {
			eTn = p.RcvTime
		} else {
			ne, np, find := findIJ(AS, i)
			if find {
				eTn = interpolate(AS[ne], AS[np], p)
			} else {
				eTn = roughly(AS, p.PacketNumber)
				if p.RcvTime.Sub(eTn) > 1*time.Second {
					fmt.Println("出现BUG!", p.PacketNumber, eTn)
					for _, p := range AS {
						fmt.Println(p.PacketNumber, p.RcvTime)
					}
				}
			}
			// fmt.Println(ne, np, find, p.PacketNumber, eTn.Sub(time.Time{}).Milliseconds())
		}
		dTn = append(dTn, p.RcvTime.Sub(eTn))
	}

	return dPn, dTn

}

// add by zhaolee
// 请注意，这些实现需要根据实际的数据结构和要求进行适当调整
func findIJ(AS []*BriefPacket, currentIndex int) (int, int, bool) {
	var i, j int = -1, -1
	var minDiffToI, minDiffToJ protocol.PacketNumber = math.MaxUint64, math.MaxUint64
	currentPacketNumber := AS[currentIndex].PacketNumber

	// 向前查找最近的i，满足包号最接近且小于给定包号
	for index := 0; index < currentIndex; index++ {
		if AS[index].PacketNumber < currentPacketNumber {
			diff := currentPacketNumber - AS[index].PacketNumber
			if diff < minDiffToI {
				i = index
				minDiffToI = diff
			}
		}
	}

	// 向后查找最近的j，满足包号最接近且大于给定包号
	for index := currentIndex + 1; index < len(AS); index++ {
		if AS[index].PacketNumber > currentPacketNumber {
			diff := AS[index].PacketNumber - currentPacketNumber
			if diff < minDiffToJ {
				j = index
				minDiffToJ = diff
			}
		}
	}

	return i, j, i != -1 && j != -1
}

// add by zhaolee
func interpolate(pi, pj, p *BriefPacket) time.Time {
	if !(pi.PacketNumber < p.PacketNumber && p.PacketNumber < pj.PacketNumber) {
		fmt.Println("Invalid Input for Interpolating.")
		return p.RcvTime
	}
	// 计算两个参考点之间的时间差和包号差
	timeDiff := pj.RcvTime.Sub(pi.RcvTime)
	packetNumberDiff := pj.PacketNumber - pi.PacketNumber

	// 计算被插值点相对于pi的包号差占总包号差的比例
	ratio := float64(p.PacketNumber-pi.PacketNumber) / float64(packetNumberDiff)

	// 使用这个比例来计算时间差
	delta := time.Duration(float64(timeDiff) * ratio)

	// 计算并返回被插值点的期望接收时间
	return pi.RcvTime.Add(delta)
}

// add by zhaolee
func roughly(AS []*BriefPacket, n protocol.PacketNumber) time.Time {

	var closestDiff protocol.PacketNumber = math.MaxUint64
	var nearestPacket = []*BriefPacket{}

	// 遍历所有数据包，找到与n包号差距最小的数据包
	for _, packet := range AS {
		if packet.PacketNumber == n { // 跳过相同包号的数据包
			continue
		}
		// 计算差异，确保差异总是正值
		diff := packet.PacketNumber - n
		if n > packet.PacketNumber {
			diff = n - packet.PacketNumber
		}

		if diff < closestDiff {
			// 发现了更接近的数据包
			closestDiff = diff
			nearestPacket = []*BriefPacket{packet}
		} else if diff == closestDiff {
			// 同样接近，添加到列表
			nearestPacket = append(nearestPacket, packet)
		}
		// 如果已经找到两个最接近的包，且差异为1，提前结束
		if closestDiff == 1 && len(nearestPacket) >= 2 {
			break
		}
	}

	if len(nearestPacket) == 0 {
		return time.Now() // 没有找到任何最接近的包
	}
	// 计算所有最接近包的平均接收时间
	refTime := nearestPacket[0].RcvTime
	var sum time.Duration
	for _, p := range nearestPacket {
		sum += p.RcvTime.Sub(refTime)
	}

	averageDuration := sum / time.Duration(len(nearestPacket))
	averageTime := refTime.Add(averageDuration)

	return averageTime
}

// 该函数会出现BUG,但不知道为什么,似乎逻辑没有区别
// func roughly(AS []*BriefPacket, n protocol.PacketNumber) time.Time {

// 	var closestDiff protocol.PacketNumber = math.MaxUint64
// 	var closestTimeSum time.Duration
// 	var closestCount int

// 	// 遍历所有数据包，找到与n包号差距最小的数据包
// 	for _, packet := range AS {
// 		if packet.PacketNumber == n {
// 			continue
// 		}
// 		diff := packet.PacketNumber - n
// 		if n > packet.PacketNumber {
// 			diff = n - packet.PacketNumber
// 		}

// 		if diff < closestDiff {
// 			// 发现了更接近的数据包，重置计数和总和
// 			closestDiff = diff
// 			closestTimeSum = packet.RcvTime.Sub(time.Time{})
// 			closestCount = 1
// 		} else if diff == closestDiff {
// 			// 发现另一个同样接近的数据包，累加其接收时间
// 			closestTimeSum += packet.RcvTime.Sub(time.Time{})
// 			closestCount++
// 		}

// 	}

// 	// fmt.Println("ClosestCount=", closestCount, ",closestTimeSum=", closestTimeSum)

// 	if closestCount == 0 {
// 		// 如果没有找到最接近的包，理论上不应该发生
// 		return time.Now() // 或其他合理的默认值
// 	}

// 	// 如果找到了最接近的包，根据找到的数量计算平均时间
// 	avgTime := time.Time{}.Add(closestTimeSum / time.Duration(closestCount))
// 	return avgTime
// }

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
