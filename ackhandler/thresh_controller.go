package ackhandler

import (
	"log"
	"time"

	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

const (
	DEFAULT_TIME_THRESH = 9 / 8
	DEFAULT_DUP_THRESH  = 3
)

const (
	MAX_TIME_THRESH = 5
	MAX_DUP_THRESH  = 10
)

const (
	// 平滑滤波参数
	ALPHA = 0.5
	// MD参数
	DELTA = 0.1
	Krtt  = 4
)

type LossTrigger uint32

var noLoss LossTrigger = 0
var lossByDuplicate LossTrigger = 1
var lossByDelay LossTrigger = 2

type ThreshController struct {
	// 定义时间阈值和数量阈值
	timeThreshold float32
	dupThreshold  uint

	// 超参数
	args *ThresholdArgs

	// 触发原因统计,0:lossByDelay,1:lossByDuplicate
	triggers [2]int

	// symbol的统计参数
	lastSymbolStatistic *SymbolStatistic
	curSymbolStatistic  *SymbolStatistic
	// packet的统计参数
	lastPacketStatistic *PacketStatistic
	curPacketStatistic  *PacketStatistic

	//时间周期
	lastRefreshTime time.Time

	// pkt和rtt的回调函数
	// h.packets, h.retransmissions, h.losses
	pktCallBacK func() (uint64, uint64, uint64)
	rttCallBack *congestion.RTTStats
}

func NewThreshController(pktcallback func() (uint64, uint64, uint64), rttCallBack *congestion.RTTStats) *ThreshController {
	args := &ThresholdArgs{
		MinTimeThresh: DEFAULT_TIME_THRESH,
		MinDupThresh:  DEFAULT_DUP_THRESH,
		MaxTimeThresh: MAX_TIME_THRESH,
		MaxDupThresh:  MAX_DUP_THRESH,
	}

	return &ThreshController{
		// 阈值
		timeThreshold: DEFAULT_TIME_THRESH,
		dupThreshold:  DEFAULT_DUP_THRESH,
		// 超参数
		args: args,
		// 间隔
		lastRefreshTime: time.Now(),
		// symbol统计
		lastSymbolStatistic: newSymbolStatistic(),
		curSymbolStatistic:  newSymbolStatistic(),
		// packet统计
		lastPacketStatistic: newPacketStatistic(),
		curPacketStatistic:  newPacketStatistic(),

		// 回调函数
		pktCallBacK: pktcallback,
		rttCallBack: rttCallBack,
	}
}
func (t *ThreshController) getSmothedRTT() time.Duration {
	return t.rttCallBack.SmoothedRTT()
}

// var Count int

func (t *ThreshController) updateAckedSymbols(Acked protocol.NumberOfAckedSymbol, nNumberOfSymbolsSent uint64) {

	// 没到时间直接返回
	sRTT := t.getSmothedRTT()

	if time.Since(t.lastRefreshTime) < Krtt*sRTT {
		return
	}

	t.onNextPeriod(Acked, nNumberOfSymbolsSent)
}

func (t *ThreshController) onNextPeriod(Acked protocol.NumberOfAckedSymbol, nNumberOfSymbolsSent uint64) {
	// 更新当前时间的Symbol信息
	t.curSymbolStatistic.numberOfSymbolsAcked = uint64(Acked)
	t.curSymbolStatistic.numberOfSymbols = nNumberOfSymbolsSent
	// 更新pkt信息
	pkts, retrans, _ := t.pktCallBacK()
	t.curPacketStatistic.numberOfPackets = pkts
	t.curPacketStatistic.numberOfRetransmissions = retrans

	// 计算当前gap的差值
	// symbol
	newlySent := t.curSymbolStatistic.numberOfSymbols - t.lastSymbolStatistic.numberOfSymbolsAcked
	newlyAcked := t.curSymbolStatistic.numberOfSymbolsAcked - t.lastSymbolStatistic.numberOfSymbolsAcked
	// packet
	newlyPkt := t.curPacketStatistic.numberOfPackets - t.lastPacketStatistic.numberOfPackets
	newlyRetrans := t.curPacketStatistic.numberOfRetransmissions - t.lastPacketStatistic.numberOfRetransmissions

	// log.Printf("(TC) newlyLoss: Delay: %d, Dup: %d, total: %d", t.triggers[0], t.triggers[1], t.triggers[0]+t.triggers[1])
	log.Printf("------------Global (new gap)----------------")
	log.Printf("Symbol: Acked: %d, Sent: %d", t.lastSymbolStatistic.numberOfSymbolsAcked, t.lastSymbolStatistic.numberOfSymbols)
	log.Printf("Packet: Retrans: %d, Sent: %d", retrans, pkts)
	log.Printf("RetransRate: %f, Lossrate: %f", float64(retrans)/float64(pkts), 1-float64(t.lastSymbolStatistic.numberOfSymbolsAcked)/float64(t.lastSymbolStatistic.numberOfSymbols))
	log.Printf("------------Newly (new gap)-----------------")
	log.Printf("Symbol: Acked: %d, Sent: %d", newlyAcked, newlySent)
	log.Printf("Packet: Retrans: %d, Sent: %d", newlyRetrans, newlySent)
	log.Printf("RetransRate: %f, Lossrate: %f", float64(newlyRetrans)/float64(newlyPkt), 1-float64(newlyAcked)/float64(newlySent))
	log.Printf("\n")

	// 计算当前时隙的丢包率
	var lossRate float64
	if newlySent == 0 {
		lossRate = t.lastSymbolStatistic.lossRate
	} else {
		lossRate = float64(newlySent-newlyAcked) / float64(newlySent)
	}

	// 重传率
	var retransRate float64
	if newlyPkt == 0 {
		retransRate = t.lastPacketStatistic.retransRate
	} else {
		retransRate = float64(newlyRetrans) / float64(newlyPkt)

	}

	// log.Printf("newly LossRate: %f, newly Retrans: %f", lossRate, retransRate)

	// 更新统计模块
	t.curSymbolStatistic.lossRate = lossRate
	t.lastSymbolStatistic = t.curSymbolStatistic
	t.curSymbolStatistic = newSymbolStatistic()

	t.curPacketStatistic.retransRate = retransRate
	t.lastPacketStatistic = t.curPacketStatistic
	t.curPacketStatistic = newPacketStatistic()

	// 更新时间
	t.lastRefreshTime = time.Now()

	t.refreshThreshold()
}

func (t *ThreshController) refreshThreshold() {
	// log.Println("byDelay,ByDup:", t.triggers[0], t.triggers[1])
	// from last
	retransRate := t.lastPacketStatistic.retransRate
	lossRate := t.lastSymbolStatistic.lossRate

	// 重传率较低，应该降低阈值, mutiple decrease
	if retransRate <= lossRate {
		t.dupThreshold = t.dupThreshold / 2
		t.timeThreshold = t.timeThreshold * (1 - DELTA)

		// 如果阈值在减小，不需要清空trigger，继续统计

	} else {
		byDelay := t.triggers[0]
		byDup := t.triggers[1]

		if byDelay < byDup {
			// 如果Dup触发的多，那就增大Dup阈值
			t.dupThreshold++
		} else {
			t.timeThreshold += DELTA
		}

		// 如果阈值增大了，开始统计下一时隙，清空trigger统计
		t.triggers = [2]int{}
	}
	// 限制范围
	t.dupThreshold = min(t.args.MaxDupThresh, max(t.dupThreshold, t.args.MinDupThresh))
	t.timeThreshold = min(t.args.MaxTimeThresh, max(t.timeThreshold, t.args.MinTimeThresh))

	// log.Printf("Refresh Threshold:%d(dup),%f(delay).", t.dupThreshold, t.timeThreshold)
	// log.Printf("Retransmit and LossRate: %f(re), %f(lo)", lossRate, retransRate)
}

func (t *ThreshController) OnPacketLostBy(reason LossTrigger) {
	log.Println("Loss Triggered")
	if reason == lossByDelay {
		t.triggers[0]++
	}
	if reason == lossByDuplicate {
		t.triggers[1]++
	}
}

func (t *ThreshController) getDupThreshold() uint {
	return t.dupThreshold

}

func (t *ThreshController) getTimeThreshold() float32 {
	return t.timeThreshold
}

func (t *ThreshController) setMaxTimeThreshold(timeThresh float32) {
	t.args.MaxTimeThresh = timeThresh
}
func (t *ThreshController) setMaxDupThreshold(n uint) {
	t.args.MaxDupThresh = n
}

type SymbolStatistic struct {
	numberOfSymbols      uint64
	numberOfSymbolsAcked uint64
	lossRate             float64
}

func newSymbolStatistic() *SymbolStatistic {
	return &SymbolStatistic{
		numberOfSymbols:      0,
		numberOfSymbolsAcked: 0,
		lossRate:             0,
	}
}

type ThresholdArgs struct {
	MinTimeThresh, MaxTimeThresh float32
	MinDupThresh, MaxDupThresh   uint
}

type PacketStatistic struct {
	numberOfPackets         uint64
	numberOfRetransmissions uint64
	retransRate             float64
}

func newPacketStatistic() *PacketStatistic {
	return &PacketStatistic{
		numberOfPackets:         0,
		numberOfRetransmissions: 0,
		retransRate:             0,
	}
}

func min[T float32 | uint](i, j T) T {
	if i > j {
		return j
	}

	return i
}

func max[T float32 | uint](i, j T) T {
	if i < j {
		return j
	}

	return i
}
