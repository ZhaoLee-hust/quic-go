package ackhandler

import (
	"log"
	"time"

	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

const (
	// 初始阈值
	DEFAULT_TIME_THRESH = 9.0 / 8.0
	DEFAULT_DUP_THRESH  = 3
	// 时间阈值最值
	MAX_TIME_THRESH = 5
	MIN_TIME_THRESH = 9.0 / 8.0
	// 数量阈值最值
	MAX_DUP_THRESH = 10
	MIN_DUP_THRESH = 3
	// 平滑滤波默认参数
	ALPHA = 0.5
	// MD参数
	DELTA = 0.1
	Krtt  = 3
)

type LossTrigger uint32

const (
	noLoss          LossTrigger = 0
	lossByDuplicate LossTrigger = 1
	lossByDelay     LossTrigger = 2
)

type pktStatistic struct {
	Sent        uint64
	Retrans     uint64
	retransRate float64
}

type symbolStatistic struct {
	Sent     uint64
	Acked    uint64
	lossRate float64
}

type ThreshController struct {
	// 定义时间阈值和数量阈值
	timeThreshold float32
	dupThreshold  uint

	// 触发原因统计,0:lossByDelay,1:lossByDuplicate
	triggers [2]int

	// symbol的统计参数
	symbolStatistic *symbolStatistic
	// packet的统计参数
	packetStatistic *pktStatistic

	//时间周期
	lastRefreshTime time.Time

	// pkt和rtt的回调函数
	// h.packets, h.retransmissions, h.losses
	pktCallBacK func() (uint64, uint64, uint64)
	rttCallBack *congestion.RTTStats

	// 时隙编号
	epochIndex uint64

	// 过去5个时隙
	pastTotalPackets   []uint64 // 过去时隙的数据包总数
	pastRetransPackets []uint64 // 过去时隙的重传数据包数
	pastTotalSymbols   []uint64
	pastAckedSymbols   []uint64

	// 统计函数
	thresholdStatistic []map[uint64][2]float64
	symbolsStatistic   []map[uint64][2]uint64
}

func NewThreshController(pktcallback func() (uint64, uint64, uint64), rttCallBack *congestion.RTTStats) *ThreshController {

	return &ThreshController{
		// 阈值
		timeThreshold: DEFAULT_TIME_THRESH,
		dupThreshold:  DEFAULT_DUP_THRESH,
		// 间隔
		lastRefreshTime: time.Now(),
		// symbol统计
		symbolStatistic: &symbolStatistic{},
		// packet统计
		packetStatistic: &pktStatistic{},

		// 回调函数
		// h.packets, h.retransmissions, h.losses
		pktCallBacK: pktcallback,
		rttCallBack: rttCallBack,

		//
		epochIndex: 1,
	}
}
func (t *ThreshController) getSmothedRTT() time.Duration {
	return t.rttCallBack.SmoothedRTT()
}

func (t *ThreshController) updateAckedSymbols(Acked protocol.NumberOfAckedSymbol, nNumberOfSymbolsSent uint64) {

	// 没到时间直接返回
	sRTT := t.getSmothedRTT()

	if time.Since(t.lastRefreshTime) < Krtt*sRTT {
		return
	}

	t.onNextPeriod(Acked, nNumberOfSymbolsSent)
}

func (t *ThreshController) computePastRates() (float64, float64) {
	if len(t.pastTotalPackets) < 5 || len(t.pastAckedSymbols) < 5 {
		return -1, -1 // 表示无法计算
	}
	pastTotalPackets := t.pastTotalPackets[len(t.pastTotalPackets)-1] - t.pastTotalPackets[len(t.pastTotalPackets)-5]
	pastRetransPackets := t.pastRetransPackets[len(t.pastRetransPackets)-1] - t.pastRetransPackets[len(t.pastRetransPackets)-5]
	pastRetransRate := float64(pastRetransPackets) / float64(pastTotalPackets)

	pastTotalSymbols := t.pastTotalSymbols[len(t.pastTotalSymbols)-1] - t.pastTotalSymbols[len(t.pastTotalSymbols)-5]
	pastAckedSymbols := t.pastAckedSymbols[len(t.pastAckedSymbols)-1] - t.pastAckedSymbols[len(t.pastAckedSymbols)-5]
	pastLossRate := 1.0 - float64(pastAckedSymbols)/float64(pastTotalSymbols)

	return pastLossRate, pastRetransRate
}

func (t *ThreshController) onNextPeriod(Acked protocol.NumberOfAckedSymbol, nNumberOfSymbolsSent uint64) {

	// 获取参数
	var globalLossRate, globalRetransRate float64
	nPackets, nRetrans, _ := t.pktCallBacK()
	globalRetransRate = float64(nRetrans) / float64(nPackets)

	pastLossRate, pastRetransRate := t.computePastRates()
	var lossRate, reTransRate float64
	if pastLossRate != -1 && pastRetransRate != -1 {
		globalLossRate = 1 - float64(Acked)/float64(nNumberOfSymbolsSent)
		lossRate = 0.75*globalLossRate + 0.25*pastLossRate
		reTransRate = 0.75*globalRetransRate + 0.25*pastRetransRate
	}
	log.Printf("(TC) newlyLoss: Delay: %d, Dup: %d, total: %d", t.triggers[0], t.triggers[1], t.triggers[0]+t.triggers[1])
	t.refreshThreshold(lossRate, reTransRate)

	t.packetStatistic.Retrans = nRetrans
	t.packetStatistic.Sent = nPackets
	t.packetStatistic.retransRate = globalRetransRate

	t.symbolStatistic.Acked = uint64(Acked)
	t.symbolStatistic.Sent = nNumberOfSymbolsSent
	t.symbolStatistic.lossRate = globalLossRate

	// 更新过去的数据包总数和重传数据包数，存总数
	t.pastTotalPackets = append(t.pastTotalPackets, nPackets)
	t.pastRetransPackets = append(t.pastRetransPackets, nRetrans)
	if len(t.pastTotalPackets) > 5 {
		t.pastTotalPackets = t.pastTotalPackets[1:]
	}
	if len(t.pastRetransPackets) > 5 {
		t.pastRetransPackets = t.pastRetransPackets[1:]
	}
	// 更新冗余数据包数量，存的是总数
	t.pastAckedSymbols = append(t.pastAckedSymbols, uint64(Acked))
	t.pastTotalSymbols = append(t.pastTotalSymbols, nNumberOfSymbolsSent)
	if len(t.pastAckedSymbols) > 5 {
		t.pastAckedSymbols = t.pastAckedSymbols[1:]
	}
	if len(t.pastTotalSymbols) > 5 {
		t.pastTotalSymbols = t.pastTotalSymbols[1:]
	}

	// 更新
	t.symbolsStatistic = append(t.symbolsStatistic, map[uint64][2]uint64{t.epochIndex: {t.symbolStatistic.Acked, t.symbolStatistic.Sent}})
	t.lastRefreshTime = time.Now()
	t.epochIndex++

	if t.epochIndex <= 5 {
		return
	}

	log.Printf("------------Global (new gap)----------------")
	log.Printf("Symbol: Acked: %d, Sent: %d", Acked, nNumberOfSymbolsSent)
	log.Printf("Packet: Retrans: %d, Sent: %d", nRetrans, nPackets)
	log.Printf("RetransRate: %f, Lossrate: %f", globalRetransRate, globalLossRate)
	pastTotalPackets := t.pastTotalPackets[len(t.pastTotalPackets)-1] - t.pastTotalPackets[0]
	pastRetransPackets := t.pastRetransPackets[len(t.pastRetransPackets)-1] - t.pastRetransPackets[0]
	pastTotalSymbols := t.pastTotalSymbols[len(t.pastTotalSymbols)-1] - t.pastTotalSymbols[0]
	pastAckedSymbols := t.pastAckedSymbols[len(t.pastAckedSymbols)-1] - t.pastAckedSymbols[0]
	log.Printf("------------Newly (new gap)-----------------")
	log.Printf("Symbol: Acked: %d, Sent: %d", pastAckedSymbols, pastTotalSymbols)
	log.Printf("Packet: Retrans: %d, Sent: %d", pastRetransPackets, pastTotalPackets)
	log.Printf("RetransRate: %f, Lossrate: %f", pastRetransRate, pastLossRate)
	log.Printf("weighted lossRate: %f, reTransRate: %f", lossRate, reTransRate)
	log.Println("Threshold Updated: ", t.timeThreshold, t.dupThreshold)
	log.Printf("\n")

}

func (t *ThreshController) refreshThreshold(loss, retrans float64) {

	// 重传率较低，应该降低阈值, mutiple decrease
	if retrans <= loss {
		t.dupThreshold = t.dupThreshold / 2
		t.timeThreshold = t.timeThreshold * (1 - DELTA)

		// //如果阈值在减小，不需要清空trigger，继续统计
		t.triggers = [2]int{}

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
	t.dupThreshold = min(MAX_DUP_THRESH, max(t.dupThreshold, MIN_DUP_THRESH))
	t.timeThreshold = min(MAX_TIME_THRESH, max(t.timeThreshold, MIN_TIME_THRESH))
	t.thresholdStatistic = append(t.thresholdStatistic, map[uint64][2]float64{t.epochIndex: {float64(t.timeThreshold), float64(t.dupThreshold)}})

}

func (t *ThreshController) OnPacketLostBy(reason LossTrigger) {
	// log.Println("Loss Triggered")
	if reason == lossByDelay {
		t.triggers[0]++
	}
	if reason == lossByDuplicate {
		t.triggers[1]++
	}
}

func (t *ThreshController) getDupThreshold() int {
	return int(t.dupThreshold)

}

func (t *ThreshController) getTimeThreshold() float64 {
	return float64(t.timeThreshold)
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

// // 计算当前时隙的权重
// NSentPktAvg := t.packetStatistic.Sent / t.epochIndex
// w1 := 0.5 / (1.0 + math.Exp(-float64(deltaSentPkt-NSentPktAvg)))
// // w1 = 0
// reTransRate := w1*curRetransRate + (1.0-w1)*t.packetStatistic.retransRate

// // 更新当前时间的Symbol丢失信息
// deltaSentSymbol := nNumberOfSymbolsSent - t.symbolStatistic.Sent
// deltaAckedSymbol := uint64(Acked) - t.symbolStatistic.Acked
// curLossRate := 1.0 - float64(deltaAckedSymbol)/float64(deltaSentSymbol)
// // 计算当前时隙的权重
// NSentSymbolAvg := t.symbolStatistic.Sent / t.epochIndex
// w2 := 0.5 / (1.0 + math.Exp(-float64(deltaSentSymbol-NSentSymbolAvg)))
// // w2 = 0
// lossRate := w2*curLossRate + (1.0-w2)*t.symbolStatistic.lossRate

// log
// log.Printf("(TC) newlyLoss: Delay: %d, Dup: %d, total: %d", t.triggers[0], t.triggers[1], t.triggers[0]+t.triggers[1])
// log.Printf("------------Global (new gap)----------------")
// log.Printf("Symbol: Acked: %d, Sent: %d", Acked, nNumberOfSymbolsSent)
// log.Printf("Packet: Retrans: %d, Sent: %d", nRetrans, nPackets)
// log.Printf("RetransRate: %f, Lossrate: %f", float64(nRetrans)/float64(nPackets), 1.0-float64(Acked)/float64(nNumberOfSymbolsSent))
// log.Printf("------------Newly (new gap)-----------------")
// log.Printf("Symbol: Acked: %d, Sent: %d", deltaAckedSymbol, deltaSentSymbol)
// log.Printf("Packet: Retrans: %d, Sent: %d", deltaRetransPkt, deltaSentPkt)
// log.Printf("RetransRate: %f, Lossrate: %f", float64(deltaRetransPkt)/float64(deltaSentPkt), 1-float64(deltaAckedSymbol)/float64(deltaSentSymbol))
// log.Printf("weighted lossRate: %f, reTransRate: %f", lossRate, reTransRate)
// log.Println("Threshold Updated: ", t.timeThreshold, t.dupThreshold)
// log.Printf("\n")
