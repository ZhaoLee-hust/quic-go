package ackhandler

import (
	"time"

	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

const (
	// 初始阈值
	DEFAULT_TIME_THRESH   = 1.0 / 8.0
	DEFAULT_PACKET_THRESH = 3
	// 时间阈值最值
	MAX_TIME_THRESH = 5.0
	MIN_TIME_THRESH = 9.0 / 8.0
	// 数量阈值最值
	MAX_PACKET_THRESH = 100.0
	MIN_PACKET_THRESH = 3.0
	// 平滑滤波默认参数
	ALPHA = 0.5
	// MD参数
	DELTA = 0.1
	Krtt  = 3
)

const BASE = 3
const BASE_REDU = 0.1

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

type QUICLRController struct {
	// 定义时间阈值和数量阈值
	timeThreshold   float64
	packetThreshold float64

	lastMaxAckedSymbol protocol.SymbolNumber

	byPacket uint16
	byTime   uint16

	// pkt和rtt的回调函数
	// h.packets, h.retransmissions, h.losses
	pktCallBacK func() (uint64, uint64, uint64)
	rttCallBack *congestion.RTTStats

	// 后面的赞不需要
	// symbol的统计参数
	symbolStatistic *symbolStatistic
	// packet的统计参数
	packetStatistic *pktStatistic

	//时间周期
	lastRefreshTime time.Time

	// 统计函数
	thresholdStatistic []map[uint64][2]float64
	symbolsStatistic   []map[uint64][2]uint64
	pktStatistic       []map[uint64][2]uint64
}

func NewThreshController(pktcallback func() (uint64, uint64, uint64), rttCallBack *congestion.RTTStats) *QUICLRController {

	return &QUICLRController{
		// 阈值
		timeThreshold:   DEFAULT_TIME_THRESH,
		packetThreshold: DEFAULT_PACKET_THRESH,
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
	}
}
func (t *QUICLRController) getSmothedRTT() time.Duration {
	return t.rttCallBack.SmoothedRTT()
}

func (t *QUICLRController) updateThreshold(SymbolACK *wire.SymbolAckFrame) {
	lossRate := 1 - float64(SymbolACK.SymbolReceived)/float64(SymbolACK.MaxSymbolReceived)
	nPackets, nRetrans, _ := t.pktCallBacK()
	if nPackets == nRetrans {
		utils.Debugf("BUG:全部重传了！")
	}
	retransRate := float64(nRetrans) / (float64(nPackets) - float64(nRetrans))
	// 计算NRTT=SRTT(P(n)-P(n-1))/(t(n)-t(n-1))
	NRTT := t.getSmothedRTT() * time.Duration(SymbolACK.MaxSymbolReceived-t.lastMaxAckedSymbol) / time.Since(t.lastRefreshTime)
	if t.byPacket+t.byTime == 0 {
		utils.Debugf("No Loss in the Previous Period!")
		return
	}
	// 分配比例
	nPT := float64(t.byPacket) / float64(t.byPacket+t.byTime)
	nTT := 1 - nPT
	// 更新阈值
	if retransRate > lossRate {
		t.IncreaseThreshold(protocol.NumberOfAckedSymbol(NRTT), nPT, nTT)
	} else if retransRate < lossRate {
		t.DecreaseThreshold(protocol.NumberOfAckedSymbol(NRTT), nPT, nTT)
	}
	// fmt.Printf("nPT:%v,nTT:%v,NRTT:%v,retrans:%v,loss:%v,\n", nPT, nTT, NRTT, retransRate, lossRate)
	// fmt.Printf("数据包数量:%v,重传数量:%v,冗余包确认数量:%v,冗余包最大确认号:%v\n", nPackets, nRetrans, SymbolACK.SymbolReceived, SymbolACK.MaxSymbolReceived)
	// 控制范围
	t.timeThreshold = max(MIN_TIME_THRESH, min(MAX_TIME_THRESH, t.timeThreshold))
	t.packetThreshold = max(MIN_PACKET_THRESH, min(MAX_PACKET_THRESH, t.packetThreshold))
	// 复位
	t.byTime = 0
	t.byPacket = 0
	t.lastRefreshTime = time.Now()
	t.lastMaxAckedSymbol = SymbolACK.MaxSymbolReceived
}

func (t *QUICLRController) IncreaseThreshold(NRTT protocol.NumberOfAckedSymbol, nPT, nTT float64) {
	// 增加
	t.timeThreshold += BASE * nTT / float64(NRTT)
	t.packetThreshold += BASE * nPT
}

func (t *QUICLRController) DecreaseThreshold(NRTT protocol.NumberOfAckedSymbol, nPT, nTT float64) {
	// 减少
	t.timeThreshold = t.timeThreshold * (1 - BASE_REDU*nTT/float64(NRTT))
	t.packetThreshold = t.packetThreshold * (1 - BASE_REDU*nPT)
}

func (t *QUICLRController) OnPacketLostBy(reason LossTrigger) {
	// log.Println("Loss Triggered")
	if reason == lossByDelay {
		t.byTime++
	}
	if reason == lossByDuplicate {
		t.byPacket++
	}
}

func (t *QUICLRController) getPacketThreshold() int {
	return int(t.packetThreshold)

}

func (t *QUICLRController) getTimeThreshold() float64 {
	return float64(t.timeThreshold)
}

func min[T float32 | uint | float64](i, j T) T {
	if i > j {
		return j
	}

	return i
}

func max[T float32 | uint | float64](i, j T) T {
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
