package fec

import (
	"log"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

const (
	MaxSourceSymbols int = 255
	MinSourceSymbols int = 2
)

const (
	Nrtts    int     = 3
	Nsamples int     = 3
	RCInit   float64 = 10
	// target residual loss
	GammaTarget float64 = 0.03
	Delta       float64 = 0.33
)

type TransParams struct {
	SntPkts, SntRetrans, SntLost uint64
	RcvPkts, RecoveredPkts       uint64
	SmoothedRTT                  time.Duration
}

type rquicRedundancyController struct {
	PresentParas  TransParams
	LastSavedPara TransParams
	// 3 epsilons result in an average
	epsilon [Nsamples]float64

	NumberOfSourceSymbols     uint8
	NumberOfRepairSymbols     uint8
	NumberOfInterleavedBlocks uint8

	timeflag time.Time
	gamma    float64
	state    uint8

	// test
	packetLost uint64
	packetRec  uint64
}

func NewrQuicRedundancyController(NumberOfSourceSymbols, NumberOfRepairSymbols uint8) RedundancyController {
	return &rquicRedundancyController{
		NumberOfSourceSymbols: NumberOfRepairSymbols,
		NumberOfRepairSymbols: NumberOfRepairSymbols,
		timeflag:              time.Now(),
		gamma:                 float64(RCInit),
	}
}

var _ RedundancyController = &rquicRedundancyController{}

func (r *rquicRedundancyController) OnPacketLost(pn protocol.PacketNumber) {
	r.packetLost++
	// Nothing to do thanks to TransParams
}

func (r *rquicRedundancyController) OnPacketReceived(protocol.PacketNumber) {
	r.packetRec++
	// Nothing to do thanks to TransParams
}

func (r *rquicRedundancyController) GetNumberOfDataSymbols() uint {
	return uint(r.gamma)
}

func (r *rquicRedundancyController) GetNumberOfRepairSymbols() uint {
	return uint(r.NumberOfRepairSymbols)
	// return 1
}

func (r *rquicRedundancyController) GetNumberOfInterleavedBlocks() uint {
	// return uint(r.NumberOfInterleavedBlocks)
	return 1
}

func (r *rquicRedundancyController) GetWindowStepSize() uint {
	// don't care this temporary
	return 2
}

func (r *rquicRedundancyController) PushParamerters(paras TransParams) {
	now := time.Now()
	// log.Println("SmoothedRTT: %t", paras.SmoothedRTT)
	// 每3个rtt更新一次参数
	if now.Sub(r.timeflag) < 5*paras.SmoothedRTT {
		return
	}
	// 刷新时间点
	r.timeflag = now
	// 将当前的参数传入rc,并计算这3个rtt对应的epsilon
	r.populateParas(paras)
	r.epsilon[r.state] = r.getcurrentEpsilon()

	log.Printf("Saved: SntPkts %d,SntLost %d,SntRetrans %d,RcvPkts %d,Recover %d",
		r.PresentParas.SntPkts,
		r.PresentParas.SntLost,
		r.PresentParas.SntRetrans,
		r.PresentParas.RcvPkts,
		r.PresentParas.RecoveredPkts)
	log.Printf("Gamma:%f, Epsilon:%f, Epsilon[0]:%f, Epsilon[1]:%f, Epsilon[2]:%f", r.gamma, ArithmeticAverage(r.epsilon), r.epsilon[0], r.epsilon[1], r.epsilon[2])
	log.Printf("r.state: %d,r.epsilon[%d]: %f", r.state, r.state, r.epsilon[r.state])

	r.state += 1
	// 每3次参数更新计算一次新的rc
	if r.state == uint8(Nsamples) {
		log.Println("Refresh Parameters!")
		// 这个时候r.state的3个元素都有值,可以取平均用于计算冗余
		r.computeEstimations()

		// 计算完之后删除epsilon
		r.epsilon = [3]float64{0, 0, 0}
		// 并将state置为0
		r.state = r.state % uint8(Nsamples)
	}
	log.Printf("CALLBACK: OnPacketLost:%d, OnPacketReceived:%d", r.packetLost, r.packetRec)
	log.Println("------------------------------------------")
}

func (r *rquicRedundancyController) computeEstimations() {
	// r.epsilon = append(r.epsilon, r.getcurrentEpsilon())
	// Average = (e[0] + e[1] + e[2]) / 3
	Average := ArithmeticAverage(r.epsilon)

	if Average > GammaTarget {
		r.gamma = r.gamma * (1 - Delta)
	} else {
		r.gamma = r.gamma * (1 + Delta)
	}

	// limit gamma within 2~255
	if (r.gamma) > float64(MaxSourceSymbols) {
		r.gamma = float64(MaxSourceSymbols)
	}
	if r.gamma < float64(MinSourceSymbols) {
		r.gamma = float64(MinSourceSymbols)
	}

	log.Printf("NewEpsilon: %f,r.gamma: %f", Average, r.gamma)
}

func (r *rquicRedundancyController) getcurrentEpsilon() float64 {
	if r.PresentParas.SntRetrans == r.PresentParas.SntPkts {
		return 1
	}
	// return float64(r.PresentParas.SntRetrans) / (float64(r.PresentParas.SntPkts) - float64(r.PresentParas.SntRetrans))
	return float64(r.PresentParas.SntRetrans) / (float64(r.PresentParas.SntPkts))
}

func (r *rquicRedundancyController) populateParas(paras TransParams) {
	r.showconfig(paras)
	r.PresentParas.SntPkts = paras.SntPkts - r.LastSavedPara.SntPkts
	r.PresentParas.SntLost = paras.SntLost - r.LastSavedPara.SntLost
	r.PresentParas.SntRetrans = paras.SntRetrans - r.LastSavedPara.SntRetrans
	r.PresentParas.RcvPkts = paras.RcvPkts - r.LastSavedPara.RcvPkts
	r.PresentParas.RecoveredPkts = paras.RecoveredPkts - r.LastSavedPara.RecoveredPkts

	r.LastSavedPara = paras

}

func ArithmeticAverage(e [3]float64) float64 {
	return (e[0] + e[1] + e[2]) / 3
}

func (r *rquicRedundancyController) showconfig(Newparas TransParams) {
	log.Printf("Present: SntPkts %d,SntLost %d,SntRetrans %d,RcvPkts %d,Recover %d",
		Newparas.SntPkts,
		Newparas.SntLost,
		Newparas.SntRetrans,
		Newparas.RcvPkts,
		Newparas.RecoveredPkts)
	log.Printf("LastSavedPara: SntPkts %d,SntLost %d,SntRetrans %d,RcvPkts %d,Recover %d",
		r.LastSavedPara.SntPkts,
		r.LastSavedPara.SntLost,
		r.LastSavedPara.SntRetrans,
		r.LastSavedPara.RcvPkts,
		r.LastSavedPara.RecoveredPkts)

}
