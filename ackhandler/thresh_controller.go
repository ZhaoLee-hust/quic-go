package ackhandler

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
	Krtt  = 3
)

type ThreshController struct {
	timeThreshold       float32
	dupThreshold        uint
	thresholdArgs       *ThresholdArgs
	lastSymbolStatistic *SymbolStatistic
	curSymbolStatistic  *SymbolStatistic
}

func NewThreshController() *ThreshController {
	args := &ThresholdArgs{
		MinTimeThresh: DEFAULT_TIME_THRESH,
		MinDupThresh:  DEFAULT_DUP_THRESH,
		alpha:         ALPHA,
		delta:         DELTA,
		krtt:          Krtt,
		MaxTimeThresh: MAX_TIME_THRESH,
		MaxDupThresh:  MAX_DUP_THRESH,
	}
	return &ThreshController{
		timeThreshold:       DEFAULT_TIME_THRESH,
		dupThreshold:        DEFAULT_DUP_THRESH,
		thresholdArgs:       args,
		lastSymbolStatistic: newSymbolStatistic(),
		curSymbolStatistic:  newSymbolStatistic(),
	}
}

func (thr *ThreshController) receiveSomeSymbols(n uint32) {
	// thr.
}

func (thr *ThreshController) ackedSomeSymbols(n uint32) {

}

func (thr *ThreshController) getDupThreshold() uint {
	return thr.dupThreshold

}

func (thr *ThreshController) getTimeThreshold() float32 {
	return thr.timeThreshold
}

func (thr *ThreshController) setMaxTimeThreshold(t float32) {
	thr.thresholdArgs.MaxTimeThresh = t
}
func (thr *ThreshController) setMaxDupThreshold(n uint) {
	thr.thresholdArgs.MaxDupThresh = n
}

type SymbolStatistic struct {
	numberOfSymbols      uint32
	numberOfSymbolsAcked uint32
}

func newSymbolStatistic() *SymbolStatistic {
	return &SymbolStatistic{
		numberOfSymbols:      0,
		numberOfSymbolsAcked: 0,
	}
}

type ThresholdArgs struct {
	MinTimeThresh, MaxTimeThresh float32
	MinDupThresh, MaxDupThresh   uint
	alpha                        float32
	delta                        float32
	krtt                         uint
}
