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
)

type reorderThreshController struct {
	minTimeThresh, maxTimeThresh uint
	minDupThresh, maxDupThresh   uint
	alpha                        float32
	delta                        float32
}

func NewThreshController() *reorderThreshController {
	return &reorderThreshController{
		minTimeThresh: DEFAULT_TIME_THRESH,
		minDupThresh:  DEFAULT_DUP_THRESH,
		alpha:         ALPHA,
		delta:         DELTA,
		maxTimeThresh: MAX_TIME_THRESH,
		maxDupThresh:  MAX_DUP_THRESH,
	}
}
