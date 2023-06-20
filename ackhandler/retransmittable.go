package ackhandler

import "github.com/lucas-clemente/quic-go/internal/wire"

// Returns a new slice with all non-retransmittable frames deleted.
func stripNonRetransmittableFrames(fs []wire.Frame) []wire.Frame {
	res := make([]wire.Frame, 0, len(fs))
	for _, f := range fs {
		if IsFrameRetransmittable(f) {
			res = append(res, f)
		}
	}
	return res
}

// abort FEC frame,FEC帧可能被丢弃
// Returns a new slice with all non-retransmittable frames deleted excepted unreliable stream frames.
func stripNonRetransmittableExceptedUnrealiableStreamFrames(fs []wire.Frame) []wire.Frame {
	res := make([]wire.Frame, 0, len(fs))
	for _, f := range fs {
		if _, isSF := f.(*wire.StreamFrame); isSF || IsFrameRetransmittable(f) {
			res = append(res, f)
		}
	}
	return res
}

// Returns a new slice with all non-retransmittable frames deleted excepted unreliable stream frames.
// 留下的：流帧、可重传帧(除了StopWaitingFrame、AckFrame、FECFrame)和FEC相关的帧
func stripNonRetransmittableExceptedUnrealiableStreamFramesOrFECRelatedFrames(fs []wire.Frame) []wire.Frame {
	res := make([]wire.Frame, 0, len(fs))
	for _, f := range fs {
		if _, isSF := f.(*wire.StreamFrame); isSF || IsFrameRetransmittable(f) || IsFECRelated(f) {
			res = append(res, f)
		}
	}
	return res
}

// IsFrameRetransmittable returns true if the frame should be retransmitted.
// 除了StopWaitingFrame、AckFrame、(FECFrame)，这三个不重传
func IsFrameRetransmittable(f wire.Frame) bool {
	switch f2 := f.(type) {
	case *wire.StopWaitingFrame:
		return false
	case *wire.AckFrame:
		return false
		// added by michelfra: FEC Frames and Unreliable Frames handling
	case *wire.FECFrame:
		return false
	case *wire.StreamFrame:
		return !f2.Unreliable || !f2.DeadlineExpired()
	default:
		return true
	}
}

// IsFrameRetransmittable returns true if the frame should be retransmitted.
func IsFECRelated(f wire.Frame) bool {
	switch f.(type) {
	case *wire.RecoveredFrame:
		return true
	case *wire.FECFrame:
		return true
	default:
		return false
	}
}

// HasRetransmittableFrames returns true if at least one frame is retransmittable.
// 包括：StopWaitingFrame、AckFrame、FECFrame
func HasRetransmittableFrames(fs []wire.Frame) bool {
	for _, f := range fs {
		if IsFrameRetransmittable(f) {
			return true
		}
	}
	return false
}

// HasRetransmittableFrames returns true if at least one frame is retransmittable.
// true：是流帧；
// false：StopWaitingFrame、AckFrame、(FECFrame)
func HasRetransmittableOrUnreliableStreamFrames(fs []wire.Frame) bool {
	for _, f := range fs {
		switch f.(type) {
		case *wire.StreamFrame:
			return true
		}
		if IsFrameRetransmittable(f) {
			return true
		}
	}
	// 不能识别的帧类型
	return false
}

// HasRetransmittableFrames returns true if at least one frame is retransmittable.
func HasFECRelatedFrames(fs []wire.Frame) bool {
	for _, f := range fs {
		switch f.(type) {
		case *wire.FECFrame:
			return true
		case *wire.RecoveredFrame:
			return true
		}
	}
	return false
}
