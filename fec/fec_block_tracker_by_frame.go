package fec

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type BlockTrackerByFrame struct {
	ReceivedFrames               map[protocol.FECBlockNumber][]map[protocol.FecFrameOffset]*wire.FECFrame
	toltalNumberOfFramesReceived uint64
	isExpiredBlocks              map[protocol.FECBlockNumber]bool
}

var _ SymbolBlockTracker = &BlockTrackerByFrame{}

func NewBlockTrackerByFrame() *BlockTrackerByFrame {

	return &BlockTrackerByFrame{
		ReceivedFrames:               make(map[protocol.FECBlockNumber][]map[protocol.FecFrameOffset]*wire.FECFrame),
		toltalNumberOfFramesReceived: 0,
	}
}

func (b *BlockTrackerByFrame) GetSymbolACKFrame() *wire.SymbolAckFrame {

	return &wire.SymbolAckFrame{
		SymbolReceived: protocol.NumberOfAckedSymbol(b.toltalNumberOfFramesReceived),
	}
}

func (b *BlockTrackerByFrame) ReceivedNewFECFrame(frame *wire.FECFrame) {
	if _, ok := b.isExpiredBlocks[frame.FECBlockNumber]; ok {
		return
	}
	// add frame if not already present
	FramesInBlock := b.ReceivedFrames[frame.FECBlockNumber]

	// 补齐,将[]map的长度扩充到Symbol的个数
	if len(FramesInBlock) <= int(frame.RepairSymbolNumber) {
		delta := int(frame.RepairSymbolNumber) - len(FramesInBlock)
		for i := 0; i <= delta; i++ {
			FramesInBlock = append(FramesInBlock, make(map[protocol.FecFrameOffset]*wire.FECFrame))
		}
		b.ReceivedFrames[frame.FECBlockNumber] = FramesInBlock
	}

	FramesInSymbol := FramesInBlock[frame.RepairSymbolNumber]
	if _, ok := FramesInSymbol[frame.Offset]; !ok {
		// 定位Group--定位某个Symbol的--定位到具体的Frame
		FramesInSymbol[frame.Offset] = frame
		b.toltalNumberOfFramesReceived += 1
	}
	FramesInBlock[frame.RepairSymbolNumber] = FramesInSymbol
}
