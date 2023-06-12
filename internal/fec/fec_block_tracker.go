package fec

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

const DEFAULT_MAX_TRACE_BLOCKS = 5000
const SYMBOL_GAP = 5

type BlockTracker struct {
	ReceivedFrames     map[protocol.FECBlockNumber][]map[protocol.FecFrameOffset]*wire.FECFrame
	ReceivedSymbol     map[protocol.FECBlockNumber][]*RepairSymbol
	lastReceivedSymbol protocol.NumberOfAckedSymbol
	isExpiredBlocks    map[protocol.FECBlockNumber]bool
}

func NewBlockTracker(maxTrace uint64) *BlockTracker {
	// 暂时不用
	if maxTrace == 0 {
		maxTrace = DEFAULT_MAX_TRACE_BLOCKS
	}

	return &BlockTracker{
		ReceivedFrames:  make(map[protocol.FECBlockNumber][]map[protocol.FecFrameOffset]*wire.FECFrame),
		ReceivedSymbol:  make(map[protocol.FECBlockNumber][]*RepairSymbol),
		isExpiredBlocks: make(map[protocol.FECBlockNumber]bool),
	}
}

// 当接收到一个FECFrame时，将其按照BlockNumber对应放置
// 并且适当生成Symbol并统计
func (b *BlockTracker) ReceivedNewFECFrame(frame *wire.FECFrame) {
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
	}
	symbol, _, _ := b.UpdateNewlyConfirmedSymbols(frame)
	if symbol != nil {
		b.ReceivedSymbol[frame.FECBlockNumber] = append(b.ReceivedSymbol[frame.FECBlockNumber], symbol)
	}
	// 适当删除某个Block,注意是整个block一起删除
	symbolsForTheBlock := b.ReceivedSymbol[frame.FECBlockNumber]
	if len(symbolsForTheBlock) >= int(symbol.NumberOfRepairSymbols) {
		delete(b.ReceivedFrames, frame.FECBlockNumber)
		b.isExpiredBlocks[frame.FECBlockNumber] = true
	}

	b.UpdateTackerByBlock()
}

func (b *BlockTracker) UpdateNewlyConfirmedSymbols(receivedFrame *wire.FECFrame) (*RepairSymbol, int, int) {
	// 定位到group
	fecBlockNumber := receivedFrame.FECBlockNumber
	// 取出waitingframe
	waitingFrames, ok := b.ReceivedFrames[fecBlockNumber]
	if !ok || len(waitingFrames) == 0 {
		// there are no waiting frames
		return nil, -1, -1
		// 第二个参数：该group涉及的数据包(packet)数，第三个参数：涉及的修复符合数(RepairSymbol)
	}
	if len(waitingFrames) <= int(receivedFrame.Offset) {
		delta := int(receivedFrame.Offset) - len(waitingFrames)
		for i := 0; i <= delta; i++ {
			waitingFrames = append(waitingFrames, make(map[protocol.FecFrameOffset]*wire.FECFrame))
		}
		b.ReceivedFrames[fecBlockNumber] = waitingFrames
		// 补齐
	}
	waitingFramesForSymbol := waitingFrames[receivedFrame.RepairSymbolNumber]
	if len(waitingFramesForSymbol) == 0 {
		// there are no waiting frames
		return nil, -1, -1

	}
	// 以上的提前返回说明还没有收到waitingFramesForSymbol，或者还达不到生成symbol的条件
	//
	//

	if len(waitingFramesForSymbol) == 1 {
		if !receivedFrame.FinBit || receivedFrame.Offset != 0 {
			// there is only one waiting (which is the receivedFrame) frame which does not contain a full symbol, so obviously we cannot return symbols
			return nil, -1, -1
		} else {
			// there is only one FEC Frame, which contains a full symbol and has the FinBit set so return the symbol
			// 由于waitingFECFrames是以fecBlockNumber区分的，直接删除
			delete(b.ReceivedFrames, fecBlockNumber)
			symbol := &RepairSymbol{
				FECSchemeSpecific: receivedFrame.FECSchemeSpecific,
				FECBlockNumber:    receivedFrame.FECBlockNumber,
				SymbolNumber:      receivedFrame.RepairSymbolNumber,
				// ??不太能理解
				// 明白了！这是因为waitingFramesForSymbol只有1个，说明当然frame自带finbit，即带有一个完整symbol的载荷
				Data: receivedFrame.Data,
			}
			return symbol, int(receivedFrame.NumberOfPackets), int(receivedFrame.NumberOfRepairSymbols)
		}
	}

	//
	//
	// 程序进行至此说明waitingFramesForSymbol不止一个，即是多个frame构成一个symbol；FinBit已经取得，说明symbol已经发送完毕,可以重建
	finBitFound := false
	var largestOffset protocol.FecFrameOffset = 0
	// 是否能找到Finbit
	for _, frame := range waitingFramesForSymbol {
		if frame.FinBit {
			finBitFound = true
		}

		// 及时更新largestOffset
		if frame.Offset > largestOffset {
			largestOffset = frame.Offset
		}
	}

	// 如果没找到Finbit，则说明还没发送完毕，直接返回
	if !finBitFound || int(largestOffset) >= len(waitingFramesForSymbol) {
		// there is no packet with fin bit, or the largest offset in the waiting frames is greater than the number of waiting frames
		// all frames are not present in the waiting frames for the symbol, the payload is thus not complete
		return nil, -1, -1

	} else {
		// the frames are all present in the waitingFrames
		// the payload is complete, extract it！
		// 漂亮！万事俱备，只欠东风，接下来直接重建symbol！
		orderedFrames := make([]*wire.FECFrame, len(waitingFramesForSymbol))
		for _, frame := range waitingFramesForSymbol {
			// 先排序，乱序可能是网络原因——乱序到达
			orderedFrames[frame.Offset] = frame
		}
		var payloadData []byte

		// 每个frame的data合起来，就算整个Symbol的data了
		for _, frame := range orderedFrames {
			payloadData = append(payloadData, frame.Data...)
		}

		// remove the frames from waitingFECFrames, as the payload has been recovered
		// modify: zhaolee
		// b.ReceivedFrames[fecBlockNumber][receivedFrame.RepairSymbolNumber] = nil

		//delete(b.ReceivedFrames[fecBlockNumber], receivedFrame.RepairSymbolNumber)

		var nPackets, nRepairSymbols byte
		if orderedFrames[0] != nil {
			nPackets = orderedFrames[0].NumberOfPackets
			nRepairSymbols = orderedFrames[0].NumberOfRepairSymbols
		}
		return &RepairSymbol{
			FECSchemeSpecific: receivedFrame.FECSchemeSpecific,
			FECBlockNumber:    fecBlockNumber,
			Data:              payloadData,
			SymbolNumber:      receivedFrame.RepairSymbolNumber,
		}, int(nPackets), int(nRepairSymbols)
	}
}

// 计算所有block统计的所有冗余包并返回
func (b *BlockTracker) CountReceivedSymbol() protocol.NumberOfAckedSymbol {
	var numSymbols protocol.NumberOfAckedSymbol
	for _, Symbols := range b.ReceivedSymbol {
		numSymbols += protocol.NumberOfAckedSymbol(len(Symbols))
	}
	return numSymbols
}

// 返回一个SmybolACKFrame
func (b *BlockTracker) GetSymbolACKFrame() *wire.SymbolAckFrame {
	nCurrentSymbols := b.CountReceivedSymbol()
	if nCurrentSymbols < b.lastReceivedSymbol+SYMBOL_GAP {
		return nil
	}
	b.lastReceivedSymbol = nCurrentSymbols
	frame := &wire.SymbolAckFrame{
		SymbolReceived: nCurrentSymbols,
	}
	return frame
}

// 如果track了超过5000个
func (b *BlockTracker) UpdateTackerByBlock() {
	if len(b.ReceivedFrames) < DEFAULT_MAX_TRACE_BLOCKS {
		return
	}
	// TODO:complete
	// b.ReceivedFrames = b.ReceivedFrames[]
}
