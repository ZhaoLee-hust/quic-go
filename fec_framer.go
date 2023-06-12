package quic

import (
	"github.com/lucas-clemente/quic-go/fec"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

// 看起来，主要用途是把symbol打散成frame
type FECFramer struct {
	// 里面是[]*fec.RepairSymbol
	transmissionQueue []*fec.RepairSymbol

	// 这个参数指的是，取出一定的frame后，下一个frame在symbol中的起点
	currentOffsetInSymbol protocol.ByteCount

	version protocol.VersionNumber

	// 这个参数会被传递给FECFrame的Offset，指frame在symbol内的偏移
	currentFrameOffset int
	FECSender
}

type FECSender interface {
	// 在session中实现
	// select {
	// case s.fecScheduled <- struct{}{}:}
	onHasFECData()
}

func newFECFramer(sender FECSender, version protocol.VersionNumber) *FECFramer {
	return &FECFramer{
		FECSender: sender,
		version:   version,
	}
}

// Pops some FEC Frames from the transmission buffer if there is space enough and returns a tuple (res, takenPayload)
// with takenPayload the payload size taken by these frames
//
//	如果有足够的空间，则从传输缓冲区弹出一些FEC帧，并返回一个元组（res，takenPayload），其中takenpaload是这些帧的有效负载大小,输入参数MaxBytes是symbol还剩余的数据量
func (f *FECFramer) maybePopFECFrames(maxBytes protocol.ByteCount) (res []*wire.FECFrame, takenPayload protocol.ByteCount, error error) {
	defer func() {
		if len(f.transmissionQueue) > 0 {
			f.onHasFECData()
		}
	}()
	takenPayload = 0
	if maxBytes > 0 && len(f.transmissionQueue) > 0 {
		// 第二个参数是该frame的总长度，包括hdr和body(这里是Len(frame.Data))
		// 从queue中取出一个frame
		frame, takenPayload := f.popFECFrame(maxBytes)
		return []*wire.FECFrame{frame}, takenPayload, nil
	}

	return
}

// 从传输队列的第一个符号中pop一个FECframe,maxBytes指的是这个Frame最大占据多少字节
func (f *FECFramer) popFECFrame(maxBytes protocol.ByteCount) (*wire.FECFrame, protocol.ByteCount) {
	if len(f.transmissionQueue) == 0 {
		return nil, 0
	}
	// 取出第一个修复符号
	symbol := f.transmissionQueue[0]

	// 临时生成一个frame，根据版本判断帧的大小
	tempFrame := wire.FECFrame{Offset: protocol.FecFrameOffset(f.currentOffsetInSymbol), RepairSymbolNumber: symbol.SymbolNumber}
	fecFrameHeaderLength, _ := tempFrame.MinLength(f.version)

	// 已经不足以取出一个frame了?
	if maxBytes <= fecFrameHeaderLength {
		return nil, 0
	}

	maxBytes -= fecFrameHeaderLength

	// 剩下的data是需要发送的
	remainingData := symbol.Data[f.currentOffsetInSymbol:]
	// 确定发送长度
	lenDataToSend := utils.Min(int(maxBytes), len(remainingData))
	// 取出带发送data
	dataToSend := remainingData[:lenDataToSend]

	// 从RepairSymbol提取一个FECFrame
	frame := &wire.FECFrame{
		FECSchemeSpecific:     symbol.FECSchemeSpecific,
		FECBlockNumber:        symbol.FECBlockNumber,
		Offset:                protocol.FecFrameOffset(f.currentFrameOffset),
		RepairSymbolNumber:    symbol.SymbolNumber,
		DataLength:            protocol.FecFrameLength(len(dataToSend)),
		Data:                  dataToSend,
		NumberOfPackets:       byte(symbol.NumberOfPackets),
		NumberOfRepairSymbols: byte(symbol.NumberOfRepairSymbols),
		Convolutional:         symbol.Convolutional,
		EncodingSymbolID:      symbol.EncodingSymbolID,
	}

	f.currentOffsetInSymbol += protocol.ByteCount(lenDataToSend)

	// 余下的data长度等于刚刚生成的frame的长度，也就是说这一次生成frame已经取完了symbol
	if lenDataToSend == len(remainingData) {
		// We've read the symbol until the end
		f.currentOffsetInSymbol = 0
		f.currentFrameOffset = 0
		// 直接把这个qunue去除
		f.transmissionQueue = f.transmissionQueue[1:]
		// 并且设置结束标志位
		frame.FinBit = true
	} else {
		// 后面还需要划分成多个frame，因此offset加一即可
		f.currentFrameOffset++
	}
	// 这个Minlength是头部header的长度
	ml, _ := frame.MinLength(f.version)
	return frame, ml + protocol.ByteCount(len(frame.Data))
}

// TODO: make this thread safe (channels)
func (f *FECFramer) popRepairSymbol() (retVal *fec.RepairSymbol) {
	retVal, f.transmissionQueue = f.transmissionQueue[0], f.transmissionQueue[1:]
	return
}

// f.transmissionQueue = append(f.transmissionQueue, symbol)
func (f *FECFramer) pushRepairSymbol(symbol *fec.RepairSymbol) {
	f.transmissionQueue = append(f.transmissionQueue, symbol)
	f.onHasFECData()
}

// f.transmissionQueue = append(f.transmissionQueue, symbols...)
func (f *FECFramer) pushRepairSymbols(symbols []*fec.RepairSymbol) {
	f.transmissionQueue = append(f.transmissionQueue, symbols...)
}

// return len(f.transmissionQueue) > 0
func (f *FECFramer) hasFECDataToSend() bool {
	return len(f.transmissionQueue) > 0
}
