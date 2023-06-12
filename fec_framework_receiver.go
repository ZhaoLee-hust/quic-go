package quic

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/lucas-clemente/quic-go/fec"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

/**
 *	Receives payloads and repair symbols for a block (FEC Group) and gives it to the FEC scheme. FEC scheme returns :
 * 		- One or more Recovered FEC Source payloads (recovered packets)
 */

//		+----------------------+
//		|     Application      |
//		+----------------------+
//		^
//		|
//		|(6) ADUs
//		|
//		+----------------------+                           +----------------+
//		|    FEC Framework     |                           |                |
//		|                      |<--------------------------|   FEC Scheme   |
//		|(2)Extract FEC Payload|(5) Recovered QUIC packets |                |
//		|   IDs and pass IDs,  |                           |(4) FEC Decoding|
//		|   payloads & symbols |-------------------------->|                |
//		|   to FEC scheme      |(3) Explicit Source FEC    |                |
//		+----------------------+    Payload IDs            +----------------+
//		^             ^         Source payloads (FEC-protected packets)
//		|             |         Repair symbols
//		|             |
//		|             |
//		|Source       |Repair FEC Frames
//		|packets      |
//		|             |
//		+-- -- -- -- -- -- -- -+
//		|    QUIC Processing	 |
//		+-- -- -- -- -- -- -- -+
//		^
//		|(1) QUIC packets containing FEC source data and repair symbols (in FEC Frames)
//		|
//		+----------------------+
//		|   Transport Layer    |
//		|     (e.g., UDP)      |
//		+----------------------+
//
//		Figure 5: Receiver Operation with RTP Repair Flows

// TODO: give a maximum number of buffers and remove older buffers if full (FIFO ?), to avoid memory explosion

// Reciever的作用是：对于frame：收到frame之后将其缓存，并适时拼凑成symbol；对于Packet：收到之后恢复并向上递交
type FECFrameworkReceiver struct {
	fecGroupsBuffer *fecGroupsBuffer
	// 一个修复符号被拆成了多个帧，定位Group--定位某个Symbol的--定位到具体的Frame
	// fec frames that only contain parts of a FEC payload and that
	// wait for the next parts access: [fecPayloadID][repairSymbol][Offset]
	waitingFECFrames map[protocol.FECBlockNumber][]map[protocol.FecFrameOffset]*wire.FECFrame
	// 共用了session的成员
	recoveredPackets chan *receivedPacket
	//  TODO：找到另一种方法，而不是直接传递会话以获取版本号、收/发端和远程地址信息
	// the session that uses this handler (TODO: find another way than passing
	// the session directly to get the version number, perspective and remoteAddress informations
	session      *session
	doRecovery   bool // Debug parameter: if false, the recovered packets won't be used by the session, like if it has not been recovered
	fecScheme    fec.BlockFECScheme
	AdaptiveCtrl *fec.AdaptiveController
	blockTracker *fec.BlockTracker
}

func NewFECFrameworkReceiver(s *session, fecScheme fec.BlockFECScheme) *FECFrameworkReceiver {
	buffer := newFecGroupsBuffer(200)
	return &FECFrameworkReceiver{
		fecGroupsBuffer: buffer,
		// TODO: find a good value for the packets buffer size rather than 1000
		waitingFECFrames: make(map[protocol.FECBlockNumber][]map[protocol.FecFrameOffset]*wire.FECFrame),
		session:          s,
		recoveredPackets: s.recoveredPackets,
		doRecovery:       true,
		fecScheme:        fecScheme,
		blockTracker:     fec.NewBlockTracker(fec.DEFAULT_MAX_TRACE_BLOCKS),
	}
}

// 将给定的packet添加到fecGroupsBuffer中,由packetUnpacker调用
func (f *FECFrameworkReceiver) handlePacket(data []byte, header *wire.Header) {
	if !header.FECFlag {
		return
	}
	fecBlockNumber := header.FECPayloadID.GetBlockNumber()
	_, ok := f.fecGroupsBuffer.fecGroups[fecBlockNumber]
	if !ok {
		group := fec.NewFECGroup(fecBlockNumber, f.session.version)
		group.AddPacket(data, header)
		f.fecGroupsBuffer.addFECGroup(group)

	}
	f.fecGroupsBuffer.addPacketInFECGroup(data, header)
	f.updateStateForSomeFECGroup(fecBlockNumber)

}

func (f *FECFrameworkReceiver) GetSymbolACKFrame() *wire.SymbolAckFrame {
	return f.blockTracker.GetSymbolACKFrame()
}

func (f *FECFrameworkReceiver) handleSymbolACKFrame(frame *wire.SymbolAckFrame) {
	log.Print("frame.SymbolReceived: %d", frame.SymbolReceived)
	// todo
}

// Recovers a packet from this FEC group if possible. If a packet has been recovered or if this FEC group is useless (there is no missing packet in the buffer),
// the buffer of this FEC group will be removed
//
//	将一个group恢复出来，并加载到session(调用函数完成)，恢复之后这个Blocknumber对应的Group会从buffer中删掉，如果不需要恢复，这个group也会删掉。
func (f *FECFrameworkReceiver) updateStateForSomeFECGroup(fecBlockNumber protocol.FECBlockNumber) error {
	group := f.fecGroupsBuffer.fecGroups[fecBlockNumber]
	if len(group.RepairSymbols) == 0 {
		return nil
	}
	if f.fecScheme.CanRecoverPackets(group) {
		// modify try to show the rr config
		// if there is one remaining packet to receive, we can find it thanks to the FEC payload and the already received packets

		start := time.Now()
		recoveredPackets, err := f.fecScheme.RecoverPackets(group)
		elapsed := time.Since(start)
		utils.Infof(fmt.Sprintf("decode time: %s, decode length: %d", elapsed, len(recoveredPackets)))
		if err != nil {
			return err
		}

		// set log
		writeString := fmt.Sprintf("%d    %d    %d    %d    %d\n",
			group.CurrentNumberOfPackets(),
			group.TotalNumberOfPackets,
			len(group.RepairSymbols),
			group.TotalNumberOfRepairSymbols,
			len(recoveredPackets))
		utils.Infof(writeString)
		// utils.Infof("-----------------------------------------------")

		if len(recoveredPackets) == 0 {
			return errors.New("the fec scheme hasn't recovered any packet although it indicated that it could")
		}
		if len(recoveredPackets) > 0 {
			// log.Printf("recovered %d packets !", len(recoveredPackets))
			// modify
			fec.NumberofRecoveredPacket += len(recoveredPackets)
		}
		for _, packet := range recoveredPackets {
			f.parseAndSendRecoveredPacket(packet)
		}
		delete(f.fecGroupsBuffer.fecGroups, fecBlockNumber)
		// RC := f.AdaptiveCtrl.GetAdaptiveRC()
	}
	if group.TotalNumberOfPackets > 0 && group.CurrentNumberOfPackets() == group.TotalNumberOfPackets && len(group.RepairSymbols) == group.TotalNumberOfRepairSymbols {
		delete(f.fecGroupsBuffer.fecGroups, fecBlockNumber)
	}
	return nil
}

// Transforms the recoveredPacket and sends it to the session, like a normal received packet
//
//	传输恢复的数据包并将其发送到session，就像正常接收的数据包一样，每次一个包
func (f *FECFrameworkReceiver) parseAndSendRecoveredPacket(recoveredPacket []byte) {
	// Handle the doRecovery debug parameter
	if !f.doRecovery {
		return
	}
	// TODO: maybe try to find a cleaner way to re-parse the bytes into a receivedPacket...
	r := bytes.NewReader(recoveredPacket)
	// r.ReadByte()并没有调用，因此r.Len()==len(recoveredPacket)

	var header *wire.Header
	var err error
	// 从packet的[][]byte中加载出header，这会调用底层quic对header的声明
	if f.session.perspective == protocol.PerspectiveServer {
		header, err = wire.ParseHeaderSentByClient(r)
	} else {
		header, err = wire.ParseHeaderSentByServer(r, f.session.version)
	}
	if err == nil {
		//  Raw？是指首字节？一直看不懂Raw字段的含义
		header.Raw = recoveredPacket[:len(recoveredPacket)-r.Len()]
		rp := &receivedPacket{
			f.session.RemoteAddr(),
			header,
			recoveredPacket[len(recoveredPacket)-r.Len():], //除了Raw字段的所有
			time.Now(),
			nil,
			true,
		}

		f.recoveredPackets <- rp
	} else {
		log.Printf("Error when parsing header of recovered packet : %s", err.Error())
	}
}

// adds the FEC frame in the waiting FEC frames and handles its payload directly if it can recover the full payload
// for the FEC group of the specified FEC frame
//
//	将FEC帧添加到等待的FEC帧中，如果可以恢复指定FEC帧的FEC组的完整有效载荷，则直接处理其有效载荷。
//
// 这个函数由session直接调用，接收到FECFrame后的行动从此开始。Frame-->Symbol-->group-->RecoveredGroup-->Upload
func (f *FECFrameworkReceiver) handleFECFrame(frame *wire.FECFrame) {
	// Copying FEC Frame data
	newData := make([]byte, len(frame.Data))
	copy(newData, frame.Data)
	frame.Data = newData
	f.putWaitingFrame(frame)
	symbol, numberOfPacketsInFECGroup, numberOfRepairSymbols := f.getRepairSymbolForSomeFECGroup(frame)
	if symbol != nil {
		// 也就是确实获取到了一个完整的symbol，那就尝试恢复，恢复成功后向上层推送
		f.handleRepairSymbol(symbol, numberOfPacketsInFECGroup, numberOfRepairSymbols)
	}
	f.blockTracker.ReceivedNewFECFrame(frame)
}

// pre: the payload argument must be a full packet payload
// addFECGroup the complete FEC Payload in a buffer in the fecGroupsMap, adds the waitingPackets of this FEC group in the buffer
// and recovers a packet if it can
func (f *FECFrameworkReceiver) handleRepairSymbol(symbol *fec.RepairSymbol, numberOfPacketsInFECGroup int, numberOfRepairSymbols int) {
	group, ok := f.fecGroupsBuffer.fecGroups[symbol.FECBlockNumber]
	if !ok {
		group = fec.NewFECGroup(symbol.FECBlockNumber, f.session.version)
		group.AddRepairSymbol(symbol)
		f.fecGroupsBuffer.addFECGroup(group)
	} else {
		group.AddRepairSymbol(symbol)
	}
	group.TotalNumberOfPackets = numberOfPacketsInFECGroup
	group.TotalNumberOfRepairSymbols = numberOfRepairSymbols
	if ok || numberOfPacketsInFECGroup == 1 {
		// recover packet if possible, remove useless buffers
		f.updateStateForSomeFECGroup(symbol.FECBlockNumber)
	}
}

// TODO: waitingFrames should be an array of frames sorted by offset, absent frames should be nil in the array

// Looks in the waitingFECFrames and returns the full payload for the specified FEC group and removes the frames from the waitingFrames if all the frames are present.
// First return value: Returns nil if all the frames for this FEC group are not present in the waitingFrames
// Second return value: the number of packets concerned by this FEC Group if the return symbol has the number 0. Returns -1 otherwise.
// Third return value: the number of repair symbols concerned by this FEC Group if the return symbol has the number 0. Returns -1 otherwise.
func (f *FECFrameworkReceiver) getRepairSymbolForSomeFECGroup(receivedFrame *wire.FECFrame) (*fec.RepairSymbol, int, int) {
	// 定位到group
	fecBlockNumber := receivedFrame.FECBlockNumber
	// 取出waitingframe
	waitingFrames, ok := f.waitingFECFrames[fecBlockNumber]
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
		f.waitingFECFrames[fecBlockNumber] = waitingFrames
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
			delete(f.waitingFECFrames, fecBlockNumber)
			symbol := &fec.RepairSymbol{
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
		f.waitingFECFrames[fecBlockNumber][receivedFrame.RepairSymbolNumber] = nil

		//delete(f.waitingFECFrames[fecBlockNumber], receivedFrame.RepairSymbolNumber)

		var nPackets, nRepairSymbols byte
		if orderedFrames[0] != nil {
			nPackets = orderedFrames[0].NumberOfPackets
			nRepairSymbols = orderedFrames[0].NumberOfRepairSymbols
		}
		return &fec.RepairSymbol{
			FECSchemeSpecific: receivedFrame.FECSchemeSpecific,
			FECBlockNumber:    fecBlockNumber,
			Data:              payloadData,
			SymbolNumber:      receivedFrame.RepairSymbolNumber,
		}, int(nPackets), int(nRepairSymbols)
	}
}

// waitingFrame也是根据FECBlockNumber划分，每个FECBlockNumber对应一个 *[]waitingFrames
// Session=>HandleFECFrame=>putWaitingFrame
func (f *FECFrameworkReceiver) putWaitingFrame(frame *wire.FECFrame) {
	// add frame if not already present
	waitingFrames := f.waitingFECFrames[frame.FECBlockNumber]

	// ensure to have place for this repair symbol
	// 看起来是一个frame对应一个RepairSymbolNumber

	// 补齐
	if len(waitingFrames) <= int(frame.RepairSymbolNumber) {
		delta := int(frame.RepairSymbolNumber) - len(waitingFrames)
		for i := 0; i <= delta; i++ {
			waitingFrames = append(waitingFrames, make(map[protocol.FecFrameOffset]*wire.FECFrame))
		}
		f.waitingFECFrames[frame.FECBlockNumber] = waitingFrames
	}

	waitingFramesForSymbol := waitingFrames[frame.RepairSymbolNumber]
	if _, ok := waitingFramesForSymbol[frame.Offset]; !ok {
		// 定位Group--定位某个Symbol的--定位到具体的Frame
		waitingFramesForSymbol[frame.Offset] = frame
	}
}

type fecGroupsBuffer struct {
	head      *node // FIFO queue which will be used to remove old fecBuffers which has not been normally removed (never used, maybe because of the loss of more than one packet)
	tail      *node
	size      uint
	maxSize   uint
	fecGroups map[protocol.FECBlockNumber]*fec.FECBlock
}

type node struct {
	fecBlockNumber protocol.FECBlockNumber
	next           *node
}

func newFecGroupsBuffer(maxSize uint) *fecGroupsBuffer {
	return &fecGroupsBuffer{
		nil,
		nil,
		0,
		maxSize,
		make(map[protocol.FECBlockNumber]*fec.FECBlock),
	}
}

func (b *fecGroupsBuffer) addFECGroup(group *fec.FECBlock) {
	number := group.FECBlockNumber
	if b.size == b.maxSize {
		toRemove := b.head
		b.head = b.head.next
		delete(b.fecGroups, toRemove.fecBlockNumber)
		b.size--
	}
	newNode := &node{number, nil}
	if b.size == 0 {
		b.tail = newNode
		b.head = newNode
	} else {
		b.tail.next = newNode
		b.tail = newNode
	}
	b.fecGroups[number] = group
	b.size++
}

// TODO: should return true if it has been added, and false if not.
func (b *fecGroupsBuffer) addPacketInFECGroup(packet []byte, header *wire.Header) (err error) {
	group, ok := b.fecGroups[header.FECPayloadID.GetBlockNumber()]
	if ok {
		group.AddPacket(packet, header)
	}
	return
}
