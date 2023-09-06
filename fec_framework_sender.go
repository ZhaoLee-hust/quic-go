package quic

import (
	"errors"
	"log"

	"github.com/lucas-clemente/quic-go/fec"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

/**
 *	Receives payloads for a block (FEC Group) and gives it to the FEC scheme. FEC scheme returns :
 * 		- One or more FEC Repair packet payloads
 * 		- FEC Payload IDs for the FEC Repair packet payloads (in a same group, these IDs will be the FEC Group ?)
 *  Then, the FEC Framework adds the FEC Group to the ADUs (quic packets) and returns it. Then, it stores FEC repair
 * 	payloads with their FEC Payload ID (FEC Group) to then construct FEC Frames.
 */

//		+----------------------+
//		|     Application      |
//		+----------------------+
//		|
//		|(1) ADUs
//		|
//		v
//		+----------------------+                           +----------------+
//		|    FEC Framework     |                           |                |
//		|                      |-------------------------->|   FEC Scheme   |
//		|(2) Construct source  |(3) Source Block           |                |
//		|    blocks            |                           |(4) FEC Encoding|
//		|(6) Construct FEC     |<--------------------------|                |
//		|    source packets and|                           |                |
//		|    repair payloads   |(5) Repair FEC Payload ID  |                |
//		+----------------------+    Repair symbols         +----------------+
//		|             |
//		|             |
//		|             |
//		|(7) Source   |(7') Repair payloads (FEC Frames)
//		|    packets  |
//		|             |
//		|      + -- -- -- -- -+
//		|      |     QUIC     |
//		|      +-- -- -- -- --+
//		v             v
//		+----------------------+
//		|   Transport Layer    |
//		|     (e.g., UDP)      |
//		+----------------------+

//  	Figure 3: Sender Operation with QUIC FEC Framework

// 核心是用Framer发送(push)；用Container装载，Container的实例有window和group；用Scheduler标注已经发送。因为Scheduler不考虑RLC，因此单独定义window
type FECFrameworkSender struct {
	fecScheme            fec.FECScheme
	fecScheduler         fec.FECScheduler
	fecFramer            *FECFramer
	redundancyController fec.RedundancyController

	nextEncodingSymbolID protocol.FECEncodingSymbolID
	fecWindow            *fec.FECWindow
	sess                 *session
	// add by zhaolee
	// 统计发送的全部Symbol个数
	numberOfSymbols uint64
	// 统计被确认的Symbol个数,总数
	numberOfSymbolsAcked uint64
}

var FECFrameworkSenderPacketHandledWithWrongFECGroup = errors.New("FECFrameworkSender: A packet with the wrong FEC Group Number has been added")

func (f *FECFrameworkSender) handleSymbolACKFrame(frame *wire.SymbolAckFrame) {
	utils.Debugf("Acked Symbol: %d", frame.SymbolReceived)
	// f.
	f.numberOfSymbolsAcked = uint64(frame.SymbolReceived)
	symbolLossRate := float64(f.numberOfSymbols-f.numberOfSymbolsAcked) / float64(f.numberOfSymbols)
	log.Printf("Dynamic Symbol Sent: %d, ACKed: %d, LossRate: %f", f.numberOfSymbols, f.numberOfSymbolsAcked, symbolLossRate)
}

// TODO define a window size and a spacing
// TODO: define convolutional design in FEC frames
func NewFECFrameworkSender(fecScheme fec.FECScheme, fecScheduler fec.FECScheduler, fecFramer *FECFramer, redundancyController fec.RedundancyController, version protocol.VersionNumber, session *session) *FECFrameworkSender {
	window := fec.NewFECWindow(uint8(redundancyController.GetNumberOfDataSymbols()), version)

	return &FECFrameworkSender{
		fecScheme:            fecScheme,
		fecScheduler:         fecScheduler,
		fecFramer:            fecFramer,
		redundancyController: redundancyController,
		nextEncodingSymbolID: 1,
		fecWindow:            window,
		sess:                 session,
	}
}

// 取出下一个fecContainer并将packet添加进去；
// 如果是FECScheme是ConvolutionalFECScheme则Container是FECWindow；
// 否则是FECGroup
func (f *FECFrameworkSender) HandlePacket(packet []byte, hdr *wire.Header) {

	hdr.FECPayloadID = f.GetNextSourceFECPayloadID()

	var fecContainer fec.FECContainer
	if _, ok := f.fecScheme.(fec.ConvolutionalFECScheme); ok {
		fecContainer = f.fecWindow
	} else {
		fecContainer = f.fecScheduler.GetNextFECGroup()
	}

	switch fc := fecContainer.(type) {
	case *fec.FECWindow:
		if uint(fc.WindowSize) != f.redundancyController.GetNumberOfDataSymbols() {
			fc.SetSize(int(f.redundancyController.GetNumberOfDataSymbols()))
		}
	}

	fecContainer.AddPacket(packet, hdr)
	f.nextEncodingSymbolID++
}

// handles this packet for Forward Error Correction.
// Returns the packet as it should be sent
// TODO: the framework should receive a packet without a valid FEC Group and should insert it itself.
func (f *FECFrameworkSender) HandlePacketAndMaybePushRS(packet []byte, hdr *wire.Header) ([]byte, error) {
	//TODO: decide if we here assume that the packet already has the correct header, fecGroupNumber or not
	//if hdr.FECPayloadID != f.GetNextSourceFECPayloadID() {
	//	log.Printf("%d VS %d", hdr.FECPayloadID, f.GetNextSourceFECPayloadID())
	//	return nil, FECFrameworkSenderPacketHandledWithWrongFECGroup
	//}

	f.HandlePacket(packet, hdr)

	// TODO: remove these ugly ifs

	// mainly for rQUIC
	// wairning: we don't consider multipath, so the path number is default in protocol.InitialPathID(0)
	smoothedRTT := f.sess.paths[protocol.InitialPathID].rttStats.SmoothedRTT()
	sntPkts, sntRetrans, sntLost := f.sess.paths[protocol.InitialPathID].sentPacketHandler.GetStatistics()
	rcvPkts, recoveredPkts := f.sess.paths[protocol.InitialPathID].receivedPacketHandler.GetStatistics()
	f.redundancyController.PushParamerters(fec.TransParams{
		SntPkts:       sntPkts,
		SntRetrans:    sntRetrans,
		SntLost:       sntLost,
		RcvPkts:       rcvPkts,
		RecoveredPkts: recoveredPkts,
		SmoothedRTT:   smoothedRTT,
	})
	// end

	var fecContainer fec.FECContainer
	if _, ok := f.fecScheme.(fec.ConvolutionalFECScheme); ok {
		fecContainer = f.fecWindow
	} else {
		fecContainer = f.fecScheduler.GetNextFECGroup()
	}

	if fecContainer.ShouldBeSent(f.redundancyController) {
		if _, ok := f.fecScheme.(fec.ConvolutionalFECScheme); ok {

		} else {
			fecGroup := fecContainer.(*fec.FECBlock)
			fecGroup.TotalNumberOfPackets = fecContainer.CurrentNumberOfPackets()
			defer f.fecScheduler.SentFECBlock(fecGroup.FECBlockNumber)
		}
		// 测试编码时间
		// start := time.Now()
		f.GenerateRepairSymbols(fecContainer, f.redundancyController.GetNumberOfRepairSymbols(), hdr.FECPayloadID)
		// elapsed := time.Since(start)
		// utils.Infof(fmt.Sprintf("encode time: %s", elapsed))
		// log.Printf("encode time: %s,encode length: %d", elapsed, len(fecContainer.GetPackets()))
		// log.Printf("rc souce: %d, rc repair: %d", f.redundancyController.GetNumberOfDataSymbols(), f.redundancyController.GetNumberOfRepairSymbols())

		// 最后检查，并更新所有packet的NRS和NSS
		fecContainer.PrepareToSend() // will never error thanks to the ShouldBeSent check
		symbols := fecContainer.GetRepairSymbols()
		f.fecFramer.pushRepairSymbols(symbols)
		f.numberOfSymbols += uint64(len(symbols))
		utils.Debugf("numberOfSymbols has been sent: %d", f.numberOfSymbols)
	}

	// if f.redundancyController.GetNumberOfDataSymbols()

	return packet, nil
}

func (f *FECFrameworkSender) PushRemainingFrames() error {
	rs, err := f.GetRepairSymbols(f.redundancyController.GetNumberOfRepairSymbols())
	if err != nil {
		return err
	}
	f.fecFramer.pushRepairSymbols(rs)
	return nil
}

func (f *FECFrameworkSender) GetRepairSymbols(numberOfRepairSymbols uint) ([]*fec.RepairSymbol, error) {

	if _, ok := f.fecScheme.(fec.ConvolutionalFECScheme); ok {
		fw := f.fecWindow
		if fw.HasSomethingToSend() {
			rs, err := fec.FlushCurrentSymbols(f.fecScheme, fw, numberOfRepairSymbols)
			if err != nil {
				log.Printf("RLC PUSH ERROR %+v", err)
				return nil, err
			}
			fw.SetRepairSymbols(rs)
			fw.PrepareToSend()
			return rs, nil
		}

	} else if _, ok := f.fecScheme.(fec.BlockFECScheme); ok {
		for group := f.fecScheduler.GetNextFECGroup(); group.CurrentNumberOfPackets() > 0; group = f.fecScheduler.GetNextFECGroup() {
			rs, err := fec.FlushCurrentSymbols(f.fecScheme, group, uint(utils.MinUint64(uint64(numberOfRepairSymbols), uint64(f.redundancyController.GetNumberOfRepairSymbols()))))
			if err != nil {
				return nil, err
			}
			group.SetRepairSymbols(rs)
			// Scheduler删除该Block
			f.fecScheduler.SentFECBlock(group.FECBlockNumber)
			return rs, nil
		}
	}
	return nil, nil
}

func (f *FECFrameworkSender) GetNextSourceFECPayloadID() protocol.FECPayloadID {
	if _, ok := f.fecScheme.(fec.ConvolutionalFECScheme); ok {
		return protocol.NewConvolutionalSourceFECPayloadID(f.nextEncodingSymbolID)
	} else {
		return protocol.NewBlockSourceFECPayloadID(f.fecScheduler.GetNextFECBlockNumber(), f.fecScheduler.GetNextFECGroupOffset())
	}
}

func (f *FECFrameworkSender) GenerateRepairSymbols(container fec.FECContainer, numberOfSymbols uint, id protocol.FECPayloadID) error {
	var symbols []*fec.RepairSymbol
	var err error
	if fs, ok := f.fecScheme.(fec.ConvolutionalFECScheme); ok {
		symbols, err = fs.GetRepairSymbols(container, numberOfSymbols, id.GetConvolutionalEncodingSymbolID())

	} else {
		symbols, err = f.fecScheme.(fec.BlockFECScheme).GetRepairSymbols(container, numberOfSymbols, id.GetBlockNumber())
	}
	if err != nil {
		return err
	}
	container.SetRepairSymbols(symbols)
	return nil
}
