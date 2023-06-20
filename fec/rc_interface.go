package fec

import "github.com/lucas-clemente/quic-go/internal/protocol"

// a class that implemented this interface is a redundancy controller
type RedundancyController interface {
	// is called whenever a packet is lost
	OnPacketLost(protocol.PacketNumber)
	// is called whenever a packet is received
	OnPacketReceived(protocol.PacketNumber)
	// returns the number of data symbols that should compose a single FEC Group
	GetNumberOfDataSymbols() uint
	// returns the maximum number of repair symbols that should be generated for a single FEC Group
	GetNumberOfRepairSymbols() uint
	// returns the number of blocks that must be interleaved for block FEC Schemes
	// 对应Scheduler的size
	GetNumberOfInterleavedBlocks() uint
	// returns the window step size for convolutional FEC Schemes
	GetWindowStepSize() uint

	// added by zhaolee
	PushParamerters(TransParams)
}
