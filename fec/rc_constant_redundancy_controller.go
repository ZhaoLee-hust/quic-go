package fec

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

type constantRedundancyController struct {
	nRepairSymbols     uint
	nDataSymbols       uint
	nInterleavedBlocks uint
	windowStepSize     uint
}

var _ RedundancyController = &constantRedundancyController{}

func NewConstantRedundancyController(nDataSymbols uint, nRepairSymbols uint, nInterleavedBlocks uint, windowStepSize uint) RedundancyController {
	return &constantRedundancyController{
		nDataSymbols:       nDataSymbols,
		nRepairSymbols:     nRepairSymbols,
		nInterleavedBlocks: nInterleavedBlocks,
		windowStepSize:     windowStepSize,
	}
}

func (*constantRedundancyController) OnPacketLost(protocol.PacketNumber) {}

func (*constantRedundancyController) OnPacketReceived(protocol.PacketNumber) {}

func (c *constantRedundancyController) GetNumberOfDataSymbols() uint {
	return c.nDataSymbols
}

func (c *constantRedundancyController) GetNumberOfRepairSymbols() uint {
	return c.nRepairSymbols
}

func (c *constantRedundancyController) GetNumberOfInterleavedBlocks() uint {
	return c.nInterleavedBlocks
}

func (c *constantRedundancyController) GetWindowStepSize() uint {
	return c.windowStepSize
}

func (c *constantRedundancyController) PushParamerters(paras TransParams) {}
