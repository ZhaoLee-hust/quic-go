package fec

import "github.com/lucas-clemente/quic-go/internal/wire"

type SymbolBlockTracker interface {
	GetSymbolACKFrame() *wire.SymbolAckFrame
	ReceivedNewFECFrame(frame *wire.FECFrame)
}
