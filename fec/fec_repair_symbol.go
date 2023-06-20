package fec

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

type RepairSymbol struct {
	// 前两个都在Frame里面有指示
	FECSchemeSpecific uint32
	FECBlockNumber    protocol.FECBlockNumber
	SymbolNumber      byte
	Data              []byte // TODO: Maybe put this attr private, and do a GetData() method: some ECC may not be done incrementally but all at once, so random access should be prohibited

	NumberOfPackets       uint8
	NumberOfRepairSymbols uint8
	Convolutional         bool

	// 用于RLC
	EncodingSymbolID protocol.FECEncodingSymbolID
}
