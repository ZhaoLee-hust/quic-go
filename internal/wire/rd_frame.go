package wire

import (
	"bytes"
	"errors"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

var RDFrameTypeByte byte = 0x14

// An RDFrame is a Reorder Detection Frame in QUIC
type RDFrame struct {
	// dPn
	MaxDisPlacement uint16
	// dTn, ms
	MaxDelay uint16
}

var _ Frame = &RDFrame{}

var (
	errInvalidRDTypeByte = errors.New("Invalid RDFrame bytetype")
)

func (rd *RDFrame) MinLength(version protocol.VersionNumber) (protocol.ByteCount, error) {
	//FrameTypeByte + AckTypeByte + SymbolCountLength + SymbolCount
	return 5, nil
}

func (rd *RDFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	//Write TypeByte
	b.WriteByte(RDFrameTypeByte)
	utils.GetByteOrder(version).WriteUint16(b, rd.MaxDisPlacement)
	utils.GetByteOrder(version).WriteUint16(b, rd.MaxDelay)
	return nil
}

func ParseRDFrame(r *bytes.Reader, version protocol.VersionNumber) (*RDFrame, error) {
	frame := &RDFrame{}

	typeByte, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	if typeByte != RDFrameTypeByte {
		return nil, errInvalidRDTypeByte
	}

	dPn, _ := utils.GetByteOrder(version).ReadUint16(r)
	frame.MaxDisPlacement = dPn

	dTn, _ := utils.GetByteOrder(version).ReadUint16(r)
	frame.MaxDelay = dTn

	return frame, nil
}
