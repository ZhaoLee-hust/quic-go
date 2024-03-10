package wire

import (
	"bytes"
	"errors"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

var RDFrameTypeByte byte = 0x14

// An SymbolAckFrame is an ACK frame in QUIC
type RDFrame struct {
	// We just need one parameter to show how many symbols have been accepted.
	TimeThresholdMS uint16
	PacketThreshold uint16
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
	typeByte := RDFrameTypeByte
	b.WriteByte(typeByte)
	utils.GetByteOrder(version).WriteUint16(b, rd.TimeThresholdMS)
	utils.GetByteOrder(version).WriteUint16(b, rd.PacketThreshold)
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

	timeT, _ := utils.GetByteOrder(version).ReadUint16(r)
	frame.TimeThresholdMS = timeT

	packetT, _ := utils.GetByteOrder(version).ReadUint16(r)
	frame.PacketThreshold = packetT

	return frame, nil
}
