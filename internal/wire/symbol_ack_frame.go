package wire

import (
	"bytes"
	"errors"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

var (
	// ErrInvalidAckRanges occurs when a client sends inconsistent ACK ranges
	ErrInvalidSymbolAckRanges = errors.New("SymbolFrame: Symbol frame contains invalid Symbol ranges")
	// ErrInvalidFirstAckRange occurs when the first ACK range contains no packets
	ErrInvalidFirstSymbolAckRange = errors.New("SymbolFrame: Symbol frame has invalid first Symbol range")
)

var (
	errInconsistentLargestSymbolAck = errors.New("internal inconsistency: LargestSymbol does not match Symbol ranges")
	errInconsistentLowestSymbolAck  = errors.New("internal inconsistency: LowestSymbol does not match Symbol ranges")
	errInvalidTypeByte              = errors.New("Invalid SymBolACKFrame bytetype")
)

type SymbolAckRange AckRange

var SymbolAckFrameTypeByte byte = 0x13

// An SymbolAckFrame is an ACK frame in QUIC
type SymbolAckFrame struct {
	// We just need one parameter to show how many symbols have been accepted.
	SymbolReceived protocol.NumberOfAckedSymbol
	// 另一个参数写最大确认号
	MaxSymbolReceived protocol.SymbolNumber
}

var _ Frame = &SymbolAckFrame{}

func (s *SymbolAckFrame) MinLength(version protocol.VersionNumber) (protocol.ByteCount, error) {
	// TODO: Consider the version deviation
	//FrameTypeByte + AckTypeByte + SymbolCountLength + SymbolCount
	minLength := protocol.ByteCount(2) // typeBytes
	minLength += protocol.ByteCount(1)
	largestAckedLen := protocol.GetPacketNumberLength(protocol.PacketNumber(s.SymbolReceived))
	// 第二个参数长度
	MaxSymbolReceivedLen := protocol.GetPacketNumberLength(protocol.PacketNumber(s.MaxSymbolReceived))
	minLength += protocol.ByteCount(largestAckedLen) + protocol.ByteCount(MaxSymbolReceivedLen)

	return minLength, nil
}

func (s *SymbolAckFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	//Write TypeByte
	typeByte := uint8(0x13)
	b.WriteByte(typeByte)

	// write ACK typeByte
	ACKtypeByte := uint8(0x40)
	b.WriteByte(ACKtypeByte)

	// only in 1,2,4,6
	largestAckedLen := protocol.GetPacketNumberLength(protocol.PacketNumber(s.SymbolReceived))
	b.WriteByte(byte(largestAckedLen))
	numOfSymbolsToBeAcked := s.SymbolReceived

	//
	// 根据largestAckedLen即D2-D3决定接下来的几个字节，最多6个字节
	// 用于存放最大确认pn的位数，1 2 4 6分别对应1246字节，也表示最大确认pn的位数需要这么多字节才能放得下
	// 1表示pn不超过255，2表示不超过1024，4表示不超过4096
	// 接下来写最大ACK
	switch largestAckedLen {
	case protocol.PacketNumberLen1:
		b.WriteByte(uint8(numOfSymbolsToBeAcked))
	case protocol.PacketNumberLen2:
		utils.GetByteOrder(version).WriteUint16(b, uint16(numOfSymbolsToBeAcked))
	case protocol.PacketNumberLen4:
		utils.GetByteOrder(version).WriteUint32(b, uint32(numOfSymbolsToBeAcked))
	case protocol.PacketNumberLen6:
		// 清零最高16位
		utils.GetByteOrder(version).WriteUint48(b, uint64(numOfSymbolsToBeAcked)&(1<<48-1))
	}

	// 写第二个参数
	// only in 1,2,4,6
	MaxSymbolReceivedLen := protocol.GetPacketNumberLength(protocol.PacketNumber(s.MaxSymbolReceived))
	b.WriteByte(byte(MaxSymbolReceivedLen))
	maxSymbolReceived := s.MaxSymbolReceived

	//
	// 根据largestAckedLen即D2-D3决定接下来的几个字节，最多6个字节
	// 用于存放最大确认pn的位数，1 2 4 6分别对应1246字节，也表示最大确认pn的位数需要这么多字节才能放得下
	// 1表示pn不超过255，2表示不超过1024，4表示不超过4096
	// 接下来写最大ACK
	switch MaxSymbolReceivedLen {
	case protocol.PacketNumberLen1:
		b.WriteByte(uint8(maxSymbolReceived))
	case protocol.PacketNumberLen2:
		utils.GetByteOrder(version).WriteUint16(b, uint16(maxSymbolReceived))
	case protocol.PacketNumberLen4:
		utils.GetByteOrder(version).WriteUint32(b, uint32(maxSymbolReceived))
	case protocol.PacketNumberLen6:
		// 清零最高16位
		utils.GetByteOrder(version).WriteUint48(b, uint64(maxSymbolReceived)&(1<<48-1))
	}

	return nil
}

func ParseSymbolAckFrame(r *bytes.Reader, version protocol.VersionNumber) (*SymbolAckFrame, error) {
	frame := &SymbolAckFrame{}

	typeByte, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	if typeByte != SymbolAckFrameTypeByte {
		return nil, errInvalidTypeByte
	}

	// this should be an ackTypeByte, we don't consider it temporarily.
	_, err = r.ReadByte()
	if err != nil {
		return nil, err
	}

	// 解析第一个参数
	lenOfSymbolsToBeAcked, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	var numOfSymbolsToBeAcked uint64
	switch protocol.PacketNumberLen(lenOfSymbolsToBeAcked) {
	case protocol.PacketNumberLen1:
		res, _ := r.ReadByte()
		numOfSymbolsToBeAcked = uint64(res)
	case protocol.PacketNumberLen2:
		res, _ := utils.GetByteOrder(version).ReadUint16(r)
		numOfSymbolsToBeAcked = uint64(res)
	case protocol.PacketNumberLen4:
		res, _ := utils.GetByteOrder(version).ReadUint32(r)
		numOfSymbolsToBeAcked = uint64(res)
	case protocol.PacketNumberLen6:
		numOfSymbolsToBeAcked, _ = utils.GetByteOrder(version).ReadUintN(r, 6)
	}

	frame.SymbolReceived = protocol.NumberOfAckedSymbol(numOfSymbolsToBeAcked)

	// 解析第二个参数
	MaxSymbolReceivedLen, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	var MaxSymbolReceived uint64
	switch protocol.PacketNumberLen(MaxSymbolReceivedLen) {
	case protocol.PacketNumberLen1:
		res, _ := r.ReadByte()
		MaxSymbolReceived = uint64(res)
	case protocol.PacketNumberLen2:
		res, _ := utils.GetByteOrder(version).ReadUint16(r)
		MaxSymbolReceived = uint64(res)
	case protocol.PacketNumberLen4:
		res, _ := utils.GetByteOrder(version).ReadUint32(r)
		MaxSymbolReceived = uint64(res)
	case protocol.PacketNumberLen6:
		MaxSymbolReceived, _ = utils.GetByteOrder(version).ReadUintN(r, 6)
	}

	frame.MaxSymbolReceived = protocol.SymbolNumber(MaxSymbolReceived)

	return frame, nil

}
