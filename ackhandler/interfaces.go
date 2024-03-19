package ackhandler

import (
	"time"

	"github.com/lucas-clemente/quic-go/congestion"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

// SentPacketHandler handles ACKs received for outgoing packets
type SentPacketHandler interface {
	// SentPacket may modify the packet
	SentPacket(packet *Packet) error
	ReceivedAck(ackFrame *wire.AckFrame, withPacketNumber protocol.PacketNumber, encLevel protocol.EncryptionLevel, recvTime time.Time) error
	ReceivedRecoveredFrame(frame *wire.RecoveredFrame, encLevel protocol.EncryptionLevel) error
	SetHandshakeComplete()

	// Specific to multipath operation
	SetInflightAsLost()

	SendingAllowed() bool
	GetStopWaitingFrame(force bool) *wire.StopWaitingFrame
	ShouldSendRetransmittablePacket() bool
	DequeuePacketForRetransmission() (packet *Packet)
	GetLeastUnacked() protocol.PacketNumber

	GetAlarmTimeout() time.Time
	OnAlarm()

	DuplicatePacket(packet *Packet)

	ComputeRTOTimeout() time.Duration

	GetStatistics() (uint64, uint64, uint64)

	GetBytesInFlight() protocol.ByteCount
	GetPacketsInFlight() []*Packet
	GetSendAlgorithm() congestion.SendAlgorithm

	// add by zhaolee
	ReceiveSymbolAck(*wire.SymbolAckFrame, uint64)
	HandleRDFrame(*wire.RDFrame)
	// GetNumberOfRepairSymbols() uint64
	GetAckedSymbols() uint64
	GetthresholdStatistic() ([]map[uint64][2]float64, []map[uint64][2]uint64, []map[uint64][2]uint64)
}

// ReceivedPacketHandler handles ACKs needed to send for incoming packets
type ReceivedPacketHandler interface {
	// change by zhaolee, add the whole packets for reorder detection!
	ReceivedPacket(packetNumber protocol.PacketNumber, shouldInstigateAck bool, recovered bool) error
	// ReceivedPacket(packetNumber protocol.PacketNumber, shouldInstigateAck bool, recovered bool, pkt *ReceivedPacket) error
	SetLowerLimit(protocol.PacketNumber)

	GetAlarmTimeout() time.Time
	GetAckFrame() *wire.AckFrame
	GetRecoveredFrame() *wire.RecoveredFrame

	GetStatistics() (uint64, uint64)
	SentRecoveredFrame(f *wire.RecoveredFrame)
}
