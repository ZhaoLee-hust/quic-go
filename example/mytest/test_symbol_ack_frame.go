package main

import (
	"bytes"
	"log"
	_ "net/http/pprof"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

// var bufferPool sync.Pool

func main() {
	SymbolAckFrame := &wire.SymbolAckFrame{SymbolReceived: 1 << 8}
	log.Printf("SymbolAckFrame: %v", SymbolAckFrame.SymbolReceived)
	// raw := bufferPool.Get().([]byte)
	raw := make([]byte, 0, 1024)
	// log.Println(raw)
	buffer := bytes.NewBuffer(raw)
	err := SymbolAckFrame.Write(buffer, protocol.VersionMP)
	if err != nil {
		log.Print("write err: ", err)
	}
	raw = raw[0:buffer.Len()]
	log.Println("raw:", raw)

	r := bytes.NewReader(raw)
	typeByte, _ := r.ReadByte()
	if typeByte != 0x13 {
		log.Print("Invalid typebyte.")
	}
	r.UnreadByte()
	log.Printf("DECODE SymBolAckFrame")
	frame, _ := wire.ParseSymbolAckFrame(r, protocol.VersionMP)

	log.Print("Frame:", frame)
	log.Print(frame.SymbolReceived)

}
