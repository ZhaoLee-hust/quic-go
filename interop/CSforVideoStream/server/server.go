package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/fec"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

// CHUNK size to read
const CHUNK = 1024 * 10

var fs quic.FECSchemeID
var NUMBER_OF_SOURCE_SYMBOLS uint = 20
var NUMBER_OF_REPAIR_SYMBOLS uint = 10
var NUMBER_OF_INTERLEAVED_BLOCKS uint = 1
var DISABLE_RECOVERED_FRAMES bool = true
var USE_FEC bool = true
var RS_WHEN_APPLICATION_LIMITED = false

func main() {
	multipath := flag.Bool("m", false, "multipath")
	fecSchemeFlag := flag.String("fecScheme", "rs", "rs, rlc or xor")
	nifg := flag.Uint("nifg", NUMBER_OF_INTERLEAVED_BLOCKS, "Set to 1 (recommended) when no block interleaving is needed. Specifies the number of FEC blocks to interleave to handle loss bursts for weak codes such as XOR. (max. 255)")
	nss := flag.Uint("nss", NUMBER_OF_SOURCE_SYMBOLS, "Default number of Source Symbols (max. 255)")
	nrs := flag.Uint("nrs", NUMBER_OF_REPAIR_SYMBOLS, "Default number of Repair Symbols (max. 255)")
	norf := flag.Bool("no-rf", false, "Use this flag to prevent the receiver from sending recovered frames")
	cache := flag.Bool("c", true, "cache handshake information")

	NUMBER_OF_SOURCE_SYMBOLS = *nss
	NUMBER_OF_REPAIR_SYMBOLS = *nrs
	NUMBER_OF_INTERLEAVED_BLOCKS = *nifg
	DISABLE_RECOVERED_FRAMES = *norf

	var fecSchemeArg string = *fecSchemeFlag
	if fecSchemeArg == "rs" {
		fs = quic.ReedSolomonFECScheme
		log.Printf("RS")
	} else if fecSchemeArg == "xor" {
		fs = quic.XORFECScheme
		NUMBER_OF_INTERLEAVED_BLOCKS = NUMBER_OF_REPAIR_SYMBOLS
		NUMBER_OF_SOURCE_SYMBOLS /= NUMBER_OF_REPAIR_SYMBOLS
		NUMBER_OF_REPAIR_SYMBOLS = 1
		log.Printf("XOR")
	} else {
		fs = quic.RLCFECScheme
		log.Printf("RLC")
	}

	var maxPathID uint8
	if *multipath {
		// Two path topology
		maxPathID = 2
	}

	rr := fec.NewConstantRedundancyController(
		NUMBER_OF_SOURCE_SYMBOLS,             //20 source code
		NUMBER_OF_REPAIR_SYMBOLS,             //10 repair code
		NUMBER_OF_INTERLEAVED_BLOCKS,         //1 interleaved blocks
		uint(protocol.ConvolutionalStepSize)) //6

	quicConfig := &quic.Config{
		CacheHandshake:                    *cache,
		MaxPathID:                         maxPathID,
		FECScheme:                         fs,
		RedundancyController:              rr,
		DisableFECRecoveredFrames:         DISABLE_RECOVERED_FRAMES,
		ProtectReliableStreamFrames:       USE_FEC,
		UseFastRetransmit:                 true,
		OnlySendFECWhenApplicationLimited: RS_WHEN_APPLICATION_LIMITED,
		// Versions:             []quic.VersionNumber{version},

	}

	addr := "localhost:8000"
	server(addr, quicConfig)
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func server(addr string, quicConfig *quic.Config) {
	// Configure multipath
	// quicConfig := &quic.Config{
	// 	CreatePaths: true,
	// }

	listener, err := quic.ListenAddr(addr, generateTLSConfig(), quicConfig)
	check(err)

	// Listen forever
	for {
		sess, err := listener.Accept()
		check(err)
		fmt.Println("Accepted connection")
		go handleClient(sess)
	}
}

func handleClient(sess quic.Session) {
	stream, err := sess.AcceptStream()
	check(err)
	defer stream.Close()

	cmd := readMessage(stream)
	if cmd != "SETUP" {
		return
	}
	fmt.Println("Received SETUP request...")
	sendMessage("OK", stream)
	filename := readMessage(stream)
	fmt.Println("Filename:", filename)
	f, err := os.Open("/var/www/" + filename)
	check(err)
	defer f.Close()

	r := bufio.NewReader(f)
	_, err = io.Copy(stream, r)
	if err != nil {
		fmt.Println("Client disconnected...")
	}
	fmt.Println("Exited...")
}

func sendMessage(msg string, stream quic.Stream) {
	l := uint32(len(msg))
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, l)
	stream.Write(data)
	stream.Write([]byte(msg))
}

func readMessage(stream quic.Stream) string {
	data := make([]byte, 4)
	stream.Read(data)
	l := binary.LittleEndian.Uint32(data)
	data = make([]byte, l)
	stream.Read(data)
	return string(data)
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{tlsCert}}
}
