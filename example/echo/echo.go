package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/fec"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

const addr = "localhost:4242"

const message = "foobar"

// add quic.Config
var fs quic.FECSchemeID
var NUMBER_OF_SOURCE_SYMBOLS uint = 20
var NUMBER_OF_REPAIR_SYMBOLS uint = 10
var NUMBER_OF_INTERLEAVED_BLOCKS uint = 1
var DISABLE_RECOVERED_FRAMES bool = true
var USE_FEC bool = true
var RS_WHEN_APPLICATION_LIMITED = false

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func main() {
	// add quic.Config
	// cp := flag.String("certpath", getBuildDir(), "certificate directory")
	multipath := flag.Bool("m", false, "multipath")
	fecSchemeFlag := flag.String("fecScheme", "rs", "rs, rlc or xor")
	nifg := flag.Uint("nifg", NUMBER_OF_INTERLEAVED_BLOCKS, "Set to 1 (recommended) when no block interleaving is needed. Specifies the number of FEC blocks to interleave to handle loss bursts for weak codes such as XOR. (max. 255)")
	nss := flag.Uint("nss", NUMBER_OF_SOURCE_SYMBOLS, "Default number of Source Symbols (max. 255)")
	nrs := flag.Uint("nrs", NUMBER_OF_REPAIR_SYMBOLS, "Default number of Repair Symbols (max. 255)")
	norf := flag.Bool("no-rf", false, "Use this flag to prevent the receiver from sending recovered frames")
	cache := flag.Bool("c", false, "cache handshake information")

	NUMBER_OF_SOURCE_SYMBOLS = *nss
	NUMBER_OF_REPAIR_SYMBOLS = *nrs
	NUMBER_OF_INTERLEAVED_BLOCKS = *nifg
	DISABLE_RECOVERED_FRAMES = *norf

	// certPath = *cp

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

	go func() { log.Fatal(echoServer(quicConfig)) }()

	err := clientMain(quicConfig)
	if err != nil {
		panic(err)
	}
}

// Start a server that echos all data on the first stream opened by the client
func echoServer(quicConfig *quic.Config) error {
	listener, err := quic.ListenAddr(addr, generateTLSConfig(), quicConfig)
	if err != nil {
		return err
	}
	sess, err := listener.Accept()
	if err != nil {
		return err
	}
	stream, err := sess.AcceptStream()
	if err != nil {
		panic(err)
	}
	// Echo through the loggingWriter
	_, err = io.Copy(loggingWriter{stream}, stream)
	return err
}

func clientMain(quicConfig *quic.Config) error {
	session, err := quic.DialAddr(addr, &tls.Config{InsecureSkipVerify: true}, quicConfig)
	if err != nil {
		return err
	}

	stream, err := session.OpenStreamSync()
	if err != nil {
		return err
	}

	fmt.Printf("Client: Sending '%s'\n", message)
	_, err = stream.Write([]byte(message))
	if err != nil {
		return err
	}

	buf := make([]byte, len(message))
	_, err = io.ReadFull(stream, buf)
	if err != nil {
		return err
	}
	fmt.Printf("Client: Got '%s'\n", buf)

	return nil
}

// A wrapper for io.Writer that also logs the message.
type loggingWriter struct{ io.Writer }

func (w loggingWriter) Write(b []byte) (int, error) {
	fmt.Printf("Server: Got '%s'\n", string(b))
	return w.Writer.Write(b)
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
