package main

import (
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/fec"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
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

	verbose := flag.Bool("v", false, "verbose")
	multipath := flag.Bool("m", false, "multipath")
	output := flag.String("o", "", "logging output")
	cache := flag.Bool("c", false, "cache handshake information")
	fecSchemeFlag := flag.String("fecScheme", "rs", "rs, rlc or xor")
	flag.Parse()

	// urls := flag.Args()
	// urls := addr

	if *verbose {
		utils.SetLogLevel(utils.LogLevelDebug)
	} else {
		utils.SetLogLevel(utils.LogLevelInfo)
	}

	if *output != "" {
		logfile, err := os.Create(*output)
		if err != nil {
			panic(err)
		}
		defer logfile.Close()
		log.SetOutput(logfile)
	}

	var maxPathID uint8
	if *multipath {
		// Two path topology
		maxPathID = 2
	}

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
	}

	// hclient := &http.Client{
	// 	Transport: &h2quic.RoundTripper{QuicConfig: quicConfig, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	// }

	addr := "localhost:8000"
	filename := "test.mp4"
	client(addr, filename, quicConfig)
}

func check(err error) {
	if err != nil {
		// fmt.Println(err)
		panic(err)
	}
}

func client(addr string, filename string, quicConfig *quic.Config) {
	// create a new client
	// connect to server
	session, err := quic.DialAddr(addr, &tls.Config{InsecureSkipVerify: true}, quicConfig)
	// session, err := quic.DialAddr(addr, generateTLSConfig(), quicConfig)
	check(err)
	stream, err := session.OpenStreamSync()

	if err != nil {
		log.Printf("Error: %s", err)
		return
	}

	defer stream.Close()

	// initiate SETUP
	sendMessage("SETUP", stream)

	// send filename
	sendMessage(filename, stream)

	// get reponse
	msg := readMessage(stream)
	if msg != "OK" {
		return
	}

	// start ffmpeg
	ffmpeg := exec.Command("ffplay", "-f", "mp4", "-i", "pipe:")
	inpipe, err := ffmpeg.StdinPipe()
	check(err)
	err = ffmpeg.Start()
	check(err)

	// write
	_, err = io.Copy(inpipe, stream)
	fmt.Println("Playing Vedio")
	if err != nil {
		fmt.Println("Stream closed...")
	}
	fmt.Println("Exited...")
	ffmpeg.Wait()
}

func sendMessage(msg string, stream quic.Stream) {
	// utility for sending control messages
	l := uint32(len(msg))
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, l)
	stream.Write(data)
	stream.Write([]byte(msg))
}

func readMessage(stream quic.Stream) string {
	// utility for receiving control messages
	data := make([]byte, 4)
	stream.Read(data)
	l := binary.LittleEndian.Uint32(data)
	data = make([]byte, l)
	stream.Read(data)
	return string(data)
}

// Setup a bare-bones TLS config for the server
// ....
// func generateTLSConfig() *tls.Config {
// 	key, err := rsa.GenerateKey(rand.Reader, 1024)
// 	if err != nil {
// 		panic(err)
// 	}
// 	template := x509.Certificate{SerialNumber: big.NewInt(1)}
// 	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
// 	if err != nil {
// 		panic(err)
// 	}
// 	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
// 	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

// 	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
// 	if err != nil {
// 		panic(err)
// 	}
// 	return &tls.Config{Certificates: []tls.Certificate{tlsCert}}
// }
