package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path"
	"runtime"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/fec"
	"github.com/lucas-clemente/quic-go/h2quic"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

var certPath string

var fs quic.FECSchemeID
var NUMBER_OF_SOURCE_SYMBOLS uint = 15 //number of source symbol
var NUMBER_OF_REPAIR_SYMBOLS uint = 3  //number of repair symbol

// changed from (20,10) to (10,3)
var NUMBER_OF_INTERLEAVED_BLOCKS uint = 1 //interlearved blocks, used in RLC
var DISABLE_RECOVERED_FRAMES bool = false //disble recover frames

var RS_WHEN_APPLICATION_LIMITED = false

func getBuildDir() string {
	_, filename, _, ok := runtime.Caller(0)
	//runtime.Caller(skip)
	//pc,file,line,ok := runtime.Caller(skip)
	//skip为0时表示当前文件
	if !ok {
		panic("Failed to get current frame")
	}
	return path.Dir(filename)
} //返回当前工作文件夹目录

func main() {
	// defer profile.Start().Stop()
	// fmt.Println("Running as a fileserver.")
	cp := flag.String("certpath", getBuildDir(), "certificate directory")
	multipath := flag.Bool("m", false, "multipath")
	fsFlag := flag.String("fs", "rs", "rs, rlc or xor")
	nifg := flag.Uint("nifg", NUMBER_OF_INTERLEAVED_BLOCKS, "Set to 1 (recommended) when no block interleaving is needed. Specifies the number of FEC blocks to interleave to handle loss bursts for weak codes such as XOR. (max. 255)")
	nss := flag.Uint("nss", NUMBER_OF_SOURCE_SYMBOLS, "Default number of Source Symbols (max. 255)")
	nrs := flag.Uint("nrs", NUMBER_OF_REPAIR_SYMBOLS, "Default number of Repair Symbols (max. 255)")
	norf := flag.Bool("no-rf", false, "Use this flag to prevent the receiver from sending recovered frames")
	cache := flag.Bool("c", false, "cache handshake information")
	port := flag.String("port", "6121", "The port will listen on")
	output := flag.String("o", "", "logging output")
	use_fec := flag.Bool("u", false, "whether use FEC")
	rc := flag.String("rc", "r", "choose a redundancy controller")
	lossRate := flag.Int("l", 0, "Set LossRate")
	flag.Parse()

	NUMBER_OF_SOURCE_SYMBOLS = *nss
	NUMBER_OF_REPAIR_SYMBOLS = *nrs
	NUMBER_OF_INTERLEAVED_BLOCKS = *nifg
	DISABLE_RECOVERED_FRAMES = *norf
	certPath = *cp

	//config logfile
	LogFilePath := "/mnt/hgfs/share/log/"
	LogFilePath = LogFilePath + time.Now().Format("2006-01-02") + "/"
	_, err := os.Stat(LogFilePath)
	if err != nil {
		os.Mkdir(LogFilePath, os.ModePerm)
	}
	// now := time.Now()
	fecvar := ""
	if *use_fec {
		// rs xor
		fecvar = *fsFlag
	} else {
		fecvar = "nofec"
	}
	logFileName := fmt.Sprintf("fs+nki+loss=%s_%d_%d_%d_%d.txt",
		// now.Format("2006.01.02 15:04:05"),
		fecvar,
		NUMBER_OF_SOURCE_SYMBOLS,
		NUMBER_OF_REPAIR_SYMBOLS,
		NUMBER_OF_INTERLEAVED_BLOCKS,
		*lossRate)

	if *output != "" {
		logFileName = *output
		logfile, err := os.Create(LogFilePath + logFileName)
		if err != nil {
			panic(err)
		}
		defer logfile.Close()
		log.SetOutput(logfile)
	}

	// log.Println(LogFilePath + logFileName)

	//config TLS
	certFile := certPath + "/fullchain.pem"
	keyFile := certPath + "/privkey.pem"

	//config multipath
	var maxPathID uint8
	if *multipath {
		// Two path topology
		maxPathID = 2
	}

	//config fec scheme
	var fecScheme string = *fsFlag
	if !*use_fec {
		log.Printf("Not use FEC")
	}
	if fecScheme == "rs" {
		fs = quic.ReedSolomonFECScheme
		log.Printf("RS")
	} else if fecScheme == "xor" {
		fs = quic.XORFECScheme
		NUMBER_OF_INTERLEAVED_BLOCKS = NUMBER_OF_REPAIR_SYMBOLS
		// NUMBER_OF_SOURCE_SYMBOLS /= NUMBER_OF_REPAIR_SYMBOLS
		NUMBER_OF_REPAIR_SYMBOLS = 1
		log.Printf("XOR")
	} else {
		fs = quic.RLCFECScheme
		log.Printf("RLC")
	}

	//config redundancy controller
	rrAverage := fec.NewAverageRedundancyController(
		uint8(NUMBER_OF_SOURCE_SYMBOLS),
		uint8(NUMBER_OF_REPAIR_SYMBOLS))
	rrConstant := fec.NewConstantRedundancyController(
		NUMBER_OF_SOURCE_SYMBOLS,             //20 source code
		NUMBER_OF_REPAIR_SYMBOLS,             //10 repair code
		NUMBER_OF_INTERLEAVED_BLOCKS,         //1 interleaved blocks
		uint(protocol.ConvolutionalStepSize)) //6
	rrRQUIC := fec.NewrQuicRedundancyController(
		uint8(NUMBER_OF_SOURCE_SYMBOLS),
		uint8(NUMBER_OF_REPAIR_SYMBOLS))

	var redundancyController string = *rc
	var rr fec.RedundancyController
	if redundancyController == "r" {
		rr = rrRQUIC
	} else if redundancyController == "a" {
		rr = rrAverage
	} else if redundancyController == "c" {
		rr = rrConstant
	}
	log.Printf("RC Scheme: %s", redundancyController)

	//config quicConfig
	quicConfig := &quic.Config{
		CacheHandshake:                    *cache,
		MaxPathID:                         maxPathID,
		FECScheme:                         fs,
		RedundancyController:              rr,
		DisableFECRecoveredFrames:         DISABLE_RECOVERED_FRAMES,
		ProtectReliableStreamFrames:       *use_fec,
		UseFastRetransmit:                 false,
		OnlySendFECWhenApplicationLimited: RS_WHEN_APPLICATION_LIMITED,
		// Versions:             []quic.VersionNumber{version},

	}

	//open a fileserver with TLS
	// go http.ListenAndServeTLS("0.0.0.0:8080", certFile, keyFile, http.FileServer(http.Dir("/var/www/web")))

	//regist handler
	http.Handle("/", http.FileServer(http.Dir("/var/www")))

	listeningAddr := "0.0.0.0:" + *port
	h2quic.ListenAndServeQUICWIthConfig(
		listeningAddr,
		certFile,
		keyFile,
		nil,
		quicConfig)

	fmt.Println("end of server.")

}
