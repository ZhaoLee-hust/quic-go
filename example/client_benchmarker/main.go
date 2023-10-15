package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	_ "net/http/pprof"

	quic "github.com/lucas-clemente/quic-go"

	"github.com/lucas-clemente/quic-go/fec"
	"github.com/lucas-clemente/quic-go/h2quic"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	// _ "net/http/pprof"
)

var fs quic.FECSchemeID
var NUMBER_OF_SOURCE_SYMBOLS uint = 15
var NUMBER_OF_REPAIR_SYMBOLS uint = 6
var NUMBER_OF_INTERLEAVED_BLOCKS uint = 1
var DISABLE_RECOVERED_FRAMES bool = false

// var USE_FEC bool = false
var RS_WHEN_APPLICATION_LIMITED = false

func main() {
	// go func() {
	// 	log.Println(http.ListenAndServe("localhost:6060", nil))
	// }()
	verbose := flag.Bool("v", false, "verbose")
	multipath := flag.Bool("m", false, "multipath")
	output := flag.String("o", "", "logging output")
	cache := flag.Bool("c", false, "cache handshake information")
	fsFlag := flag.String("fs", "rs", "rs, rlc or xor")

	remoteAddr := flag.String("addr", "https://10.0.0.2", "Remote address")
	port := flag.String("port", "6121", "The port will listen on")
	filename := flag.String("f", "file2", "Filename")

	use_fec := flag.Bool("u", false, "whether use FEC")
	rc := flag.String("s", "c", "choose a redundancy controller")
	keylog := flag.String("key", "/home/zhaolee/go/src/github.com/lucas-clemente/quic-go/example/client_benchmarker/key.log", "key log file")
	flag.Parse()

	//config logfile
	if *verbose {
		utils.SetLogLevel(utils.LogLevelDebug)
	} else {
		utils.SetLogLevel(utils.LogLevelInfo)
	}
	utils.SetLogLevel(utils.LogLevelError)
	// fecvar := ""
	// if *use_fec {
	// 	fecvar = *fsFlag
	// } else {
	// 	fecvar = "nofec"
	// }
	LogFilePath := "/mnt/hgfs/share/log/"
	LogFilePath = LogFilePath + time.Now().Format("2006-01-02") + "/"
	_, err := os.Stat(LogFilePath)
	if err != nil {
		os.Mkdir(LogFilePath, os.ModePerm)
	}
	if *output != "" {
		logFileName := *output
		logfile, err := os.Create(LogFilePath + logFileName)
		if err != nil {
			panic(err)
		}
		defer logfile.Close()
		log.SetOutput(logfile)
	}

	// if *output != "" {
	// 	// fecSchemeFlag= rs xor rlc
	// 	logfile, err := os.Create(LogFilePath + fecvar + "_" + *output + ".txt")
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	defer logfile.Close()
	// 	log.SetOutput(logfile)
	// }
	// logExp := "CNOPackets" + "    " + "TNOPackets" + "    " + "CNOSymbols" + "    " + "TNOSymbols" + "    " + "NRECPackets\n"
	// utils.Infof(logExp)

	//config multipath
	var maxPathID uint8
	if *multipath {
		// Two path topology
		maxPathID = 2
	}

	//config fec scheme
	var fecSchemeArg string = *fsFlag
	if fecSchemeArg == "rs" {
		fs = quic.ReedSolomonFECScheme
		utils.Infof("FEC Scheme: RS")
	} else if fecSchemeArg == "xor" {
		fs = quic.XORFECScheme
		NUMBER_OF_INTERLEAVED_BLOCKS = NUMBER_OF_REPAIR_SYMBOLS
		NUMBER_OF_SOURCE_SYMBOLS /= NUMBER_OF_REPAIR_SYMBOLS
		NUMBER_OF_REPAIR_SYMBOLS = 1
		utils.Infof("FEC Scheme: XOR")
	} else {
		fs = quic.RLCFECScheme
		utils.Infof("FEC Scheme: RLC")
	}

	utils.Infof("running client!")

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
	utils.Infof("redundancy controller: %s", redundancyController)

	//config quicConfig
	quicConfig := &quic.Config{
		CacheHandshake:                    *cache,
		MaxPathID:                         maxPathID,
		FECScheme:                         fs,
		RedundancyController:              rr,
		DisableFECRecoveredFrames:         DISABLE_RECOVERED_FRAMES,
		ProtectReliableStreamFrames:       *use_fec,
		UseFastRetransmit:                 true,
		OnlySendFECWhenApplicationLimited: RS_WHEN_APPLICATION_LIMITED,
	}

	//config client
	key, _ := os.Create(*keylog)
	hclient := &http.Client{
		Transport: &h2quic.RoundTripper{QuicConfig: quicConfig,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, KeyLogWriter: key},
		},
	}

	//config urls
	var urls []string
	// *remoteAddr = "https://127.0.0.1"
	if len(flag.Args()) != 0 {
		urls = flag.Args()
	} else {
		fmt.Println("Init addr: " + *remoteAddr + ":" + *port + "/" + *filename)
		urls = append(urls, *remoteAddr+":"+*port+"/"+*filename)
	}

	//get!
	var wg sync.WaitGroup
	wg.Add(len(urls))
	for _, addr := range urls {
		utils.Infof("GET %s", addr)
		go func(addr string) {
			start := time.Now()
			rsp, err := hclient.Get(addr)
			if err != nil {
				panic(err)
			}

			body := &bytes.Buffer{}
			_, err = io.Copy(body, rsp.Body)
			if err != nil {
				panic(err)
			}

			// fmt.Println(body)
			elapsed := time.Since(start)
			log.Printf("transfer length: %d", body.Len())
			// fmt.Sprintln("transfer time:", elapsed)
			log.Printf("transfer time: %s", elapsed)

			wg.Done()
		}(addr)
	}
	wg.Wait()
}
