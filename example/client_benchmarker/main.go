package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
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
var NUMBER_OF_REPAIR_SYMBOLS uint = 3
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
	// output := flag.String("o", "", "logging output")
	cache := flag.Bool("c", false, "cache handshake information")
	fsFlag := flag.String("fs", "rs", "rs, rlc or xor")

	remoteAddr := flag.String("addr", "https://10.0.0.2", "Remote address")
	port := flag.String("port", "6121", "The port will listen on")
	filename := flag.String("f", "file2", "Filename")

	use_fec := flag.Bool("fec", false, "whether use FEC")
	rc := flag.String("rc", "c", "choose a redundancy controller")
	keylog := flag.String("key", "/home/zhaolee/go/src/github.com/lucas-clemente/quic-go/example/client_benchmarker/key.log", "key log file")

	EnhanceScheme := flag.String("s", "none", "choos from none, QUIC_LR, QUIC_RD")

	flag.Parse()

	if *use_fec {
		log.Printf("开启FEC机制!\n")
	}

	if *EnhanceScheme == "lr" {
		log.Printf("开启QUIC-LR策略!默认开启FEC!\n")
		protocol.QUIC_LR = true
		protocol.QUIC_RD = false
		protocol.QUIC_D = false
	} else if *EnhanceScheme == "rd" {
		log.Printf("开启QUIC-RD策略!\n")
		protocol.QUIC_LR = false
		protocol.QUIC_RD = true
		protocol.QUIC_D = false
	} else if *EnhanceScheme == "d" {
		log.Printf("开启QUIC-D策略!\n")
		protocol.QUIC_LR = false
		protocol.QUIC_RD = false
		protocol.QUIC_D = true
	} else {
		log.Printf("QUIC-LR,QUIC-RD和QUIC-D均不启用!\n")
		protocol.QUIC_LR = false
		protocol.QUIC_RD = false
		protocol.QUIC_D = false
	}

	//config logfile
	if *verbose {
		utils.SetLogLevel(utils.LogLevelDebug)
	} else {
		utils.SetLogLevel(utils.LogLevelInfo)
	}
	utils.SetLogLevel(utils.LogLevelError)

	// LogFilePath := "/mnt/hgfs/share/2024/"
	// LogFilePath = LogFilePath + time.Now().Format("2006-01-02") + "/"
	// _, err := os.Stat(LogFilePath)
	// if err != nil {
	// 	os.Mkdir(LogFilePath, os.ModePerm)
	// }
	// if *output != "" {
	// 	logFileName := *output
	// 	logfile, err := os.Create(LogFilePath + logFileName)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	defer logfile.Close()
	// 	log.SetOutput(logfile)
	// }
	logfile, err := os.Create("clientLog.txt")
	if err != nil {
		panic(err)
	}
	defer logfile.Close()
	log.SetOutput(logfile)

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
		ProtectReliableStreamFrames:       *use_fec || *EnhanceScheme == "lr", //显示指定或者使用lr策略
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
			// log.Printf("transfer length: %d", body.Len())
			// // fmt.Sprintln("transfer time:", elapsed)
			// log.Printf("transfer time: %s", elapsed)

			// 微秒单位
			mjson, _ := json.Marshal([]int64{elapsed.Microseconds()})
			_ = os.WriteFile("client_TransferTime.json", mjson, 0644)

			wg.Done()
		}(addr)
	}
	wg.Wait()
}
