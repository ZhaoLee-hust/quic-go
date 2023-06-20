package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"path"
	"runtime"
	"strings"
	"sync"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/fec"
	"github.com/lucas-clemente/quic-go/internal/protocol"

	_ "net/http/pprof"

	"github.com/lucas-clemente/quic-go/h2quic"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

var NUMBER_OF_SOURCE_SYMBOLS uint = 20
var NUMBER_OF_REPAIR_SYMBOLS uint = 10
var NUMBER_OF_INTERLEAVED_BLOCKS uint = 1
var DISABLE_RECOVERED_FRAMES bool = true
var USE_FEC bool = false
var RS_WHEN_APPLICATION_LIMITED = false

type binds []string

var certPath string
var www string
var maxPathID uint8
var fs quic.FECSchemeID
var tcp bool

// var urls []string
//server不需要
var version quic.VersionNumber

func (b binds) String() string {
	return strings.Join(b, ",")
}

func (b *binds) Set(v string) error {
	*b = strings.Split(v, ",")
	return nil
}

// Size is needed by the /demo/upload handler to determine the size of the uploaded file
type Size interface {
	Size() int64
}

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

func mainServer(port int) {
	fmt.Println("run as a server...")
	bs := binds{} //底层是string

	certFile := certPath + "/fullchain.pem"
	keyFile := certPath + "/privkey.pem"

	http.Handle("/", http.FileServer(http.Dir(www)))
	//www = *w
	// w:= flag.String("www", "/var/www", "www data")
	//http.Dir(www)，将www转为http.Dir类型

	if len(bs) == 0 {
		// bs = binds{fmt.Sprintf("0.0.0.0:%d", port)} //bs = 0.0.0.0:6121
		bs = binds{fmt.Sprintf("0.0.0.0:%d", port)}
	}
	//格式化字符串
	//=localhost:port

	var wg sync.WaitGroup
	wg.Add(len(bs))
	//test show----------------------
	//fmt.Println("lenth of bs:", len(bs), reflect.TypeOf(bs), bs)
	//-------------------------------
	for _, b := range bs {
		bCap := b
		//test show----------------------
		fmt.Println(bCap)
		//--------------------
		go func() {
			var err error
			//var tcp bool
			//tcp = *tcpArg
			//tcpArg := flag.Bool("tcp", false, "also listen on TCP")
			if tcp {
				err = h2quic.ListenAndServe(bCap, certFile, keyFile, nil)
				fmt.Println("listening on tcp")
			} else {
				println("maxPathID ", maxPathID)
				println("listenning on quic")
				rr := fec.NewConstantRedundancyController(
					NUMBER_OF_SOURCE_SYMBOLS,             //20 source code
					NUMBER_OF_REPAIR_SYMBOLS,             //10 repair code
					NUMBER_OF_INTERLEAVED_BLOCKS,         //1 interleaved blocks
					uint(protocol.ConvolutionalStepSize)) //6
				//20 10 1 6
				err = h2quic.ListenAndServeQUICWIthConfig(
					bCap,     //ddr
					certFile, //certFile
					keyFile,  //keyFile string
					nil,      //handler http.Handler
					&quic.Config{ //config *quic.Config
						Versions:                          []quic.VersionNumber{version},
						MaxPathID:                         maxPathID,
						FECScheme:                         fs,
						RedundancyController:              rr,
						DisableFECRecoveredFrames:         DISABLE_RECOVERED_FRAMES,
						ProtectReliableStreamFrames:       USE_FEC,
						UseFastRetransmit:                 true,
						OnlySendFECWhenApplicationLimited: RS_WHEN_APPLICATION_LIMITED})
				//ddr, certFile, keyFile string, handler http.Handler, config *quic.Config
			}
			if err != nil {
				fmt.Println(err)
			}
			wg.Done()
		}()
	}
	wg.Wait()
}

func main() {
	//flag.???返回的是指针
	verbose := flag.Bool("v", false, "verbose") //设置log等级
	//flag.Var(&bs, "bind", "bind to")
	cp := flag.String("certpath", getBuildDir(), "certificate directory")
	w := flag.String("www", "/var/www", "www data")
	tcpArg := flag.Bool("tcp", false, "also listen on TCP")
	// serv := flag.Bool("s", false, "acts as a server")
	fecSchemeFlag := flag.String("fecScheme", "rs", "rs, rlc or xor")
	multipath := flag.Bool("multipath", false, "uses multiple paths")
	port := flag.Int("p", 6121, "port in which to listen (SERVER ONLY)")
	nss := flag.Uint("nss", NUMBER_OF_SOURCE_SYMBOLS, "Default number of Source Symbols (max. 255)")
	nrs := flag.Uint("nrs", NUMBER_OF_REPAIR_SYMBOLS, "Default number of Repair Symbols (max. 255)")
	nifg := flag.Uint("nifg", NUMBER_OF_INTERLEAVED_BLOCKS, "Set to 1 (recommended) when no block interleaving is needed. Specifies the number of FEC blocks to interleave to handle loss bursts for weak codes such as XOR. (max. 255)")
	css := flag.Uint("css", uint(protocol.ConvolutionalStepSize), "Step size of the convolutional window for convolutional codes")
	norf := flag.Bool("no-rf", false, "Use this flag to prevent the receiver from sending recovered frames")
	nofec := flag.Bool("no-fec", false, "Use this flag to prevent the sender from sending Repair Symbols")
	eos := flag.Bool("eos", false, "Use this flag to only send Repair Symbols to only send FEC Frames when application-limited")
	cwinfile := flag.String("cwinfile", protocol.FILE_CONTAINING_CWIN, "file in which to store the cwin evolution")
	flag.Parse()
	// urls = flag.Args()
	//server不需要url

	if *verbose {
		utils.SetLogLevel(utils.LogLevelDebug)
	} else {
		utils.SetLogLevel(utils.LogLevelInfo)
	}
	utils.SetLogTimeFormat("")

	protocol.FILE_CONTAINING_CWIN = *cwinfile

	NUMBER_OF_SOURCE_SYMBOLS = *nss
	NUMBER_OF_REPAIR_SYMBOLS = *nrs
	NUMBER_OF_INTERLEAVED_BLOCKS = *nifg
	DISABLE_RECOVERED_FRAMES = *norf
	USE_FEC = !*nofec
	RS_WHEN_APPLICATION_LIMITED = *eos
	protocol.ConvolutionalStepSize = int(*css)

	certPath = *cp
	www = *w
	tcp = *tcpArg

	var fecSchemeArg string = *fecSchemeFlag
	// "rs, rlc or xor" default RLS

	// fecSchemeArg = *fecSchemeFlag
	maxPathID = 0
	if *multipath {
		maxPathID = 3
		version = protocol.VersionMP
	} else {
		version = protocol.Version39
	}

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

	protocol.NumberOfFecPackets = uint32(NUMBER_OF_SOURCE_SYMBOLS)
	protocol.NumberOfRepairSymbols = uint8(NUMBER_OF_REPAIR_SYMBOLS)
	protocol.NumberOfInterleavedFECGroups = NUMBER_OF_INTERLEAVED_BLOCKS

	mainServer(*port) //6121 for default

}
