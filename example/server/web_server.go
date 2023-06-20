// package main

// import (
// 	"net/http"
// 	"path"
// 	"runtime"

// 	"github.com/lucas-clemente/quic-go/h2quic"
// )

// func main() {
// 	// server := h2quic.Server{}
// 	certPath := getBuildDir()
// 	certFile := certPath + "/fullchain.pem"
// 	keyFile := certPath + "/privkey.pem"
// 	h2quic.ListenAndServeQUIC(":8080", certFile, keyFile, http.FileServer(http.Dir("/var/www/web")))
// }

// func getBuildDir() string {
// 	_, filename, _, ok := runtime.Caller(0)
// 	//runtime.Caller(skip)
// 	//pc,file,line,ok := runtime.Caller(skip)
// 	//skip为0时表示当前文件

// 	if !ok {
// 		panic("Failed to get current frame")
// 	}

// 	return path.Dir(filename)
// } //返回当前工作文件夹目录
