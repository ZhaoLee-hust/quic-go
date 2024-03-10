package main

import (
	"fmt"
	"os/exec"
	"strings"
)

func main() {
	var myDir = NewDirs()
	myDir.Init()

	// server := myDir.GetNode("server")
	limit := 1000
	delayRange := [2]int{0, 20}
	lossRange := [2]int{0, 10}
	rate := 20

	delay := make([]int, delayRange[1]-delayRange[0]+1)
	for i := 0; i < len(delay); i++ {
		delay[i] = i + delayRange[0]
	}
	loss := make([]int, lossRange[1]-lossRange[0])
	for i := 0; i < len(loss); i++ {
		loss[i] = i + lossRange[0]
	}
	// 设定链路状态，并发起请求
	s1 := myDir.GetNode("s1")
	client := myDir.GetNode("client")
	for _, curLoss := range loss {
		for _, curDelay := range delay {
			bash := fmt.Sprintf("./scripts/TC_NETEM.bash %d %d %d %d", limit, curDelay, curLoss, rate)
			s1.cmd(bash)
			cmd := exec.Command("cd", myDir.Client)
			cmd.Run()
			cmd = exec.Command("go", "build", "main.go")
			cmd.Run()
			cmd = exec.Command("cp")
			// buildClientAndMoveToWorkdir()
		}
	}
	// s1.cmd(bash)
	// server.cmd("./main-server -u -rc c -o -l 17")

}

// func buildClientAndMoveToWorkdir() {
// 	cmd1 := fmt.Sprintf("%s ")
// 	exec.Command("cd")
// }

type node struct {
	path string
	name string
}

func (n *node) cmd(cli string) {
	args := strings.Split(cli, " ")
	args = append([]string{n.name}, args...)
	cmd := exec.Command(n.path, args...)
	// cmd.Start()
	out, _ := cmd.CombinedOutput()
	fmt.Println(string(out))
}

type Dirs struct {
	Quicgo   string
	Client   string
	Server   string
	WebPort  string
	Url      string
	FileName string
	MPath    string
	Pwd      string
	HttpDir  string
}

func NewDirs() *Dirs {
	return &Dirs{}
}

func (m *Dirs) Init() {
	m.SetDirsForQuicGo()
	m.SetDirsforMininet()
}

func (m *Dirs) SetDirsForQuicGo() {
	m.Quicgo = "/home/zhaolee/go/src/github.com/lucas-clemente/quic-go/"
	m.Client = m.Quicgo + "example/client_benchmarker/"
	m.Server = m.Quicgo + "example/server/"
	m.WebPort = "6121"
	m.HttpDir = "https://127.0.0.1"
	m.FileName = "file3"
	m.Url = m.HttpDir + ":" + m.WebPort + "/" + m.FileName
}

func (m *Dirs) SetDirsforMininet() {
	m.MPath = "/home/zhaolee/workplace/mininet/util/m"
	m.Pwd = "/home/zhaolee/workplace/PythonWork/mininettest/"
}

func (m *Dirs) GetNode(name string) *node {
	return &node{
		path: m.MPath,
		name: name,
	}
}
