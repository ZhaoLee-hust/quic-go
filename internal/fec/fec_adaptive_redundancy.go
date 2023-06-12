package fec

// Added by zhaolee

var NumberofRecoveredPacket int

var TempCount int = 0

// var LossRate float32

type AdaptiveFEC interface {
	GetLossRateAverage() (float32, error)
	GetLossRate() error
	GetAdaptiveRC() RedundancyController
}

type AdaptiveController struct {
	NPacketTrans         *[]int
	NPacketloss          *[]int
	RealtimeRTT          *[]float32
	LossRateAverage      float32
	LossRate             *[]float32
	RedundancyController RedundancyController
}

// for pathID, pth := range f.sess.paths {
// 	sntPkts, sntRetrans, sntLost := pth.sentPacketHandler.GetStatistics()
// 	rcvPkts, recoveredPkts := pth.receivedPacketHandler.GetStatistics()
// 	utils.Infof("Path %x: sent %d retrans %d lost %d; rcv %d, recovered %d", pathID, sntPkts, sntRetrans, sntLost, rcvPkts, recoveredPkts)
// 	// modify -add
// 	utils.Infof("Number of recovered packets in all: %d", fec.NumberofRecoveredPacket)
// 	// utils.Infof("Redundancycontroller: D:%d,R:%d", s.redundancyController.GetNumberOfDataSymbols(), s.redundancyController.GetNumberOfRepairSymbols())
// 	// utils.Infof("Redundancycontroller: D:%d,R:%d", s.fecFrameworkSender.redundancyController.GetNumberOfDataSymbols(), s.fecFrameworkSender.redundancyController.GetNumberOfRepairSymbols())
// }

type DetectedParameters struct {
	sntPkts       int
	sntRetrans    int
	sntLost       int
	rcvPkts       int
	recoveredPkts int
}

func (d *DetectedParameters) LossRate() float32 {
	return float32(d.sntLost) / float32(d.sntPkts)
}

func (d *DetectedParameters) RetransRatio() float32 {
	return float32(d.sntRetrans) / float32(d.sntPkts)
}

// func (d *DetectedParameters) Residual() float32{
// 	return float32(d)
// }

var _ AdaptiveFEC = &AdaptiveController{}

// change the redundancycontroller if neccesary, return it and set the 2nd parameter (ShouldChange flag) TRUE
func MaybeChangeAndRenewReduandancyController(c RedundancyController) (RedundancyController, bool) {
	// ...
	// TODO

	return nil, false
}

func TransLossRate() {}

func (t *AdaptiveController) GetLossRateAverage() (float32, error) {
	// ...
	return 0, nil
}

func (t *AdaptiveController) GetLossRate() error {
	// ...

	return nil
}

func (t *AdaptiveController) GetAdaptiveRC() RedundancyController {
	// ...
	return NewConstantRedundancyController(20, 10, 1, 6)
}

// func (t *AdaptiveController) SavetoTxt(writeString string) {

// 	file, err := os.OpenFile("/home/zhaolee/go/src/github.com/lucas-clemente/quic-go/example/data/"+"test.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
// 	if err != nil {
// 		panic(err)
// 	}
// 	defer file.Close()
// 	write := bufio.NewWriter(file)
// 	write.WriteString(writeString)
// 	write.Flush()
// }
