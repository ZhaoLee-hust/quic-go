package fec

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// The redundancy control will adapt the number of FEC Repair Symbols and
// the size of the FEC Group to the current conditions.

// Warning: it assumes that the packets are sent with packet numbers increasing by one.

const MAX_LOSS_BURST_LENGTH uint = 40
const SAMPLE_SIZE = 500

// 一个采样周期为500个数据包
type averageRedundancyController struct {
	initialPacketOfThisSample     protocol.PacketNumber
	packetsCounter                uint
	numberOfContiguousLostPackets uint
	lastLostPacketNumber          protocol.PacketNumber
	// numberOfContiguousLostPackets
	// 以连续丢包个数为索引？？（可以记录分别出现过多少个数据包连续丢失，这里是处理上一个连续丢包
	burstCounter map[uint]uint // TODO: evaluate performances vs array [MAX_LOSS_BURST_LENGTH]uint
	// 以当前数据包号减去上一个丢失的包号为索引，可以记录下存在过的所有的丢包丢包间距及其发生过的次数
	interLossDistanceCounter map[uint]uint // TODO: evaluate performances vs array [SAMPLE_SIZE]uint

	meanBurstLength          uint
	meanInterLossDistance    uint
	maxNumberOfSourceSymbols uint8
	maxNumberOfRepairSymbols uint8
}

var _ RedundancyController = &averageRedundancyController{}

func NewAverageRedundancyController(maxNumberOfSourceSymbols uint8, maxNumberOfRepairSymbols uint8) RedundancyController {
	return &averageRedundancyController{
		burstCounter:             make(map[uint]uint),
		interLossDistanceCounter: make(map[uint]uint),
		meanBurstLength:          uint(maxNumberOfRepairSymbols),
		meanInterLossDistance:    uint(maxNumberOfSourceSymbols),
		maxNumberOfSourceSymbols: maxNumberOfSourceSymbols,
		maxNumberOfRepairSymbols: maxNumberOfRepairSymbols,
	}
}

// 发现丢包
func (c *averageRedundancyController) OnPacketLost(pn protocol.PacketNumber) {
	// 如果还没开始计数，当前包就是第一个
	if c.packetsCounter == 0 {
		c.initialPacketOfThisSample = pn
	}
	// 如果来了个包号太小的，不管了，直接返回
	if pn < c.initialPacketOfThisSample {
		return
	}
	// 如果上一个丢包就是现在这个包号的前一个，说明出现了burst，加一个
	if c.lastLostPacketNumber == pn-1 {
		// we continue the current burst
		c.numberOfContiguousLostPackets++
	} else {
		// 如果不是，那就说明遇到了新的突发丢包
		// we begin a new burst
		// 新开一个突发计数器，以连续丢包个数为索引？？可以记录分别出现过多少个数据包连续丢失，可以记录下存在过的所有的连续丢包个数及其发生的次数
		c.burstCounter[c.numberOfContiguousLostPackets]++
		// 新开一个丢包间距计数器，以当前数据包号减去上一个丢失的包号为索引，可以记录下存在过的所有的丢包丢包间距及其发生过的次数
		c.interLossDistanceCounter[uint(pn-c.lastLostPacketNumber)]++
		// 连续丢包个数重置为1
		c.numberOfContiguousLostPackets = 1
	}
	// 最新的丢包就是现在这个数据包
	c.lastLostPacketNumber = pn
	// 增量计数器
	c.incrementCounter()
}

// 接收到数据包
func (c *averageRedundancyController) OnPacketReceived(pn protocol.PacketNumber) {
	// 出现了个很小的数据包号，返回
	if pn < c.initialPacketOfThisSample {
		return
	}
	// 包计数器如果为0,则设置起始数据包号
	if c.packetsCounter == 0 {
		c.initialPacketOfThisSample = pn
	}
	// 增量计数器
	c.incrementCounter()
}

// 返回数据包个数
func (c *averageRedundancyController) GetNumberOfDataSymbols() uint {
	// 返回平均损耗间距离和最大源符号的个数 的最小值
	return uint(utils.MinUint64(uint64(c.meanInterLossDistance), uint64(c.maxNumberOfSourceSymbols)))
}

// 返回修复符合个数
func (c *averageRedundancyController) GetNumberOfRepairSymbols() uint {
	// 返回平均爆发长度和最大修复符号的个数 的最小值
	return uint(utils.MinUint64(uint64(c.meanBurstLength), uint64(c.maxNumberOfRepairSymbols)))
	// return 1
}

// 返回交织块个数
func (c *averageRedundancyController) GetNumberOfInterleavedBlocks() uint {
	// 如果设定的最大修复符合为1,那就返回平均爆发长度(刚好完美修复)
	if c.maxNumberOfRepairSymbols == 1 {
		return c.meanBurstLength
	}
	return 1
}

// 返回窗口StepSize
func (c *averageRedundancyController) GetWindowStepSize() uint {
	// 返回平均丢包间距/平均丢包长度,至少为2
	return uint(utils.MaxUint64(2, uint64(c.meanInterLossDistance/c.meanBurstLength)))
}

// 增量计数器
func (c *averageRedundancyController) incrementCounter() {
	// 增加一个数据包个数
	c.packetsCounter++
	// 如果数据包已经到达了一个采样周期数
	if c.packetsCounter == SAMPLE_SIZE {
		// 计算预测值
		c.computeEstimations()
		// 包计数器清空
		c.packetsCounter = 0
		// 突发丢包计数器清空
		c.burstCounter = make(map[uint]uint)
		// 突发间距计数器清空
		c.interLossDistanceCounter = make(map[uint]uint)
	}
}

// 核心代码,每次丢包或接受数据包之后都会调用,计算平均爆发丢包和平均丢包间距
func (c *averageRedundancyController) computeEstimations() {
	// 定义当前时间的总爆发丢包个数，包含所有丢包长度乘各自发生的次数
	var sumOccurrencesTimesBurstLength uint = 0
	// 记录出现过爆发丢包的次数
	var sumOccurrences uint = 0
	for burstLength, count := range c.burstCounter {
		sumOccurrencesTimesBurstLength += burstLength * count
		sumOccurrences += count
	}
	// 如果出现过爆发丢包(1个似乎也算爆发？)
	if sumOccurrences > 0 {
		// 新旧的权重相当
		// 平均爆发长度=平均爆发长度与当前统计的平均爆发长度的加权平均，当前爆发长度的计算方式三总的爆发丢包个数/出现过的爆发丢包次数
		c.meanBurstLength = movingAverage(c.meanBurstLength, sumOccurrencesTimesBurstLength/sumOccurrences, 0.5)
	} else {
		// 如果没有出现过爆发丢包，平均爆发丢包长度减半
		c.meanBurstLength = movingAverage(c.meanBurstLength, 0, 0.5)
	}

	var sumOccurencesTimesILD uint = 0
	sumOccurrences = 0
	// 遍历丢包间距计数器，计算平均丢包间距
	for ild, count := range c.interLossDistanceCounter {
		sumOccurencesTimesILD += ild * count
		sumOccurrences += count
	}
	if sumOccurrences > 0 {
		c.meanInterLossDistance = uint(utils.MinUint64(uint64(movingAverage(c.meanInterLossDistance, sumOccurencesTimesILD/sumOccurrences, 0.7)), uint64(c.maxNumberOfSourceSymbols)))
	} else {
		c.meanInterLossDistance = movingAverage(c.meanInterLossDistance, uint(c.maxNumberOfSourceSymbols), 0.7)
	}
}

// 滑动均值,返回factor*old+(1-factor)*new
func movingAverage(old uint, new uint, factor float64) uint {
	return uint(factor*float64(old) + (1-factor)*float64(new))
}

func (c *averageRedundancyController) PushParamerters(paras TransParams) {}
