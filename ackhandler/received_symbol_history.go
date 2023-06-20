package ackhandler

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/qerr"
)

type receivedSymbolHistory struct {
	// ranges是个list，里面的元素是根节点本体和list长度，节点有prev和next方法，并存有所属的list。节点的value是range，包括start和end
	ranges                        *utils.SymbolIntervalList
	lowestInReceivedSymbolNumbers protocol.SymbolNumber
}

var errTooManyOutstandingReceivedSymbolRanges = qerr.Error(qerr.TooManyOutstandingReceivedSymbols, "Too many outstanding received Symbol ACK ranges")

func newreceivedSymbolHistory() *receivedSymbolHistory {
	return &receivedSymbolHistory{
		ranges: utils.NewSymbolIntervalList(),
	}
}

func (h *receivedSymbolHistory) ReceiveSymbol(p protocol.SymbolNumber) error {
	// 处理超出长度错误，history追踪了len个range
	if h.ranges.Len() >= protocol.MaxTrackedReceivedSymbolAckRanges {
		return errTooManyOutstandingReceivedSymbolRanges
	}

	if h.ranges.Len() == 0 {
		h.ranges.PushBack(utils.SymbolTnterval{Start: p, End: p})
		return nil
	}

	for el := h.ranges.Back(); el != nil; el = el.Prev() {
		if p >= el.Value.Start && p <= el.Value.End {
			return nil
		}

		// 说明没在当前的range中找到

		var rangeExtended bool
		if el.Value.End+1 == p {
			rangeExtended = true
			el.Value.End = p
		} else if el.Value.Start-1 == p {
			rangeExtended = true
			el.Value.Start = p
		}

		if rangeExtended {
			prev := el.Prev()
			if prev != nil && prev.Value.End+1 == el.Value.Start {
				prev.Value.End = el.Value.End
				h.ranges.Remove(el)
				return nil
			}
			return nil
		}

		if p > el.Value.End {
			h.ranges.InsertAfter(utils.SymbolTnterval{Start: p, End: p}, el)
			return nil
		}
	}

	h.ranges.InsertBefore(utils.SymbolTnterval{Start: p, End: p}, h.ranges.Front())
	return nil
}

// 删除history的el, 直到el的范围包含了p
func (h *receivedSymbolHistory) DeleteUpTo(p protocol.SymbolNumber) {
	h.lowestInReceivedSymbolNumbers = utils.MaxSymbolNumber(h.lowestInReceivedSymbolNumbers, p+1)

	nextEl := h.ranges.Front()
	for el := h.ranges.Front(); nextEl != nil; el = nextEl {
		nextEl = el.Next()

		if p >= el.Value.Start && p < el.Value.End {
			el.Value.Start = p + 1
		} else if el.Value.End <= p {
			h.ranges.Remove(el)
		} else {
			return
		}
	}
}

// 遍历所有symbol，将symbol的range返回
func (h *receivedSymbolHistory) GetSymbolRanges() []wire.SymbolRange {
	if h.ranges.Len() == 0 {
		return nil
	}

	symbolRanges := make([]wire.SymbolRange, h.ranges.Len())
	i := 0
	for el := h.ranges.Back(); el != nil; el = el.Prev() {
		symbolRanges[i] = wire.SymbolRange{First: protocol.PacketNumber(el.Value.Start), Last: protocol.PacketNumber(el.Value.End)}
		i++
	}
	return symbolRanges
}

// r := h.ranges.Back().Value，返回r的first和last组成的range
func (h *receivedPacketHistory) GetHighestSymbolRange() wire.SymbolRange {
	symbolRange := wire.SymbolRange{}

	if h.ranges.Len() > 0 {
		r := h.ranges.Back().Value
		symbolRange.First = r.Start
		symbolRange.Last = r.End
	}
	return symbolRange
}
