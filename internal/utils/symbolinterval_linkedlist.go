package utils

type SymbolIntervalElement struct {
	// 上下节点
	next, prev *SymbolIntervalElement

	// 所属链表，里面有一个根节点和一个长度
	list *SymbolIntervalList

	// 标注开始和结束的符号编号
	Value SymbolTnterval
}

func (e *SymbolIntervalElement) Next() *SymbolIntervalElement {
	if p := e.next; e.list != nil && p != &e.list.root {
		return p
	}
	return nil
}

func (e *SymbolIntervalElement) Prev() *SymbolIntervalElement {
	if p := e.prev; e.list != nil && p != &p.list.root {
		return p
	}
	return nil
}

type SymbolIntervalList struct {
	root SymbolIntervalElement
	len  int
}

func (l *SymbolIntervalList) Init() *SymbolIntervalList {
	l.root.next = &l.root
	l.root.prev = &l.root
	l.len = 0
	return l
}

func NewSymbolIntervalList() *SymbolIntervalList {
	return new(SymbolIntervalList).Init()
}

func (l *SymbolIntervalList) Len() int {
	return l.len
}

func (l *SymbolIntervalList) Front() *SymbolIntervalElement {
	if l.len == 0 {
		return nil
	}
	return l.root.next
}

func (l *SymbolIntervalList) Back() *SymbolIntervalElement {
	if l.len == 0 {
		return nil
	}
	return l.root.prev
}

func (l *SymbolIntervalList) lazyInit() {
	if l.root.next == nil {
		l.Init()
	}
}

// 会修改前后指针，安全
func (l *SymbolIntervalList) insert(e, at *SymbolIntervalElement) *SymbolIntervalElement {
	n := at.next
	at.next = e
	e.prev = at
	e.next = n
	n.prev = e
	e.list = l
	l.len++
	return e

}

func (l *SymbolIntervalList) insertValue(v SymbolTnterval, at *SymbolIntervalElement) *SymbolIntervalElement {
	return l.insert(&SymbolIntervalElement{Value: v}, at)
}

func (l SymbolIntervalList) remove(e *SymbolIntervalElement) *SymbolIntervalElement {
	e.prev.next = e.next
	e.next.prev = e.prev
	e.next = nil
	e.prev = nil
	e.list = nil
	l.len--
	return e
}

func (l *SymbolIntervalList) Remove(e *SymbolIntervalElement) SymbolTnterval {
	if e.list == l {
		l.remove(e)
	}
	return e.Value
}

func (l *SymbolIntervalList) PushFront(v SymbolTnterval) *SymbolIntervalElement {
	l.lazyInit()
	return l.insertValue(v, &l.root)
}

func (l *SymbolIntervalList) PushBack(v SymbolTnterval) *SymbolIntervalElement {
	l.lazyInit()
	return l.insertValue(v, l.root.prev)
}

func (l *SymbolIntervalList) InsertBefore(v SymbolTnterval, mark *SymbolIntervalElement) *SymbolIntervalElement {
	if mark.list != l {
		return nil
	}
	return l.insertValue(v, mark.prev)
}

func (l *SymbolIntervalList) InsertAfter(v SymbolTnterval, mark *SymbolIntervalElement) *SymbolIntervalElement {
	if mark.list != l {
		return nil
	}
	return l.insertValue(v, mark)
}

func (l *SymbolIntervalList) MoveToFront(e *SymbolIntervalElement) {
	if e.list != l || l.root.next == e {
		return
	}
	l.remove(e)
	l.insert(e, &l.root)
}

func (l *SymbolIntervalList) MoveToBack(e *SymbolIntervalElement) {
	if e.list != l || l.root.prev == e {
		return
	}
	// l.InsertBefore(l.remove(e).Value, &l.root)
	l.insert(l.remove(e), l.root.prev)
}

func (l *SymbolIntervalList) MoveBefore(e, mark *SymbolIntervalElement) {
	if e.list != l || e == mark || mark.list != l {
		return
	}
	l.insert(l.remove(e), mark.prev)
}

func (l *SymbolIntervalList) MoveAfter(e, mark *SymbolIntervalElement) {
	if e.list != l || mark.list != l || e == mark {
		return
	}
	l.insert(l.remove(e), mark)
}

func (l *SymbolIntervalList) PushBackList(other *SymbolIntervalList) {
	l.lazyInit()
	for i, e := other.Len(), other.Front(); i > 0; i, e = i-1, e.Next() {
		l.insertValue(e.Value, l.root.prev)
	}
}

func (l *SymbolIntervalList) PushFrontList(other *SymbolIntervalList) {
	l.lazyInit()
	for i, e := other.Len(), other.Back(); i > 0; i, e = i-1, e.Prev() {
		l.insertValue(e.Value, &l.root)
	}
}
