// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/lucas-clemente/quic-go/fec (interfaces: FECScheduler)

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	fec "github.com/lucas-clemente/quic-go/fec"
	protocol "github.com/lucas-clemente/quic-go/internal/protocol"
)

// MockFECScheduler is a mock of FECScheduler interface
type MockFECScheduler struct {
	ctrl     *gomock.Controller
	recorder *MockFECSchedulerMockRecorder
}

// MockFECSchedulerMockRecorder is the mock recorder for MockFECScheduler
type MockFECSchedulerMockRecorder struct {
	mock *MockFECScheduler
}

// NewMockFECScheduler creates a new mock instance
func NewMockFECScheduler(ctrl *gomock.Controller) *MockFECScheduler {
	mock := &MockFECScheduler{ctrl: ctrl}
	mock.recorder = &MockFECSchedulerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockFECScheduler) EXPECT() *MockFECSchedulerMockRecorder {
	return m.recorder
}

// GetNextFECBlockNumber mocks base method
func (m *MockFECScheduler) GetNextFECBlockNumber() protocol.FECBlockNumber {
	ret := m.ctrl.Call(m, "GetNextFECBlockNumber")
	ret0, _ := ret[0].(protocol.FECBlockNumber)
	return ret0
}

// GetNextFECBlockNumber indicates an expected call of GetNextFECBlockNumber
func (mr *MockFECSchedulerMockRecorder) GetNextFECBlockNumber() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetNextFECBlockNumber", reflect.TypeOf((*MockFECScheduler)(nil).GetNextFECBlockNumber))
}

// GetNextFECGroup mocks base method
func (m *MockFECScheduler) GetNextFECGroup() *fec.FECBlock {
	ret := m.ctrl.Call(m, "GetNextFECGroup")
	ret0, _ := ret[0].(*fec.FECBlock)
	return ret0
}

// GetNextFECGroup indicates an expected call of GetNextFECGroup
func (mr *MockFECSchedulerMockRecorder) GetNextFECGroup() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetNextFECGroup", reflect.TypeOf((*MockFECScheduler)(nil).GetNextFECGroup))
}

// GetNextFECGroupOffset mocks base method
func (m *MockFECScheduler) GetNextFECGroupOffset() byte {
	ret := m.ctrl.Call(m, "GetNextFECGroupOffset")
	ret0, _ := ret[0].(byte)
	return ret0
}

// GetNextFECGroupOffset indicates an expected call of GetNextFECGroupOffset
func (mr *MockFECSchedulerMockRecorder) GetNextFECGroupOffset() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetNextFECGroupOffset", reflect.TypeOf((*MockFECScheduler)(nil).GetNextFECGroupOffset))
}

// SentFECBlock mocks base method
func (m *MockFECScheduler) SentFECBlock(arg0 protocol.FECBlockNumber) {
	m.ctrl.Call(m, "SentFECBlock", arg0)
}

// SentFECBlock indicates an expected call of SentFECBlock
func (mr *MockFECSchedulerMockRecorder) SentFECBlock(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SentFECBlock", reflect.TypeOf((*MockFECScheduler)(nil).SentFECBlock), arg0)
}

// SetRedundancyController mocks base method
func (m *MockFECScheduler) SetRedundancyController(arg0 fec.RedundancyController) {
	m.ctrl.Call(m, "SetRedundancyController", arg0)
}

// SetRedundancyController indicates an expected call of SetRedundancyController
func (mr *MockFECSchedulerMockRecorder) SetRedundancyController(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetRedundancyController", reflect.TypeOf((*MockFECScheduler)(nil).SetRedundancyController), arg0)
}
