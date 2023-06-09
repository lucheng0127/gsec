// Code generated by MockGen. DO NOT EDIT.
// Source: pkg/pkt/pkt.go

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// MockPKT is a mock of PKT interface.
type MockPKT struct {
	ctrl     *gomock.Controller
	recorder *MockPKTMockRecorder
}

// MockPKTMockRecorder is the mock recorder for MockPKT.
type MockPKTMockRecorder struct {
	mock *MockPKT
}

// NewMockPKT creates a new mock instance.
func NewMockPKT(ctrl *gomock.Controller) *MockPKT {
	mock := &MockPKT{ctrl: ctrl}
	mock.recorder = &MockPKTMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockPKT) EXPECT() *MockPKTMockRecorder {
	return m.recorder
}

// Decode mocks base method.
func (m *MockPKT) Decode() ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Decode")
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Decode indicates an expected call of Decode.
func (mr *MockPKTMockRecorder) Decode() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Decode", reflect.TypeOf((*MockPKT)(nil).Decode))
}

// Encode mocks base method.
func (m *MockPKT) Encode() ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Encode")
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Encode indicates an expected call of Encode.
func (mr *MockPKTMockRecorder) Encode() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Encode", reflect.TypeOf((*MockPKT)(nil).Encode))
}
