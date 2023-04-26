package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"bou.ke/monkey"
	"github.com/golang/mock/gomock"
	"github.com/lucheng0127/gsec/agent/pkg/pkt"
	"github.com/lucheng0127/gsec/mocks"
	"github.com/lucheng0127/gsec/mocks/mock_net"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/suite"
)

type KeepaliveTestSuite struct {
	suite.Suite
	k         Keepalive
	ctrl      gomock.Controller
	mock_addr mock_net.MockAddr
	mock_sock mock_net.MockPacketConn
}

func (s *KeepaliveTestSuite) SetupTest() {
	ctrl := gomock.NewController(s.T())
	mock_addr := mock_net.NewMockAddr(ctrl)
	mock_sock := mock_net.NewMockPacketConn(ctrl)
	s.ctrl = *ctrl
	s.mock_addr = *mock_addr
	s.mock_sock = *mock_sock

	ctx, cancel := context.WithCancel(context.Background())
	s.k = &NATKeepalive{
		RemoteAddr: mock_addr,
		Interval:   0,
		Cancel:     cancel,
		Ctx:        ctx,
		Sock:       mock_sock,
		Logger:     *logrus.New(),
	}
}

func (s *KeepaliveTestSuite) TearDownTest() {
	s.ctrl.Finish()
}

func (s *KeepaliveTestSuite) TestKeepalive_OK() {
	pktData := []byte("ok")
	mock_pkt := mocks.NewMockPKT(&s.ctrl)
	mock_pkt.EXPECT().Encode().MinTimes(1).Return(pktData, nil)
	monkey.Patch(pkt.NewKeepalivePkt, func() (pkt.PKT, error) {
		return mock_pkt, nil
	})
	s.mock_sock.EXPECT().WriteTo(pktData, s.k.(*NATKeepalive).RemoteAddr).AnyTimes().Return(1, nil)
	s.mock_addr.EXPECT().String().AnyTimes().Return("127.0.0.1:4500")

	go s.k.Start()
	time.Sleep(10 * time.Microsecond)
	s.k.Stop()
}

func (s *KeepaliveTestSuite) TestKeepalive_exit_encode_send_err() {
	pktData := []byte("ok")
	mock_pkt := mocks.NewMockPKT(&s.ctrl)
	encode_fitst_call := mock_pkt.EXPECT().Encode().Times(1)
	encode_calls := mock_pkt.EXPECT().Encode().After(encode_fitst_call)
	encode_fitst_call.Return(make([]byte, 0), errors.New("encode err"))
	encode_calls.AnyTimes().Return(pktData, nil)
	monkey.Patch(pkt.NewKeepalivePkt, func() (pkt.PKT, error) {
		return mock_pkt, nil
	})
	s.mock_addr.EXPECT().String().AnyTimes().Return("127.0.0.1:4500")
	s.mock_sock.EXPECT().WriteTo(pktData, s.k.(*NATKeepalive).RemoteAddr).AnyTimes().Return(0, errors.New("send err"))
	s.k.Start()
}

func (s *KeepaliveTestSuite) TestKeepalive_exit_new_pkt_err() {
	monkey.Patch(pkt.NewKeepalivePkt, func() (pkt.PKT, error) {
		return nil, errors.New("new keepalive pkt err")
	})
	s.mock_addr.EXPECT().String().AnyTimes().Return("127.0.0.1:4500")
	s.k.Start()
}

func TestExampleTestSuite(t *testing.T) {
	suite.Run(t, new(KeepaliveTestSuite))
}
