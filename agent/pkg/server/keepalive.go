package server

import (
	"context"
	"net"
	"time"

	"github.com/lucheng0127/gsec/agent/pkg/ctx"
	"github.com/lucheng0127/gsec/agent/pkg/pkt"
	"github.com/sirupsen/logrus"
)

type Keepalive interface {
	Start()
	Stop()
}

type NATKeepalive struct {
	RemoteAddr net.Addr
	Interval   int
	Cancel     context.CancelFunc
	Ctx        context.Context
	Sock       net.PacketConn
	Logger     logrus.Logger
}

func (nk *NATKeepalive) Stop() {
	trackId := nk.Ctx.Value(ctx.TrackID)
	if trackId == nil {
		trackId = ctx.DefaultTrackID
	}
	nk.Logger.WithFields(logrus.Fields{
		"ID":     trackId,
		"Remote": nk.RemoteAddr.String(),
	}).Info("keepalive canceled")
	nk.Cancel()
}

func (nk *NATKeepalive) Start() {
	errCnt := 0
	trackId := nk.Ctx.Value(ctx.TrackID)
	if trackId == nil {
		trackId = ctx.DefaultTrackID
	}
	for {
		select {
		case <-nk.Ctx.Done():
			// Keepalive stoped
			nk.Logger.WithFields(logrus.Fields{
				"ID":     trackId,
				"Remote": nk.RemoteAddr.String(),
			}).Info("keepalive stopped")
			return
		default:
			if errCnt > 15 {
				nk.Logger.WithFields(logrus.Fields{
					"ID":     trackId,
					"Remote": nk.RemoteAddr.String(),
				}).Error("after 15 times send keepalive failed, stop it")
				nk.Stop()
			}

			pkt, err := pkt.NewKeepalivePkt()
			if err != nil {
				nk.Logger.WithFields(logrus.Fields{
					"ID":     trackId,
					"Remote": nk.RemoteAddr.String(),
					"Detail": err.Error(),
				}).Error("new keepalive packet error")
				errCnt++
				continue
			}
			keepaliveData, err := pkt.Encode()
			if err != nil {
				nk.Logger.WithFields(logrus.Fields{
					"ID":     trackId,
					"Remote": nk.RemoteAddr.String(),
					"Detail": err.Error(),
				}).Error("keepalive packet encode error")
				errCnt++
				continue
			}

			_, err = nk.Sock.WriteTo(keepaliveData, nk.RemoteAddr)
			if err != nil {
				nk.Logger.WithFields(logrus.Fields{
					"ID":     trackId,
					"Remote": nk.RemoteAddr.String(),
					"Detail": err.Error(),
				}).Error("send keepalive packet error")
				errCnt++
				continue
			}
			time.Sleep(time.Duration(nk.Interval) * time.Second)
		}
	}
}
