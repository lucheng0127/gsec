// Code generated by goctl. DO NOT EDIT.
// Source: gsecagent.proto

package server

import (
	"context"

	"github.com/lucheng0127/gsec/agent/internal/logic"
	"github.com/lucheng0127/gsec/agent/internal/svc"
	"github.com/lucheng0127/gsec/protoc/gsecagent"
)

type GsecagentServer struct {
	svcCtx *svc.ServiceContext
	gsecagent.UnimplementedGsecagentServer
}

func NewGsecagentServer(svcCtx *svc.ServiceContext) *GsecagentServer {
	return &GsecagentServer{
		svcCtx: svcCtx,
	}
}

func (s *GsecagentServer) Login(ctx context.Context, in *gsecagent.LoginRequest) (*gsecagent.LoginResponse, error) {
	l := logic.NewLoginLogic(ctx, s.svcCtx)
	return l.Login(in)
}