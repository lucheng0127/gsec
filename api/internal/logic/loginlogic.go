package logic

import (
	"context"

	"github.com/lucheng0127/gsec/api/internal/svc"
	"github.com/lucheng0127/gsec/api/internal/types"
	"github.com/lucheng0127/gsec/protoc/gsecagent"

	"github.com/zeromicro/go-zero/core/logx"
)

type LoginLogic struct {
	logx.Logger
	ctx    context.Context
	svcCtx *svc.ServiceContext
}

func NewLoginLogic(ctx context.Context, svcCtx *svc.ServiceContext) *LoginLogic {
	return &LoginLogic{
		Logger: logx.WithContext(ctx),
		ctx:    ctx,
		svcCtx: svcCtx,
	}
}

func (l *LoginLogic) Login(req *types.LoginRequest) (resp *types.LoginResponse, err error) {
	rsp, err := l.svcCtx.Rpc.Login(l.ctx, &gsecagent.LoginRequest{
		Username: req.Username,
		Password: req.Password,
	})

	if err != nil {
		return nil, err
	}

	return &types.LoginResponse{
		Username: rsp.Username,
		Token:    rsp.Token,
		Expire:   rsp.Expire,
	}, nil
}
