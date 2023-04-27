package logic

import (
	"context"

	"github.com/lucheng0127/gsec/api/internal/svc"
	"github.com/lucheng0127/gsec/api/internal/types"

	"github.com/zeromicro/go-zero/core/logx"
)

type IpsecLogic struct {
	logx.Logger
	ctx    context.Context
	svcCtx *svc.ServiceContext
}

func NewIpsecLogic(ctx context.Context, svcCtx *svc.ServiceContext) *IpsecLogic {
	return &IpsecLogic{
		Logger: logx.WithContext(ctx),
		ctx:    ctx,
		svcCtx: svcCtx,
	}
}

func (l *IpsecLogic) Ipsec(req *types.IpsecRequest) (resp *types.IpsecResponse, err error) {
	// TODO: implement it

	return &types.IpsecResponse{Data: []types.IpsecSA{
		{
			ReqID: "111",
			Src:   "src",
			Dst:   "dst",
		},
	}}, nil
}
