package logic

import (
	"context"
	"fmt"

	"github.com/lucheng0127/gsec/agent/internal/svc"
	"github.com/lucheng0127/gsec/agent/pkg/auth"
	"github.com/lucheng0127/gsec/protoc/gsecagent"

	"github.com/zeromicro/go-zero/core/logx"
)

type LoginLogic struct {
	ctx    context.Context
	svcCtx *svc.ServiceContext
	logx.Logger
}

func NewLoginLogic(ctx context.Context, svcCtx *svc.ServiceContext) *LoginLogic {
	return &LoginLogic{
		ctx:    ctx,
		svcCtx: svcCtx,
		Logger: logx.WithContext(ctx),
	}
}

func (l *LoginLogic) Login(in *gsecagent.LoginRequest) (*gsecagent.LoginResponse, error) {
	// Check user exist
	secret, ok := l.svcCtx.Config.Users[in.Username]
	if !ok {
		return nil, fmt.Errorf("user [%s] not exist", in.Username)
	}

	// Validate password
	totpAuth := auth.NewTOTPAuth(in.Username, secret)
	isValid, err := totpAuth.Validate([]byte(in.Password))
	if err != nil {
		return nil, err
	}

	if !isValid {
		return nil, fmt.Errorf("password of user [%s] not match", in.Username)
	}

	return &gsecagent.LoginResponse{
		Username: in.Username,
	}, nil
}
