package logic

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v4"
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

func (l *LoginLogic) getJwtToken(secretKey string, iat, seconds int64) (string, error) {
	claims := make(jwt.MapClaims)
	claims["exp"] = iat + seconds
	claims["iat"] = iat
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims = claims
	return token.SignedString([]byte(secretKey))
}

func (l *LoginLogic) Login(req *types.LoginRequest) (resp *types.LoginResponse, err error) {
	// Auth
	rsp, err := l.svcCtx.Rpc.Login(l.ctx, &gsecagent.LoginRequest{
		Username: req.Username,
		Password: req.Password,
	})

	if err != nil {
		return nil, err
	}

	// Generate jwt
	jwt, err := l.getJwtToken(
		l.svcCtx.Config.Auth.AccessSecret,
		time.Now().Unix(),
		l.svcCtx.Config.Auth.AccessExpire,
	)

	if err != nil {
		return nil, err
	}

	return &types.LoginResponse{
		Username: rsp.Username,
		Token:    jwt,
		Expire:   l.svcCtx.Config.Auth.AccessExpire,
	}, nil
}
