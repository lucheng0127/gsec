package logic

import (
	"context"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/lucheng0127/gsec/api/common/errorx"
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
	// Check user cell first
	if !l.svcCtx.CellCheck(req.Username) {
		return nil, errorx.NewCodeError(errorx.AuthForbideCode, "user forbide login right now, please try again 10 seconds later")
	}

	// Auth
	rsp, err := l.svcCtx.Rpc.Login(l.ctx, &gsecagent.LoginRequest{
		Username: req.Username,
		Password: req.Password,
	})

	if err != nil {
		l.svcCtx.CellCalled(req.Username, false)
		errMsg := err.Error()

		if strings.Contains(errMsg, "not exist") {
			return nil, errorx.NewCodeError(errorx.AuthUserNotExistCode, errMsg)
		}
		if strings.Contains(errMsg, "wrong one time passwd") {
			return nil, errorx.NewCodeError(errorx.AuthPasswordNotMatchCode, errMsg)
		}

		return nil, errorx.NewCodeError(errorx.AuthDefaultCode, errMsg)
	}

	// Generate jwt
	jwt, err := l.getJwtToken(
		l.svcCtx.Config.Auth.AccessSecret,
		time.Now().Unix(),
		l.svcCtx.Config.Auth.AccessExpire,
	)

	if err != nil {
		l.svcCtx.CellCalled(req.Username, false)
		return nil, errorx.NewCodeError(errorx.AuthJWTGenerateErrCode, err.Error())
	}

	l.svcCtx.CellCalled(req.Username, true)
	return &types.LoginResponse{
		Username: rsp.Username,
		Token:    jwt,
		Expire:   l.svcCtx.Config.Auth.AccessExpire,
	}, nil
}
