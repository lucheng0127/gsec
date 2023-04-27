package svc

import (
	"github.com/lucheng0127/gsec/agent/gsecagentclient"
	"github.com/lucheng0127/gsec/api/internal/config"
	"github.com/zeromicro/go-zero/zrpc"
)

type ServiceContext struct {
	Config   config.Config
	Rpc      gsecagentclient.Gsecagent
	UserCell map[string]*CellEntry
}

func NewServiceContext(c config.Config) *ServiceContext {
	return &ServiceContext{
		Config:   c,
		Rpc:      gsecagentclient.NewGsecagent(zrpc.MustNewClient(c.Rpc)),
		UserCell: make(map[string]*CellEntry),
	}
}
