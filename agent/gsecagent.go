package main

import (
	"flag"
	"fmt"

	"github.com/lucheng0127/gsec/agent/internal/config"
	"github.com/lucheng0127/gsec/agent/internal/server"
	"github.com/lucheng0127/gsec/agent/internal/svc"
	"github.com/lucheng0127/gsec/protoc/gsecagent"

	"github.com/zeromicro/go-zero/core/conf"
	"github.com/zeromicro/go-zero/core/service"
	"github.com/zeromicro/go-zero/zrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var configFile = flag.String("f", "etc/gsecagent.yaml", "the config file")

func main() {
	flag.Parse()

	var c config.Config
	conf.MustLoad(*configFile, &c)
	ctx := svc.NewServiceContext(c)

	s := zrpc.MustNewServer(c.RpcServerConf, func(grpcServer *grpc.Server) {
		gsecagent.RegisterGsecagentServer(grpcServer, server.NewGsecagentServer(ctx))

		if c.Mode == service.DevMode || c.Mode == service.TestMode {
			reflection.Register(grpcServer)
		}
	})
	defer s.Stop()

	fmt.Printf("Starting rpc server at %s...\n", c.ListenOn)
	s.Start()
}
