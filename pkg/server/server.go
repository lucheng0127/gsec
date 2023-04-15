package server

import "net"

type Server struct {
	UserBook map[string]string
	Sock     net.UDPConn
}
