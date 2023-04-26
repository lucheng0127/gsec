package pkt

const (
	PKT_AUTH_REQ = byte(0x01)
	PKT_AUTH_RSP = byte(0x01 << 1)
	PKT_SA_REQ   = byte(0x01 << 2)
	PKT_SA_RSP   = byte(0x01 << 3)
	PKT_KEEP_NAT = byte(0x01 << 4)
)

type PKT interface {
	Encode() ([]byte, error)
	Decode() ([]byte, error)
}

type KeepalivePkt struct{}

func NewKeepalivePkt() (PKT, error) {
	return nil, nil
}
