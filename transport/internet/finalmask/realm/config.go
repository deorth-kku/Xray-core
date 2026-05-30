package realm

import (
	"context"
	"net"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/hysteria/udphop"
)

func (c *Config) UDP() {}

func (c *Config) WrapPacketConnClient(ctx context.Context, raw net.PacketConn, level int, levelCount int) (net.PacketConn, error) {
	_, ok1 := raw.(*internet.FakePacketConn)
	_, ok2 := raw.(*udphop.UdpHopPacketConn)
	if level != 0 || ok1 || ok2 {
		return nil, errors.New("realm requires being at the outermost level")
	}
	return NewConnClient(ctx, c, raw)
}

func (c *Config) WrapPacketConnServer(ctx context.Context, raw net.PacketConn, level int, levelCount int) (net.PacketConn, error) {
	if level != 0 {
		return nil, errors.New("realm requires being at the outermost level")
	}
	return NewConnServer(ctx, c, raw)
}
