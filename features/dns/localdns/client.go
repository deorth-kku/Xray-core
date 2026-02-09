package localdns

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
)

// Client is an implementation of dns.Client, which queries localhost for DNS.
type Client struct{}

// Type implements common.HasType.
func (*Client) Type() interface{} {
	return dns.ClientType()
}

// Start implements common.Runnable.
func (*Client) Start() error { return nil }

// Close implements common.Closable.
func (*Client) Close() error { return nil }

const defaultTimeout = 5 * time.Second

// LookupIP implements Client.
func (c *Client) LookupIP(host string, option dns.IPOption) ([]net.IP, uint32, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	return c.QueryIP(ctx, host, option)
}

// New create a new dns.Client that queries localhost for DNS.
func New() *Client {
	return &Client{}
}
