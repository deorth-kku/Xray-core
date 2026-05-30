package localdns

import (
	"context"
	"time"

	"context"
	"syscall"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/transport/internet"
)

// Client is an implementation of dns.Client, which queries localhost for DNS.
type Client struct {
	d *net.Dialer
	r *net.Resolver
}

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
	d := &net.Dialer{
		Timeout: time.Second * 16,
		Control: func(network, address string, c syscall.RawConn) error {
			var errs []error
			for _, ctl := range internet.Controllers {
				if err := ctl(network, address, c); err != nil {
					errs = append(errs, err)
				}
			}
			err := errors.Combine(errs...)
			if err != nil {
				errors.LogInfoInner(context.Background(), err, "failed to apply external controller")
			}
			return err
		},
	}

	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return d.DialContext(ctx, network, address)
		},
	}

	return &Client{
		d: d,
		r: r,
	}
}
