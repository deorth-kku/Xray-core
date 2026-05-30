package localdns

import (
	"context"
	"net"
	"syscall"
	"time"
	_ "unsafe"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/features/dns"
)

// Client is an implementation of dns.Client, which queries localhost for DNS.
type Client struct {
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

//go:linkname Controllers github.com/xtls/xray-core/transport/internet.Controllers
var Controllers []func(network, address string, c syscall.RawConn) error

// New create a new dns.Client that queries localhost for DNS.
func New() *Client {
	if len(Controllers) == 0 {
		return &Client{
			r: net.DefaultResolver,
		}
	}
	d := &net.Dialer{
		Timeout: time.Second * 16,
		Control: func(network, address string, c syscall.RawConn) error {
			var errs []error
			for _, ctl := range Controllers {
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

	return &Client{
		r: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return d.DialContext(ctx, network, address)
			},
		},
	}
}

func (*Client) IsDisableCache() bool {
	return true
}
