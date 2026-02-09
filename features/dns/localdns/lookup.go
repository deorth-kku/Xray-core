package localdns

import (
	"context"
	gonet "net"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
)

var (
	_ dns.Resolver    = (*Client)(nil)
	_ dns.SRVResolver = (*Client)(nil)
	_ dns.TXTResolver = (*Client)(nil)

// _ dns.HTTPSResolver = (*Client)(nil)  // it's not safe to query https record on localdns anyway
)

func (*Client) Name() string {
	return "localhost"
}

func (*Client) QueryIP(ctx context.Context, domain string, option dns.IPOption) ([]net.IP, uint32, error) {
	var network string
	switch {
	case option.IPv4Enable && option.IPv6Enable:
		network = "ip"
	case option.IPv4Enable:
		network = "ip4"
	case option.IPv6Enable:
		network = "ip6"
	default:
		return nil, 0, dns.ErrEmptyResponse
	}

	ips, err := gonet.DefaultResolver.LookupIP(ctx, network, domain)
	if err != nil {
		return nil, 0, err
	}
	if len(ips) == 0 {
		return nil, 0, dns.ErrEmptyResponse
	}
	return ips, dns.DefaultTTL, err
}

func (*Client) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return gonet.DefaultResolver.LookupTXT(ctx, name)
}

func (*Client) LookupSRV(ctx context.Context, service string, proto string, name string) (string, []*gonet.SRV, error) {
	return gonet.DefaultResolver.LookupSRV(ctx, service, proto, name)
}
