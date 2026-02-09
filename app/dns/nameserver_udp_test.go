package dns_test

import (
	"context"
	gonet "net"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	. "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	dns_feature "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

var (
	_       dns_feature.SRVResolver = (*ClassicNameServer)(nil)
	_       dns_feature.TXTResolver = (*ClassicNameServer)(nil)
	dest, _                         = net.ParseDestination("udp:114.114.114.114:53")
	dp      routing.Dispatcher      = MockDispatcher{}
)

type MockDispatcher struct{}

func (MockDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	conn, err := new(gonet.Dialer).DialContext(ctx, strings.ToLower(dest.Network.String()), dest.NetAddr())
	if err != nil {
		return nil, err
	}
	return &transport.Link{
		Reader: buf.NewReader(conn),
		Writer: buf.NewWriter(conn),
	}, nil
}

func (MockDispatcher) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	panic("not implemented")
}

func (MockDispatcher) Start() error {
	return nil
}

func (MockDispatcher) Close() error {
	return nil
}

func (MockDispatcher) Type() interface{} {
	return routing.DispatcherType()
}

func withTimeout(t *testing.T, timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx := context.WithValue(t.Context(), core.XrayKey(1), new(core.Instance))
	return context.WithTimeout(ctx, timeout)
}

func TestClassicNameServer(t *testing.T) {
	s := NewClassicNameServer(dest, dp, false, net.IP(nil))
	ctx, cancel := withTimeout(t, time.Second*5)
	ips, _, err := s.QueryIP(ctx, "google.com", dns_feature.IPOption{
		IPv4Enable: true,
		IPv6Enable: true,
	})
	cancel()
	common.Must(err)
	if len(ips) == 0 {
		t.Error("expect some ips, but got 0")
	}
}

func TestClassicNameServerWithCache(t *testing.T) {
	s := NewClassicNameServer(dest, dp, false, net.IP(nil))
	ctx, cancel := withTimeout(t, time.Second*5)
	ips, _, err := s.QueryIP(ctx, "google.com", dns_feature.IPOption{
		IPv4Enable: true,
		IPv6Enable: true,
	})
	cancel()
	common.Must(err)
	if len(ips) == 0 {
		t.Error("expect some ips, but got 0")
	}

	ctx2, cancel := context.WithTimeout(context.Background(), time.Second*5)
	ips2, _, err := s.QueryIP(ctx2, "google.com", dns_feature.IPOption{
		IPv4Enable: true,
		IPv6Enable: true,
	})
	cancel()
	common.Must(err)
	if r := cmp.Diff(ips2, ips); r != "" {
		t.Fatal(r)
	}
}

func TestClassicNameServerWithIPv4Override(t *testing.T) {
	s := NewClassicNameServer(dest, dp, false, net.IP(nil))
	ctx, cancel := withTimeout(t, time.Second*5)
	ips, _, err := s.QueryIP(ctx, "google.com", dns_feature.IPOption{
		IPv4Enable: true,
		IPv6Enable: false,
	})
	cancel()
	common.Must(err)

	if len(ips) == 0 {
		t.Error("expect some ips, but got 0")
	}

	for _, ip := range ips {
		if len(ip) != net.IPv4len {
			t.Error("expect only IPv4 response from DNS query")
		}
	}
}

func TestClassicNameServerWithIPv6Override(t *testing.T) {
	s := NewClassicNameServer(dest, dp, false, net.IP(nil))
	ctx, cancel := withTimeout(t, time.Second*5)
	ips, _, err := s.QueryIP(ctx, "google.com", dns_feature.IPOption{
		IPv4Enable: false,
		IPv6Enable: true,
	})
	cancel()
	common.Must(err)

	if len(ips) == 0 {
		t.Error("expect some ips, but got 0")
	}

	for _, ip := range ips {
		if len(ip) != net.IPv6len {
			t.Error("expect only IPv6 response from DNS query")
		}
	}
}

func TestClassicNameServerSRV(t *testing.T) {
	s := NewClassicNameServer(dest, dp, false, net.IP(nil))
	ctx, cancel := withTimeout(t, time.Second*5)
	// lookup SRV for jabber.org which commonly publishes XMPP SRV records
	cname, srvs, err := s.LookupSRV(ctx, "xmpp-server", "tcp", "jabber.org")
	cancel()
	common.Must(err)
	if len(cname) == 0 {
		t.Fatal("expected SRV records for jabber.org, but got no cname")
	}
	if len(srvs) == 0 {
		t.Fatal("expected SRV records for jabber.org, but got 0")
	}
	for _, r := range srvs {
		if r.Target == "" {
			t.Fatal("SRV record has empty target")
		}
	}
}

func TestClassicNameServerTXT(t *testing.T) {
	s := NewClassicNameServer(dest, dp, false, net.IP(nil))
	ctx, cancel := withTimeout(t, time.Second*5)
	txts, err := s.LookupTXT(ctx, "google.com")
	cancel()
	common.Must(err)
	if len(txts) == 0 {
		t.Error("expect some TXT records for google.com, but got 0")
	}
}
