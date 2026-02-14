package dns_test

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	. "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	dns_feature "github.com/xtls/xray-core/features/dns"
)

var (
	_ dns_feature.FullResolver = (*QUICNameServer)(nil)
)

func TestQUICNameServer(t *testing.T) {
	url, err := url.Parse("quic://dns.nextdns.io")
	common.Must(err)
	s, err := NewQUICNameServer(url, false, net.IP(nil))
	common.Must(err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	ips, _, err := s.QueryIP(ctx, "google.com", dns.IPOption{
		IPv4Enable: true,
		IPv6Enable: true,
	})
	cancel()
	common.Must(err)
	if len(ips) == 0 {
		t.Error("expect some ips, but got 0")
	}
	ctx2, cancel := context.WithTimeout(context.Background(), time.Second*5)
	ips2, _, err := s.QueryIP(ctx2, "google.com", dns.IPOption{
		IPv4Enable: true,
		IPv6Enable: true,
	})
	cancel()
	common.Must(err)
	if r := cmp.Diff(ips2, ips); r != "" {
		t.Fatal(r)
	}
}

func TestQUICNameServerWithIPv4Override(t *testing.T) {
	url, err := url.Parse("quic://dns.nextdns.io")
	common.Must(err)
	s, err := NewQUICNameServer(url, false, net.IP(nil))
	common.Must(err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	ips, _, err := s.QueryIP(ctx, "google.com", dns.IPOption{
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

func TestQUICNameServerWithIPv6Override(t *testing.T) {
	url, err := url.Parse("quic://dns.nextdns.io")
	common.Must(err)
	s, err := NewQUICNameServer(url, false, net.IP(nil))
	common.Must(err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	ips, _, err := s.QueryIP(ctx, "google.com", dns.IPOption{
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

func TestQUICNameServer65(t *testing.T) {
	url, err := url.Parse("quic://dns.nextdns.io")
	common.Must(err)
	s, err := NewQUICNameServer(url, false, net.IP(nil))
	common.Must(err)
	ctx, cancel := withTimeout(t, 5*time.Second)
	rec, err := s.LookupHTTPS(ctx, "google.com")
	cancel()
	common.Must(err)
	if len(rec) == 0 {
		t.Error("expect some records, but got 0")
	}
}

func TestQUICNameServerTXT(t *testing.T) {
	url, err := url.Parse("quic://dns.nextdns.io")
	common.Must(err)
	s, err := NewQUICNameServer(url, false, net.IP(nil))
	common.Must(err)
	ctx, cancel := withTimeout(t, 5*time.Second)
	txts, err := s.LookupTXT(ctx, "google.com")
	cancel()
	common.Must(err)
	if len(txts) == 0 {
		t.Error("expect some txt records, but got 0")
	}
}

func TestQUICNameServerSRV(t *testing.T) {
	url, err := url.Parse("quic://dns.nextdns.io")
	common.Must(err)
	s, err := NewQUICNameServer(url, false, net.IP(nil))
	common.Must(err)
	ctx, cancel := withTimeout(t, 5*time.Second)
	cname, srvs, err := s.LookupSRV(ctx, "xmpp-server", "tcp", "jabber.org")
	cancel()
	common.Must(err)
	if len(cname) == 0 {
		t.Log("_xmpp-server._tcp.jabber.org. has empty CNAME")
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
