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
	dns_feature "github.com/xtls/xray-core/features/dns"
)

var (
	_ dns_feature.HTTPSResolver = (*TCPNameServer)(nil)
	_ dns_feature.SRVResolver   = (*TCPNameServer)(nil)
	_ dns_feature.TXTResolver   = (*TCPNameServer)(nil)
)

func TestTCPLocalNameServer(t *testing.T) {
	url, err := url.Parse("tcp+local://8.8.8.8")
	common.Must(err)
	s, err := NewTCPLocalNameServer(url, false, net.IP(nil))
	common.Must(err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
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

func TestTCPLocalNameServerWithCache(t *testing.T) {
	url, err := url.Parse("tcp+local://8.8.8.8")
	common.Must(err)
	s, err := NewTCPLocalNameServer(url, false, net.IP(nil))
	common.Must(err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
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

func TestTCPLocalNameServerWithIPv4Override(t *testing.T) {
	url, err := url.Parse("tcp+local://8.8.8.8")
	common.Must(err)
	s, err := NewTCPLocalNameServer(url, false, net.IP(nil))
	common.Must(err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
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

func TestTCPLocalNameServerWithIPv6Override(t *testing.T) {
	url, err := url.Parse("tcp+local://8.8.8.8")
	common.Must(err)
	s, err := NewTCPLocalNameServer(url, false, net.IP(nil))
	common.Must(err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
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

func TestTCPLocalNameServer65(t *testing.T) {
	url, err := url.Parse("tcp+local://8.8.8.8")
	common.Must(err)
	s, err := NewTCPLocalNameServer(url, false, net.IP(nil))
	common.Must(err)
	ctx, cancel := withTimeout(t, 5*time.Second)
	rec, err := s.LookupHTTPS(ctx, "google.com")
	cancel()
	common.Must(err)
	if len(rec) == 0 {
		t.Error("expect some records, but got 0")
	}
}

func TestTCPLocalNameServerTXT(t *testing.T) {
	url, err := url.Parse("tcp+local://8.8.8.8")
	common.Must(err)
	s, err := NewTCPLocalNameServer(url, false, net.IP(nil))
	common.Must(err)
	ctx, cancel := withTimeout(t, 5*time.Second)
	txts, err := s.LookupTXT(ctx, "google.com")
	cancel()
	common.Must(err)
	if len(txts) == 0 {
		t.Error("expect some txt records, but got 0")
	}
}

func TestTCPLocalNameServerSRV(t *testing.T) {
	url, err := url.Parse("tcp+local://8.8.8.8")
	common.Must(err)
	s, err := NewTCPLocalNameServer(url, false, net.IP(nil))
	common.Must(err)
	ctx, cancel := withTimeout(t, 5*time.Second)
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
