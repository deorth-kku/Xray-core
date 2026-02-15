package dns_test

import (
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
	_ dns_feature.FullResolver = (*DoHNameServer)(nil)
)

func TestDOHNameServer(t *testing.T) {
	url, err := url.Parse("https+local://1.1.1.1/dns-query")
	common.Must(err)

	s := NewDoHNameServer(url, nil, false, false, net.IP(nil))
	ctx, cancel := withTimeout(t, 5*time.Second)
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

func TestDOHNameServerWithCache(t *testing.T) {
	url, err := url.Parse("https+local://1.1.1.1/dns-query")
	common.Must(err)

	s := NewDoHNameServer(url, nil, false, false, net.IP(nil))
	ctx, cancel := withTimeout(t, 5*time.Second)
	ips, _, err := s.QueryIP(ctx, "google.com", dns_feature.IPOption{
		IPv4Enable: true,
		IPv6Enable: true,
	})
	cancel()
	common.Must(err)
	if len(ips) == 0 {
		t.Error("expect some ips, but got 0")
	}

	ctx2, cancel := withTimeout(t, 5*time.Second)
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

func TestDOHNameServerWithIPv4Override(t *testing.T) {
	url, err := url.Parse("https+local://1.1.1.1/dns-query")
	common.Must(err)

	s := NewDoHNameServer(url, nil, false, false, net.IP(nil))
	ctx, cancel := withTimeout(t, 5*time.Second)
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

func TestDOHNameServerWithIPv6Override(t *testing.T) {
	url, err := url.Parse("https+local://1.1.1.1/dns-query")
	common.Must(err)

	s := NewDoHNameServer(url, nil, false, false, net.IP(nil))
	ctx, cancel := withTimeout(t, 5*time.Second)
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

func TestDOHNameServer65(t *testing.T) {
	url, err := url.Parse("https+local://1.1.1.1/dns-query")
	common.Must(err)

	s := NewDoHNameServer(url, nil, false, false, net.IP(nil))
	ctx, cancel := withTimeout(t, 5*time.Second)
	defer cancel()
	rec, err := s.LookupHTTPS(ctx, "cloudflare-ech.com")
	common.Must(err)
	if len(rec) == 0 {
		t.Error("expect some records, but got 0")
	}

	starttime := time.Now()
	rec, err = s.LookupHTTPS(ctx, "cloudflare-ech.com")
	common.Must(err)
	elapsed := time.Since(starttime)
	if elapsed > 10*time.Millisecond {
		t.Error("expected cached response, but took too long: ", elapsed)
	}

	starttime = time.Now()
	ips, _, err := s.QueryIP(ctx, "cloudflare-ech.com", dns_feature.IPOption{
		IPv4Enable: true,
		IPv6Enable: true,
	})
	common.Must(err)
	elapsed = time.Since(starttime)
	if elapsed > 10*time.Millisecond {
		t.Error("expected cached response, but took too long: ", elapsed)
	}
	if len(ips) == 0 {
		t.Error("expect some ips, but got 0")
	}
}

func TestDOHNameServerTXT(t *testing.T) {
	url, err := url.Parse("https+local://1.1.1.1/dns-query")
	common.Must(err)

	s := NewDoHNameServer(url, nil, false, false, net.IP(nil))
	ctx, cancel := withTimeout(t, 5*time.Second)
	txts, err := s.LookupTXT(ctx, "google.com")
	cancel()
	common.Must(err)
	if len(txts) == 0 {
		t.Error("expect some txt records, but got 0")
	}
}

func TestDOHNameServerSRV(t *testing.T) {
	url, err := url.Parse("https+local://1.1.1.1/dns-query")
	common.Must(err)

	s := NewDoHNameServer(url, nil, false, false, net.IP(nil))
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
