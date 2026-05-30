package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	gonet "net"
	"net/http"
	"net/url"
	"time"

	miekg_dns "github.com/miekg/dns"
	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/dns"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/utils"
	dns_feature "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/net/http2"
)

// DoHNameServer implemented DNS over HTTPS (RFC8484) Wire Format,
// which is compatible with traditional dns over udp(RFC1035),
// thus most of the DOH implementation is copied from udpns.go
type DoHNameServer struct {
	cacheController *CacheController
	echCache        *cacheTable[string, []*miekg_dns.HTTPS]
	httpClient      *http.Client
	dohURL          string
	clientIP        net.IP
}

// NewDoHNameServer creates DOH/DOHL client object for remote/local resolving.
func NewDoHNameServer(url *url.URL, dialtcp DialContext, h2c bool, disableCache bool, serveStale bool, serveExpiredTTL uint32, clientIP net.IP) *DoHNameServer {
	url.Scheme = "https"
	mode := "DOH"
	if dialtcp == nil {
		mode = "DOHL"
		dialtcp = func(ctx context.Context, dest net.Destination) (net.Conn, error) {
			log.Record(&log.AccessMessage{
				From:   "DNS",
				To:     url.String(),
				Status: log.AccessAccepted,
				Detour: "local",
			})
			return internet.DialSystem(ctx, dest, nil)
		}
	}
	errors.LogInfo(context.Background(), "DNS: created ", mode, " client for ", url.String(), ", with h2c ", h2c)
	s := &DoHNameServer{
		cacheController: NewCacheController(mode+"//"+url.Host, disableCache, serveStale, serveExpiredTTL),
		dohURL:          url.String(),
		clientIP:        clientIP,
	}
	if !disableCache {
		s.echCache = NewCacheTable[string, []*miekg_dns.HTTPS]()
	}
	s.httpClient = &http.Client{
		Transport: &http2.Transport{
			IdleConnTimeout: net.ConnIdleTimeout,
			ReadIdleTimeout: net.ChromeH2KeepAlivePeriod,
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				dest, err := net.ParseDestination(network + ":" + addr)
				if err != nil {
					return nil, err
				}
				dnsCtx := toDnsContext(ctx, s.dohURL)
				if h2c {
					dnsCtx = session.ContextWithMitmAlpn11(dnsCtx, false) // for insurance
					dnsCtx = session.ContextWithMitmServerName(dnsCtx, url.Hostname())
				}
				conn, err := dialtcp(ctx, dest)
				if err != nil {
					return nil, err
				}
				if !h2c {
					conn = utls.UClient(conn, &utls.Config{ServerName: url.Hostname()}, utls.HelloChrome_Auto)
					if err := conn.(*utls.UConn).HandshakeContext(ctx); err != nil {
						return nil, err
					}
				}
				return conn, nil
			},
		},
	}
	return s
}

// Name implements Server.
func (s *DoHNameServer) Name() string {
	return s.cacheController.name
}

// IsDisableCache implements Server.
func (s *DoHNameServer) IsDisableCache() bool {
	return s.cacheController.disableCache
}

func (s *DoHNameServer) URL() string {
	return s.dohURL
}

func (s *DoHNameServer) newReqID() uint16 {
	return 0
}

// getCacheController implements CachedNameserver.
func (s *DoHNameServer) getCacheController() *CacheController {
	return s.cacheController
}

// sendQuery implements CachedNameserver.
func (s *DoHNameServer) sendQuery(ctx context.Context, noResponseErrCh chan<- error, fqdn string, option dns_feature.IPOption) {
	errors.LogInfo(ctx, s.Name(), " querying: ", fqdn)

	if s.Name()+"." == "DOH//"+fqdn {
		errors.LogError(ctx, s.Name(), " tries to resolve itself! Use IP or set \"hosts\" instead")
		if noResponseErrCh != nil {
			err := errors.New("tries to resolve itself!", s.Name())
			if option.IPv4Enable {
				noResponseErrCh <- err
			}
			if option.IPv6Enable {
				noResponseErrCh <- err
			}
		}
		return
	}

	// As we don't want our traffic pattern looks like DoH, we use Random-Length Padding instead of Block-Length Padding recommended in RFC 8467
	// Although DoH server like 1.1.1.1 will pad the response to Block-Length 468, at least it is better than no padding for response at all
	reqs, err := buildReqMsgs(fqdn, option, s.newReqID, genEDNS0Options(s.clientIP, int(crypto.RandBetween(100, 300))))
	if err != nil {
		errors.LogErrorInner(ctx, err, "failed to build dns query for ", fqdn)
		if noResponseErrCh != nil {
			if option.IPv4Enable {
				noResponseErrCh <- err
			}
			if option.IPv6Enable {
				noResponseErrCh <- err
			}
		}
		return
	}

	var deadline time.Time
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	} else {
		deadline = time.Now().Add(time.Second * 5)
	}

	for _, req := range reqs {
		go func(r *dnsRequest) {
			// generate new context for each req, using same context
			// may cause reqs all aborted if any one encounter an error
			dnsCtx := ctx

			// reserve internal dns server requested Inbound
			if inbound := session.InboundFromContext(ctx); inbound != nil {
				dnsCtx = session.ContextWithInbound(dnsCtx, inbound)
			}

			dnsCtx = session.ContextWithContent(dnsCtx, &session.Content{
				Protocol:       "https",
				SkipDNSResolve: true,
			})

			// forced to use mux for DOH
			// dnsCtx = session.ContextWithMuxPreferred(dnsCtx, true)

			var cancel context.CancelFunc
			dnsCtx, cancel = context.WithDeadline(dnsCtx, deadline)
			defer cancel()

			b, err := dns.PackMessage(r.msg)
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to pack dns query for ", fqdn)
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}
			resp, err := s.dohRoundTrip(dnsCtx, b.Bytes())
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to retrieve response for ", fqdn)
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}
			rec, err := parseResponse(resp)
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to handle DOH response for ", fqdn)
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}
			s.cacheController.updateRecord(r, rec)
		}(req)
	}
}

func (s *DoHNameServer) dohRoundTrip(ctx context.Context, b []byte) ([]byte, error) {
	body := bytes.NewBuffer(b)
	req, err := http.NewRequest("POST", s.dohURL, body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Accept", "application/dns-message")
	req.Header.Add("Content-Type", "application/dns-message")
	utils.TryDefaultHeadersWith(req.Header, "fetch")
	req.Header.Set("X-Padding", utils.H2Base62Pad(crypto.RandBetween(100, 1000)))

	hc := s.httpClient

	resp, err := hc.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body) // flush resp.Body so that the conn is reusable
		return nil, fmt.Errorf("DOH server returned code %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

func (s *DoHNameServer) LookupHTTPS(ctx context.Context, host string) ([]*miekg_dns.HTTPS, error) {
	return doHttps(ctx, s.dohRoundTrip, host, s.cacheController, s.echCache)
}

func (s *DoHNameServer) LookupSRV(ctx context.Context, service string, proto string, name string) (string, []*gonet.SRV, error) {
	return roundTripper(s.dohRoundTrip).LookupSRV(ctx, service, proto, name)
}

func (s *DoHNameServer) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return roundTripper(s.dohRoundTrip).LookupTXT(ctx, name)
}

// QueryIP implements Server.
func (s *DoHNameServer) QueryIP(ctx context.Context, domain string, option dns_feature.IPOption) ([]net.IP, uint32, error) {
	return queryIP(ctx, s, domain, option)
}
