package dns

import (
	"context"
	"encoding/binary"
	gonet "net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	dns_feature "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sync/semaphore"
)

// Fqdn normalizes domain make sure it ends with '.'
func Fqdn(domain string) string {
	return dns.Fqdn(domain)
}

type record struct {
	A    *IPRecord
	AAAA *IPRecord
}

// IPRecord is a cacheable item for a resolved domain
type IPRecord struct {
	ReqID     uint16
	IP        []net.IP
	Expire    time.Time
	RCode     dnsmessage.RCode
	RawHeader *dnsmessage.Header
}

func (r *IPRecord) getIPs() ([]net.IP, uint32, error) {
	if r == nil {
		return nil, 0, errRecordNotFound
	}
	untilExpire := time.Until(r.Expire).Seconds()
	if untilExpire <= 0 {
		return nil, 0, errRecordNotFound
	}

	ttl := uint32(untilExpire) + 1
	if ttl == 1 {
		r.Expire = time.Now().Add(time.Second) // To ensure that two consecutive requests get the same result
	}
	if r.RCode != dnsmessage.RCodeSuccess {
		return nil, ttl, dns_feature.RCodeError(r.RCode)
	}
	if len(r.IP) == 0 {
		return nil, ttl, dns_feature.ErrEmptyResponse
	}

	return r.IP, ttl, nil
}

var errRecordNotFound = errors.New("record not found")

type dnsRequest struct {
	reqType dnsmessage.Type
	domain  string
	start   time.Time
	expire  time.Time
	msg     *dnsmessage.Message
}

func genEDNS0Options(clientIP net.IP, padding int) *dnsmessage.Resource {
	if len(clientIP) == 0 && padding == 0 {
		return nil
	}

	const EDNS0SUBNET = 0x8
	const EDNS0PADDING = 0xc

	opt := new(dnsmessage.Resource)
	common.Must(opt.Header.SetEDNS0(1350, 0xfe00, true))
	body := dnsmessage.OPTResource{}
	opt.Body = &body

	if len(clientIP) != 0 {
		var netmask int
		var family uint16

		if len(clientIP) == 4 {
			family = 1
			netmask = 24 // 24 for IPV4, 96 for IPv6
		} else {
			family = 2
			netmask = 96
		}

		b := make([]byte, 4)
		binary.BigEndian.PutUint16(b[0:], family)
		b[2] = byte(netmask)
		b[3] = 0
		switch family {
		case 1:
			ip := clientIP.To4().Mask(net.CIDRMask(netmask, net.IPv4len*8))
			needLength := (netmask + 8 - 1) / 8 // division rounding up
			b = append(b, ip[:needLength]...)
		case 2:
			ip := clientIP.Mask(net.CIDRMask(netmask, net.IPv6len*8))
			needLength := (netmask + 8 - 1) / 8 // division rounding up
			b = append(b, ip[:needLength]...)
		}

		body.Options = append(body.Options,
			dnsmessage.Option{
				Code: EDNS0SUBNET,
				Data: b,
			})
	}

	if padding != 0 {
		body.Options = append(body.Options,
			dnsmessage.Option{
				Code: EDNS0PADDING,
				Data: make([]byte, padding),
			})
	}

	return opt
}

func buildReqMsgs(domain string, option dns_feature.IPOption, reqIDGen func() uint16, reqOpts *dnsmessage.Resource) []*dnsRequest {
	qA := dnsmessage.Question{
		Name:  dnsmessage.MustNewName(domain),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}

	qAAAA := dnsmessage.Question{
		Name:  dnsmessage.MustNewName(domain),
		Type:  dnsmessage.TypeAAAA,
		Class: dnsmessage.ClassINET,
	}

	var reqs []*dnsRequest
	now := time.Now()

	if option.IPv4Enable {
		msg := new(dnsmessage.Message)
		msg.Header.ID = reqIDGen()
		msg.Header.RecursionDesired = true
		msg.Questions = []dnsmessage.Question{qA}
		if reqOpts != nil {
			msg.Additionals = append(msg.Additionals, *reqOpts)
		}
		reqs = append(reqs, &dnsRequest{
			reqType: dnsmessage.TypeA,
			domain:  domain,
			start:   now,
			msg:     msg,
		})
	}

	if option.IPv6Enable {
		msg := new(dnsmessage.Message)
		msg.Header.ID = reqIDGen()
		msg.Header.RecursionDesired = true
		msg.Questions = []dnsmessage.Question{qAAAA}
		if reqOpts != nil {
			msg.Additionals = append(msg.Additionals, *reqOpts)
		}
		reqs = append(reqs, &dnsRequest{
			reqType: dnsmessage.TypeAAAA,
			domain:  domain,
			start:   now,
			msg:     msg,
		})
	}

	return reqs
}

func doHttps(ctx context.Context, r roundTripper, domain string, ipcache *CacheController, echCache *cacheTable[string, []*dns.HTTPS]) ([]*dns.HTTPS, error) {
	if echCache == nil {
		return r.LookupHTTPS(ctx, domain)
	}
	domain = Fqdn(domain)
	return echCache.Compute(ctx, domain, func(ctx context.Context) ([]*dns.HTTPS, time.Duration, error) {
		starttime := time.Now()
		records, rsp, err := r.lookupHTTPSRaw(ctx, domain)
		if err == dns_feature.ErrEmptyResponse {
			// If the response is empty, we still want to cache it to avoid repeated queries for non-existent records.
			return nil, time.Second * dns_feature.DefaultTTL, err
		}
		var ttldur time.Duration
		for _, record := range records {
			if record.Hdr.Ttl != 0 {
				ttldur = time.Duration(record.Hdr.Ttl) * time.Second
			}
			expire := time.Now().Add(ttldur)
			for _, kv := range record.Value {
				switch kv.Key() {
				case dns.SVCB_IPV4HINT:
					ipcache.updateIP(&dnsRequest{
						reqType: dnsmessage.TypeA,
						domain:  domain,
						start:   starttime,
						expire:  expire,
					}, &IPRecord{
						ReqID:  rsp.Id,
						IP:     kv.(*dns.SVCBIPv4Hint).Hint,
						Expire: expire,
						RCode:  dnsmessage.RCode(rsp.Rcode),
					})
				case dns.SVCB_IPV6HINT:
					ipcache.updateIP(&dnsRequest{
						reqType: dnsmessage.TypeAAAA,
						domain:  domain,
						start:   starttime,
						expire:  expire,
					}, &IPRecord{
						ReqID:  rsp.Id,
						IP:     kv.(*dns.SVCBIPv6Hint).Hint,
						Expire: expire,
						RCode:  dnsmessage.RCode(rsp.Rcode),
					})
				}
			}
		}
		return records, ttldur, err
	})
}

// parseResponse parses DNS answers from the returned payload
func parseResponse(payload []byte) (*IPRecord, error) {
	var parser dnsmessage.Parser
	h, err := parser.Start(payload)
	if err != nil {
		return nil, errors.New("failed to parse DNS response").Base(err).AtWarning()
	}
	if err := parser.SkipAllQuestions(); err != nil {
		return nil, errors.New("failed to skip questions in DNS response").Base(err).AtWarning()
	}

	now := time.Now()
	ipRecord := &IPRecord{
		ReqID:     h.ID,
		RCode:     h.RCode,
		Expire:    now.Add(time.Second * dns_feature.DefaultTTL),
		RawHeader: &h,
	}

L:
	for {
		ah, err := parser.AnswerHeader()
		if err != nil {
			if err != dnsmessage.ErrSectionDone {
				errors.LogInfoInner(context.Background(), err, "failed to parse answer section for domain: ", ah.Name.String())
			}
			break
		}

		ttl := ah.TTL
		if ttl == 0 {
			ttl = 1
		}
		expire := now.Add(time.Duration(ttl) * time.Second)
		if ipRecord.Expire.After(expire) {
			ipRecord.Expire = expire
		}

		switch ah.Type {
		case dnsmessage.TypeA:
			ans, err := parser.AResource()
			if err != nil {
				errors.LogInfoInner(context.Background(), err, "failed to parse A record for domain: ", ah.Name)
				break L
			}
			ipRecord.IP = append(ipRecord.IP, net.IPAddress(ans.A[:]).IP())
		case dnsmessage.TypeAAAA:
			ans, err := parser.AAAAResource()
			if err != nil {
				errors.LogInfoInner(context.Background(), err, "failed to parse AAAA record for domain: ", ah.Name)
				break L
			}
			newIP := net.IPAddress(ans.AAAA[:]).IP()
			if len(newIP) == net.IPv6len {
				ipRecord.IP = append(ipRecord.IP, newIP)
			}
		default:
			if err := parser.SkipAnswer(); err != nil {
				errors.LogInfoInner(context.Background(), err, "failed to skip answer")
				break L
			}
			continue
		}
	}

	return ipRecord, nil
}

// toDnsContext create a new background context with parent inbound, session and dns log
func toDnsContext(ctx context.Context, addr string) context.Context {
	dnsCtx := core.ToBackgroundDetachedContext(ctx)
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		dnsCtx = session.ContextWithInbound(dnsCtx, inbound)
	}
	dnsCtx = session.ContextWithContent(dnsCtx, session.ContentFromContext(ctx))
	dnsCtx = log.ContextWithAccessMessage(dnsCtx, &log.AccessMessage{
		From:   "DNS",
		To:     addr,
		Status: log.AccessAccepted,
		Reason: "",
	})
	return dnsCtx
}

func linkcc(link *transport.Link) cnc.ConnectionOption {
	cc := common.ChainedClosable{}
	if cw, ok := link.Writer.(common.Closable); ok {
		cc = append(cc, cw)
	}
	if cr, ok := link.Reader.(common.Closable); ok {
		cc = append(cc, cr)
	}
	return cnc.ConnectionOnClose(cc)
}

func cncConn(link *transport.Link) net.Conn {
	return cnc.NewConnection(
		cnc.ConnectionInputMulti(link.Writer),
		cnc.ConnectionOutputMulti(link.Reader),
		linkcc(link),
	)
}

func cncConnUDP(link *transport.Link) net.Conn {
	return &internet.FakePacketConn{
		Conn: cnc.NewConnection(
			cnc.ConnectionInputMulti(link.Writer),
			cnc.ConnectionOutputMultiUDP(link.Reader),
			linkcc(link),
		)}
}

type roundTripper func(ctx context.Context, data []byte) ([]byte, error)

func (r roundTripper) roundTrip(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	data, err := msg.Pack()
	if err != nil {
		return nil, err
	}
	data, err = r(ctx, data)
	if err != nil {
		return nil, err
	}
	msg = new(dns.Msg)
	err = msg.Unpack(data)
	return msg, err
}

func (r roundTripper) lookupHTTPSRaw(ctx context.Context, host string) ([]*dns.HTTPS, *dns.Msg, error) {
	rsp, err := r.roundTrip(ctx, new(dns.Msg).SetQuestion(dns.CanonicalName(host), dns.TypeHTTPS))
	if err != nil {
		return nil, nil, err
	}
	var records []*dns.HTTPS
	for _, answer := range rsp.Answer {
		if a, ok := answer.(*dns.HTTPS); ok {
			records = append(records, a)
		}
	}
	if len(records) == 0 {
		return nil, rsp, dns_feature.ErrEmptyResponse
	}
	return records, rsp, nil
}

func (r roundTripper) LookupHTTPS(ctx context.Context, host string) ([]*dns.HTTPS, error) {
	records, _, err := r.lookupHTTPSRaw(ctx, host)
	return records, err
}

func (r roundTripper) LookupSRV(ctx context.Context, service string, proto string, name string) (string, []*gonet.SRV, error) {
	qname := "_" + service + "._" + proto + "." + name
	rsp, err := r.roundTrip(ctx, new(dns.Msg).SetQuestion(dns.CanonicalName(qname), dns.TypeSRV))
	if err != nil {
		return "", nil, err
	}
	var records []*gonet.SRV
	var cname string
	for _, answer := range rsp.Answer {
		switch rr := answer.(type) {
		case *dns.CNAME:
			// keep last CNAME if present
			cname = rr.Target
		case *dns.SRV:
			records = append(records, &gonet.SRV{
				Target:   rr.Target,
				Port:     uint16(rr.Port),
				Priority: rr.Priority,
				Weight:   rr.Weight,
			})
		}
	}
	if len(records) == 0 {
		return cname, nil, dns_feature.ErrEmptyResponse
	}
	return cname, records, nil
}

func (r roundTripper) LookupTXT(ctx context.Context, name string) ([]string, error) {
	rsp, err := r.roundTrip(ctx, new(dns.Msg).SetQuestion(dns.CanonicalName(name), dns.TypeTXT))
	if err != nil {
		return nil, err
	}
	var txts []string
	for _, answer := range rsp.Answer {
		if t, ok := answer.(*dns.TXT); ok {
			txts = append(txts, strings.Join(t.Txt, ""))
		}
	}
	if len(txts) == 0 {
		return nil, dns_feature.ErrEmptyResponse
	}
	return txts, nil
}

type DialContext = func(ctx context.Context, dest net.Destination) (net.Conn, error)

func DispatcherDial(dispatcher routing.Dispatcher) DialContext {
	return func(ctx context.Context, dest net.Destination) (net.Conn, error) {
		link, err := dispatcher.Dispatch(ctx, dest)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		if err != nil {
			return nil, err
		}
		if dest.Network == net.Network_UDP {
			return cncConnUDP(link), nil
		}
		return cncConn(link), nil
	}
}

type cacheLine[T any] struct {
	data  T
	err   error
	sem   semaphore.Weighted
	timer *time.Timer
}

type cacheTable[K comparable, V any] struct {
	table map[K]*cacheLine[V]
	mu    sync.Mutex
}

// NewCacheTable creates a new cache table
func NewCacheTable[K comparable, V any]() *cacheTable[K, V] {
	return &cacheTable[K, V]{
		table: make(map[K]*cacheLine[V]),
	}
}

// fn should return the new value and TTL duration.
// Multiple concurrent calls with the same key will only execute fn once.
// Even if fn returns an error, the value will be updated.
// If TTL is 0 or negative, the entry will be deleted.
func (tb *cacheTable[K, V]) Compute(
	ctx context.Context,
	key K,
	fn func(ctx context.Context) (V, time.Duration, error),
) (V, error) {
	tb.mu.Lock()
	line, found := tb.table[key]
	if !found {
		line = &cacheLine[V]{
			sem: *semaphore.NewWeighted(1),
		}
		tb.table[key] = line
	}
	tb.mu.Unlock()

	// Wait for the ongoing computation if there is one
	if err := line.sem.Acquire(ctx, 1); err != nil {
		var zero V
		return zero, err
	}
	defer line.sem.Release(1)

	if line.timer != nil {
		return line.data, line.err
	}
	var ttl time.Duration
	line.data, ttl, line.err = fn(ctx)
	if ttl > 0 {
		line.timer = time.AfterFunc(ttl, func() {
			tb.mu.Lock()
			if tb.table[key] == line {
				delete(tb.table, key)
			}
			tb.mu.Unlock()
		})
	} else {
		tb.mu.Lock()
		delete(tb.table, key)
		tb.mu.Unlock()
	}
	return line.data, line.err
}
