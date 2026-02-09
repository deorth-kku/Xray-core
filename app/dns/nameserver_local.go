package dns

import (
	"context"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/dns/localdns"
)

// LocalNameServer is an wrapper over local DNS feature.
type LocalNameServer = localdns.Client

// NewLocalNameServer creates localdns server object for directly lookup in system DNS.
func NewLocalNameServer() *LocalNameServer {
	errors.LogInfo(context.Background(), "DNS: created localhost client")
	return localdns.New()
}

// NewLocalDNSClient creates localdns client object for directly lookup in system DNS.
func NewLocalDNSClient(ipOption dns.IPOption) *Client {
	return &Client{server: NewLocalNameServer(), ipOption: &ipOption}
}
