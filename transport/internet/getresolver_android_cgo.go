//go:build android && !cgo

package internet

import (
	"context"
	gonet "net"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
)

type clientsNamer interface {
	dns.Client
	NameClients(string) []string
}

func getResolver(ctx context.Context, domain string) *gonet.Resolver {
	ins := core.FromContext(ctx)
	if ins == nil {
		return gonet.DefaultResolver
	}
	namer, ok := core.GetFeature[clientsNamer](ins)
	if !ok {
		return gonet.DefaultResolver
	}
	names := namer.NameClients(domain)
	if len(names) == 0 {
		return gonet.DefaultResolver
	}
	for _, name := range names {
		dest, err := net.ParseDestination(strings.ToLower(name))
		if err != nil {
			continue
		}
		if dest.Network != net.Network_UDP {
			continue
		}
		override := dest.Address.String() + ":" + dest.Port.String()
		return &net.Resolver{
			Dial: func(ctx context.Context, network, address string) (gonet.Conn, error) {
				errors.LogDebug(ctx, "override system dns destination: ", address, "->", override)
				return new(gonet.Dialer).DialContext(ctx, network, override)
			},
		}
	}
	return gonet.DefaultResolver
}
