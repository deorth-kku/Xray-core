package conf

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/dns"
	"google.golang.org/protobuf/proto"
)

type DNSOutboundConfig struct {
	Network    Network  `json:"network,omitzero"`
	Address    *Address `json:"address,omitzero"`
	Port       uint16   `json:"port,omitzero"`
	UserLevel  uint32   `json:"userLevel,omitzero"`
	NonIPQuery string   `json:"nonIPQuery,omitzero"`
	BlockTypes []int32  `json:"blockTypes,omitzero"`
}

func (c *DNSOutboundConfig) Build() (proto.Message, error) {
	config := &dns.Config{
		Server: &net.Endpoint{
			Network: c.Network.Build(),
			Port:    uint32(c.Port),
		},
		UserLevel: c.UserLevel,
	}
	if c.Address != nil {
		config.Server.Address = c.Address.Build()
	}
	switch c.NonIPQuery {
	case "":
		c.NonIPQuery = "drop"
	case "drop", "skip", "reject":
	default:
		return nil, errors.New(`unknown "nonIPQuery": `, c.NonIPQuery)
	}
	config.Non_IPQuery = c.NonIPQuery
	config.BlockTypes = c.BlockTypes
	return config, nil
}
