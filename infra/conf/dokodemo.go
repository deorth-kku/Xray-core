package conf

import (
	"github.com/xtls/xray-core/proxy/dokodemo"
	"google.golang.org/protobuf/proto"
)

type DokodemoConfig struct {
	Host        *Address     `json:"address,omitzero"`
	PortValue   uint16       `json:"port,omitzero"`
	NetworkList *NetworkList `json:"network,omitzero"`
	Redirect    bool         `json:"followRedirect,omitzero"`
	UserLevel   uint32       `json:"userLevel,omitzero"`
}

func (v *DokodemoConfig) Build() (proto.Message, error) {
	config := new(dokodemo.Config)
	if v.Host != nil {
		config.Address = v.Host.Build()
	}
	config.Port = uint32(v.PortValue)
	config.Networks = v.NetworkList.Build()
	config.FollowRedirect = v.Redirect
	config.UserLevel = v.UserLevel
	return config, nil
}
