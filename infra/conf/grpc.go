package conf

import (
	"github.com/xtls/xray-core/transport/internet/grpc"
	"google.golang.org/protobuf/proto"
)

type GRPCConfig struct {
	Authority           string `json:"authority,omitzero"`
	ServiceName         string `json:"serviceName,omitzero"`
	MultiMode           bool   `json:"multiMode,omitzero"`
	IdleTimeout         int32  `json:"idle_timeout,omitzero"`
	HealthCheckTimeout  int32  `json:"health_check_timeout,omitzero"`
	PermitWithoutStream bool   `json:"permit_without_stream,omitzero"`
	InitialWindowsSize  int32  `json:"initial_windows_size,omitzero"`
	UserAgent           string `json:"user_agent,omitzero"`
}

func (g *GRPCConfig) Build() (proto.Message, error) {
	if g.IdleTimeout <= 0 {
		g.IdleTimeout = 0
	}
	if g.HealthCheckTimeout <= 0 {
		g.HealthCheckTimeout = 0
	}
	if g.InitialWindowsSize < 0 {
		// default window size of gRPC-go
		g.InitialWindowsSize = 0
	}

	return &grpc.Config{
		Authority:           g.Authority,
		ServiceName:         g.ServiceName,
		MultiMode:           g.MultiMode,
		IdleTimeout:         g.IdleTimeout,
		HealthCheckTimeout:  g.HealthCheckTimeout,
		PermitWithoutStream: g.PermitWithoutStream,
		InitialWindowsSize:  g.InitialWindowsSize,
		UserAgent:           g.UserAgent,
	}, nil
}
