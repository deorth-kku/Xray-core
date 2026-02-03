//go:build !android || cgo

package internet

import (
	"context"
	gonet "net"
)

func getResolver(_ context.Context, _ string) *gonet.Resolver {
	return gonet.DefaultResolver
}
