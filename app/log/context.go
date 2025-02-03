package log

import (
	"context"

	_ "unsafe"

	log "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/core"
)

//go:linkname loggerFromContext github.com/xtls/xray-core/common/errors.loggerFromContext
func loggerFromContext(ctx context.Context) log.Handler {
	i := core.FromContext(ctx)
	if i == nil {
		return nil
	}
	logger := i.GetFeature((*Instance)(nil))
	if logger == nil {
		return nil
	}
	return logger.(log.Handler)
}
