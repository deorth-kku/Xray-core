package log

import (
	"context"

	_ "unsafe"

	log "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/core"
)

//go:linkname loggerFromContext github.com/xtls/xray-core/app/log.loggerFromContext
func loggerFromContext(ctx context.Context) log.Handler {
	logger, ok := core.GetFeatureFromContext[*Instance](ctx)
	if ok {
		return logger
	}
	return nil
}
