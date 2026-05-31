package localdns_test

import (
	"testing"

	_ "github.com/xtls/xray-core/app/log"
	. "github.com/xtls/xray-core/features/dns/localdns"
	"github.com/xtls/xray-core/transport/internet"
)

func TestControllerLink(t *testing.T) {
	internet.Controllers = append(internet.Controllers, nil)
	if len(Controllers) != 1 {
		t.Error("not linked")
	}
}
