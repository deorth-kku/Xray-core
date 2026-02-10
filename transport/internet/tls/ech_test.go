package tls_test

import (
	"context"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"

	_ "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/core"
	. "github.com/xtls/xray-core/transport/internet/tls"
)

func TestECHDial(t *testing.T) {
	config := &Config{
		ServerName:    "cloudflare.com",
		EchConfigList: "encryptedsni.com+https://v2maker.deorth.xyz/cfdns", // for anyone who is seeing this, feel free to try my doh server. :)
	}
	// test concurrent Dial(to test cache problem)
	ctx := context.WithValue(t.Context(), core.XrayKey(1), new(core.Instance))
	wg := sync.WaitGroup{}
	for range 10 {
		wg.Go(func() {
			TLSConfig := config.GetTLSConfig(ctx)
			TLSConfig.NextProtos = []string{"http/1.1"}
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: TLSConfig,
				},
			}
			resp, err := client.Get("https://cloudflare.com/cdn-cgi/trace")
			common.Must(err)
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			common.Must(err)
			if !strings.Contains(string(body), "sni=encrypted") {
				t.Error("ECH Dial success but SNI is not encrypted")
			}
		})
	}
	wg.Wait()
}

func TestECHDialFail(t *testing.T) {
	config := &Config{
		ServerName:    "cloudflare.com",
		EchConfigList: "udp://127.0.0.1",
		EchForceQuery: "full",
	}
	cfg := config.GetTLSConfig(t.Context())
	if !reflect.DeepEqual(cfg.EncryptedClientHelloConfigList, []byte{1, 1, 4, 5, 1, 4}) {
		t.Error("failed to set fake echconfig")
	}
}
