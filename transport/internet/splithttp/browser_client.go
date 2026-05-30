package splithttp

import (
	"context"
	"io"
	"net/url"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/browser_dialer"
	"github.com/xtls/xray-core/transport/internet/websocket"
)

// BrowserDialerClient implements splithttp.DialerClient in terms of browser dialer
type BrowserDialerClient struct {
	transportConfig *Config
}

func (c *BrowserDialerClient) IsClosed() bool {
	panic("not implemented yet")
}

func (c *BrowserDialerClient) OpenStream(ctx context.Context, url url.URL, sessionId string, body io.Reader, uploadOnly bool) (io.ReadCloser, net.Addr, net.Addr, error) {
	if body != nil {
		return nil, nil, nil, errors.New("bidirectional streaming for browser dialer not implemented yet")
	}
	reqctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stop := context.AfterFunc(ctx, cancel)
	defer stop()
	request := NewRequestWithContext(reqctx, "GET", url, nil, c.transportConfig.GetRequestHeader())

	c.transportConfig.FillStreamRequest(request, sessionId, "")

	conn, err := browser_dialer.DialGet(request.URL.String(), request.Header, request.Cookies())
	dummyAddr := &net.IPAddr{}
	if err != nil {
		return nil, dummyAddr, dummyAddr, err
	}

	return websocket.NewConnection(conn, dummyAddr, nil, 0), conn.RemoteAddr(), conn.LocalAddr(), nil
}

func (c *BrowserDialerClient) PostPacket(ctx context.Context, url url.URL, sessionId string, seqStr string, payload buf.MultiBuffer) error {
	method := c.transportConfig.GetNormalizedUplinkHTTPMethod()
	reqctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stop := context.AfterFunc(ctx, cancel)
	defer stop()
	request := NewRequestWithContext(reqctx, method, url, nil, c.transportConfig.GetRequestHeader())

	err := c.transportConfig.FillPacketRequest(request, sessionId, seqStr, payload)
	if err != nil {
		return err
	}

	var bytes []byte
	if request.Body != nil {
		bytes, err = io.ReadAll(request.Body)
		if err != nil {
			return err
		}
	}

	err = browser_dialer.DialPacket(method, request.URL.String(), request.Header, request.Cookies(), bytes)
	if err != nil {
		return err
	}

	return nil
}
