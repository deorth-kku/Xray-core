package conf

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/platform/filesystem"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/httpupgrade"
	"github.com/xtls/xray-core/transport/internet/kcp"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/splithttp"
	"github.com/xtls/xray-core/transport/internet/tcp"
	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/internet/websocket"
	"google.golang.org/protobuf/proto"
)

var (
	kcpHeaderLoader = NewJSONConfigLoader(ConfigCreatorCache{
		"none":         func() interface{} { return new(NoOpAuthenticator) },
		"srtp":         func() interface{} { return new(SRTPAuthenticator) },
		"utp":          func() interface{} { return new(UTPAuthenticator) },
		"wechat-video": func() interface{} { return new(WechatVideoAuthenticator) },
		"dtls":         func() interface{} { return new(DTLSAuthenticator) },
		"wireguard":    func() interface{} { return new(WireguardAuthenticator) },
		"dns":          func() interface{} { return new(DNSAuthenticator) },
	}, "type", "")

	tcpHeaderLoader = NewJSONConfigLoader(ConfigCreatorCache{
		"none": func() interface{} { return new(NoOpConnectionAuthenticator) },
		"http": func() interface{} { return new(Authenticator) },
	}, "type", "")
)

type KCPConfig struct {
	Mtu             *uint32         `json:"mtu,omitzero"`
	Tti             *uint32         `json:"tti,omitzero"`
	UpCap           *uint32         `json:"uplinkCapacity,omitzero"`
	DownCap         *uint32         `json:"downlinkCapacity,omitzero"`
	Congestion      *bool           `json:"congestion,omitzero"`
	ReadBufferSize  *uint32         `json:"readBufferSize,omitzero"`
	WriteBufferSize *uint32         `json:"writeBufferSize,omitzero"`
	HeaderConfig    json.RawMessage `json:"header,omitzero"`
	Seed            *string         `json:"seed,omitzero"`
}

// Build implements Buildable.
func (c *KCPConfig) Build() (proto.Message, error) {
	config := new(kcp.Config)

	if c.Mtu != nil {
		mtu := *c.Mtu
		if mtu < 576 || mtu > 1460 {
			return nil, errors.New("invalid mKCP MTU size: ", mtu).AtError()
		}
		config.Mtu = &kcp.MTU{Value: mtu}
	}
	if c.Tti != nil {
		tti := *c.Tti
		if tti < 10 || tti > 100 {
			return nil, errors.New("invalid mKCP TTI: ", tti).AtError()
		}
		config.Tti = &kcp.TTI{Value: tti}
	}
	if c.UpCap != nil {
		config.UplinkCapacity = &kcp.UplinkCapacity{Value: *c.UpCap}
	}
	if c.DownCap != nil {
		config.DownlinkCapacity = &kcp.DownlinkCapacity{Value: *c.DownCap}
	}
	if c.Congestion != nil {
		config.Congestion = *c.Congestion
	}
	if c.ReadBufferSize != nil {
		size := *c.ReadBufferSize
		if size > 0 {
			config.ReadBuffer = &kcp.ReadBuffer{Size: size * 1024 * 1024}
		} else {
			config.ReadBuffer = &kcp.ReadBuffer{Size: 512 * 1024}
		}
	}
	if c.WriteBufferSize != nil {
		size := *c.WriteBufferSize
		if size > 0 {
			config.WriteBuffer = &kcp.WriteBuffer{Size: size * 1024 * 1024}
		} else {
			config.WriteBuffer = &kcp.WriteBuffer{Size: 512 * 1024}
		}
	}
	if len(c.HeaderConfig) > 0 {
		headerConfig, _, err := kcpHeaderLoader.Load(c.HeaderConfig)
		if err != nil {
			return nil, errors.New("invalid mKCP header config.").Base(err).AtError()
		}
		ts, err := headerConfig.(Buildable).Build()
		if err != nil {
			return nil, errors.New("invalid mKCP header config").Base(err).AtError()
		}
		config.HeaderConfig = serial.ToTypedMessage(ts)
	}

	if c.Seed != nil {
		config.Seed = &kcp.EncryptionSeed{Seed: *c.Seed}
	}

	return config, nil
}

type TCPConfig struct {
	HeaderConfig        json.RawMessage `json:"header,omitzero"`
	AcceptProxyProtocol bool            `json:"acceptProxyProtocol,omitzero"`
}

// Build implements Buildable.
func (c *TCPConfig) Build() (proto.Message, error) {
	config := new(tcp.Config)
	if len(c.HeaderConfig) > 0 {
		headerConfig, _, err := tcpHeaderLoader.Load(c.HeaderConfig)
		if err != nil {
			return nil, errors.New("invalid TCP header config").Base(err).AtError()
		}
		ts, err := headerConfig.(Buildable).Build()
		if err != nil {
			return nil, errors.New("invalid TCP header config").Base(err).AtError()
		}
		config.HeaderSettings = serial.ToTypedMessage(ts)
	}
	if c.AcceptProxyProtocol {
		config.AcceptProxyProtocol = c.AcceptProxyProtocol
	}
	return config, nil
}

type WebSocketConfig struct {
	Host                string            `json:"host,omitzero"`
	Path                string            `json:"path,omitzero"`
	Headers             map[string]string `json:"headers,omitzero"`
	AcceptProxyProtocol bool              `json:"acceptProxyProtocol,omitzero"`
	HeartbeatPeriod     uint32            `json:"heartbeatPeriod,omitzero"`
}

// Build implements Buildable.
func (c *WebSocketConfig) Build() (proto.Message, error) {
	path := c.Path
	var ed uint32
	if u, err := url.Parse(path); err == nil {
		if q := u.Query(); q.Get("ed") != "" {
			Ed, _ := strconv.Atoi(q.Get("ed"))
			ed = uint32(Ed)
			q.Del("ed")
			u.RawQuery = q.Encode()
			path = u.String()
		}
	}
	// Priority (client): host > serverName > address
	for k, v := range c.Headers {
		if strings.ToLower(k) == "host" {
			if c.Host == "" {
				c.Host = v
			}
			delete(c.Headers, k)
		}
	}
	config := &websocket.Config{
		Path:                path,
		Host:                c.Host,
		Header:              c.Headers,
		AcceptProxyProtocol: c.AcceptProxyProtocol,
		Ed:                  ed,
		HeartbeatPeriod:     c.HeartbeatPeriod,
	}
	return config, nil
}

type HttpUpgradeConfig struct {
	Host                string            `json:"host,omitzero"`
	Path                string            `json:"path,omitzero"`
	Headers             map[string]string `json:"headers,omitzero"`
	AcceptProxyProtocol bool              `json:"acceptProxyProtocol,omitzero"`
}

// Build implements Buildable.
func (c *HttpUpgradeConfig) Build() (proto.Message, error) {
	path := c.Path
	var ed uint32
	if u, err := url.Parse(path); err == nil {
		if q := u.Query(); q.Get("ed") != "" {
			Ed, _ := strconv.Atoi(q.Get("ed"))
			ed = uint32(Ed)
			q.Del("ed")
			u.RawQuery = q.Encode()
			path = u.String()
		}
	}
	// Priority (client): host > serverName > address
	for k := range c.Headers {
		if strings.ToLower(k) == "host" {
			return nil, errors.New(`"headers" can't contain "host"`)
		}
	}
	config := &httpupgrade.Config{
		Path:                path,
		Host:                c.Host,
		Header:              c.Headers,
		AcceptProxyProtocol: c.AcceptProxyProtocol,
		Ed:                  ed,
	}
	return config, nil
}

type SplitHTTPConfig struct {
	Host                 string            `json:"host,omitzero"`
	Path                 string            `json:"path,omitzero"`
	Mode                 string            `json:"mode,omitzero"`
	Headers              map[string]string `json:"headers,omitzero"`
	XPaddingBytes        Int32Range        `json:"xPaddingBytes,omitzero"`
	NoGRPCHeader         bool              `json:"noGRPCHeader,omitzero"`
	NoSSEHeader          bool              `json:"noSSEHeader,omitzero"`
	ScMaxEachPostBytes   Int32Range        `json:"scMaxEachPostBytes,omitzero"`
	ScMinPostsIntervalMs Int32Range        `json:"scMinPostsIntervalMs,omitzero"`
	ScMaxBufferedPosts   int64             `json:"scMaxBufferedPosts,omitzero"`
	ScStreamUpServerSecs Int32Range        `json:"scStreamUpServerSecs,omitzero"`
	Xmux                 XmuxConfig        `json:"xmux,omitzero"`
	DownloadSettings     *StreamConfig     `json:"downloadSettings,omitzero"`
	Extra                json.RawMessage   `json:"extra,omitzero"`
}

type XmuxConfig struct {
	MaxConcurrency   Int32Range `json:"maxConcurrency,omitzero"`
	MaxConnections   Int32Range `json:"maxConnections,omitzero"`
	CMaxReuseTimes   Int32Range `json:"cMaxReuseTimes,omitzero"`
	HMaxRequestTimes Int32Range `json:"hMaxRequestTimes,omitzero"`
	HMaxReusableSecs Int32Range `json:"hMaxReusableSecs,omitzero"`
	HKeepAlivePeriod int64      `json:"hKeepAlivePeriod,omitzero"`
}

func newRangeConfig(input Int32Range) *splithttp.RangeConfig {
	return &splithttp.RangeConfig{
		From: input.From,
		To:   input.To,
	}
}

// Build implements Buildable.
func (c *SplitHTTPConfig) Build() (proto.Message, error) {
	if c.Extra != nil {
		var extra SplitHTTPConfig
		if err := json.Unmarshal(c.Extra, &extra); err != nil {
			return nil, errors.New(`Failed to unmarshal "extra".`).Base(err)
		}
		extra.Host = c.Host
		extra.Path = c.Path
		extra.Mode = c.Mode
		c = &extra
	}

	switch c.Mode {
	case "":
		c.Mode = "auto"
	case "auto", "packet-up", "stream-up", "stream-one":
	default:
		return nil, errors.New("unsupported mode: " + c.Mode)
	}

	// Priority (client): host > serverName > address
	for k := range c.Headers {
		if strings.ToLower(k) == "host" {
			return nil, errors.New(`"headers" can't contain "host"`)
		}
	}

	if c.XPaddingBytes != (Int32Range{}) && (c.XPaddingBytes.From <= 0 || c.XPaddingBytes.To <= 0) {
		return nil, errors.New("xPaddingBytes cannot be disabled")
	}

	if c.Xmux.MaxConnections.To > 0 && c.Xmux.MaxConcurrency.To > 0 {
		return nil, errors.New("maxConnections cannot be specified together with maxConcurrency")
	}
	if c.Xmux == (XmuxConfig{}) {
		c.Xmux.MaxConcurrency.From = 16
		c.Xmux.MaxConcurrency.To = 32
		c.Xmux.HMaxRequestTimes.From = 600
		c.Xmux.HMaxRequestTimes.To = 900
		c.Xmux.HMaxReusableSecs.From = 1800
		c.Xmux.HMaxReusableSecs.To = 3000
	}

	config := &splithttp.Config{
		Host:                 c.Host,
		Path:                 c.Path,
		Mode:                 c.Mode,
		Headers:              c.Headers,
		XPaddingBytes:        newRangeConfig(c.XPaddingBytes),
		NoGRPCHeader:         c.NoGRPCHeader,
		NoSSEHeader:          c.NoSSEHeader,
		ScMaxEachPostBytes:   newRangeConfig(c.ScMaxEachPostBytes),
		ScMinPostsIntervalMs: newRangeConfig(c.ScMinPostsIntervalMs),
		ScMaxBufferedPosts:   c.ScMaxBufferedPosts,
		ScStreamUpServerSecs: newRangeConfig(c.ScStreamUpServerSecs),
		Xmux: &splithttp.XmuxConfig{
			MaxConcurrency:   newRangeConfig(c.Xmux.MaxConcurrency),
			MaxConnections:   newRangeConfig(c.Xmux.MaxConnections),
			CMaxReuseTimes:   newRangeConfig(c.Xmux.CMaxReuseTimes),
			HMaxRequestTimes: newRangeConfig(c.Xmux.HMaxRequestTimes),
			HMaxReusableSecs: newRangeConfig(c.Xmux.HMaxReusableSecs),
			HKeepAlivePeriod: c.Xmux.HKeepAlivePeriod,
		},
	}

	if c.DownloadSettings != nil {
		if c.Mode == "stream-one" {
			return nil, errors.New(`Can not use "downloadSettings" in "stream-one" mode.`)
		}
		var err error
		if config.DownloadSettings, err = c.DownloadSettings.Build(); err != nil {
			return nil, errors.New(`Failed to build "downloadSettings".`).Base(err)
		}
	}

	return config, nil
}

func readFileOrString(f string, s []string) ([]byte, error) {
	if len(f) > 0 {
		return filesystem.ReadCert(f)
	}
	if len(s) > 0 {
		return []byte(strings.Join(s, "\n")), nil
	}
	return nil, errors.New("both file and bytes are empty.")
}

type TLSCertConfig struct {
	CertFile       string   `json:"certificateFile,omitzero"`
	CertStr        []string `json:"certificate,omitzero"`
	KeyFile        string   `json:"keyFile,omitzero"`
	KeyStr         []string `json:"key,omitzero"`
	Usage          string   `json:"usage,omitzero"`
	OcspStapling   uint64   `json:"ocspStapling,omitzero"`
	OneTimeLoading bool     `json:"oneTimeLoading,omitzero"`
	BuildChain     bool     `json:"buildChain,omitzero"`
}

// Build implements Buildable.
func (c *TLSCertConfig) Build() (*tls.Certificate, error) {
	certificate := new(tls.Certificate)

	cert, err := readFileOrString(c.CertFile, c.CertStr)
	if err != nil {
		return nil, errors.New("failed to parse certificate").Base(err)
	}
	certificate.Certificate = cert
	certificate.CertificatePath = c.CertFile

	if len(c.KeyFile) > 0 || len(c.KeyStr) > 0 {
		key, err := readFileOrString(c.KeyFile, c.KeyStr)
		if err != nil {
			return nil, errors.New("failed to parse key").Base(err)
		}
		certificate.Key = key
		certificate.KeyPath = c.KeyFile
	}

	switch strings.ToLower(c.Usage) {
	case "encipherment":
		certificate.Usage = tls.Certificate_ENCIPHERMENT
	case "verify":
		certificate.Usage = tls.Certificate_AUTHORITY_VERIFY
	case "issue":
		certificate.Usage = tls.Certificate_AUTHORITY_ISSUE
	default:
		certificate.Usage = tls.Certificate_ENCIPHERMENT
	}
	if certificate.KeyPath == "" && certificate.CertificatePath == "" {
		certificate.OneTimeLoading = true
	} else {
		certificate.OneTimeLoading = c.OneTimeLoading
	}
	certificate.OcspStapling = c.OcspStapling
	certificate.BuildChain = c.BuildChain

	return certificate, nil
}

type TLSConfig struct {
	Insecure                             bool             `json:"allowInsecure,omitzero"`
	Certs                                []*TLSCertConfig `json:"certificates,omitzero"`
	ServerName                           string           `json:"serverName,omitzero"`
	ALPN                                 *StringList      `json:"alpn,omitzero"`
	EnableSessionResumption              bool             `json:"enableSessionResumption,omitzero"`
	DisableSystemRoot                    bool             `json:"disableSystemRoot,omitzero"`
	MinVersion                           string           `json:"minVersion,omitzero"`
	MaxVersion                           string           `json:"maxVersion,omitzero"`
	CipherSuites                         string           `json:"cipherSuites,omitzero"`
	Fingerprint                          string           `json:"fingerprint,omitzero"`
	RejectUnknownSNI                     bool             `json:"rejectUnknownSni,omitzero"`
	PinnedPeerCertificateChainSha256     *[]string        `json:"pinnedPeerCertificateChainSha256,omitzero"`
	PinnedPeerCertificatePublicKeySha256 *[]string        `json:"pinnedPeerCertificatePublicKeySha256,omitzero"`
	CurvePreferences                     *StringList      `json:"curvePreferences,omitzero"`
	MasterKeyLog                         string           `json:"masterKeyLog,omitzero"`
	ServerNameToVerify                   string           `json:"serverNameToVerify,omitzero"`
	VerifyPeerCertInNames                []string         `json:"verifyPeerCertInNames,omitzero"`
}

// Build implements Buildable.
func (c *TLSConfig) Build() (proto.Message, error) {
	config := new(tls.Config)
	config.Certificate = make([]*tls.Certificate, len(c.Certs))
	for idx, certConf := range c.Certs {
		cert, err := certConf.Build()
		if err != nil {
			return nil, err
		}
		config.Certificate[idx] = cert
	}
	serverName := c.ServerName
	config.AllowInsecure = c.Insecure
	if len(c.ServerName) > 0 {
		config.ServerName = serverName
	}
	if c.ALPN != nil && len(*c.ALPN) > 0 {
		config.NextProtocol = []string(*c.ALPN)
	}
	if len(config.NextProtocol) > 1 {
		for _, p := range config.NextProtocol {
			if tcp.IsFromMitm(p) {
				return nil, errors.New(`only one element is allowed in "alpn" when using "fromMitm" in it`)
			}
		}
	}
	if c.CurvePreferences != nil && len(*c.CurvePreferences) > 0 {
		config.CurvePreferences = []string(*c.CurvePreferences)
	}
	config.EnableSessionResumption = c.EnableSessionResumption
	config.DisableSystemRoot = c.DisableSystemRoot
	config.MinVersion = c.MinVersion
	config.MaxVersion = c.MaxVersion
	config.CipherSuites = c.CipherSuites
	config.Fingerprint = strings.ToLower(c.Fingerprint)
	if config.Fingerprint != "unsafe" && tls.GetFingerprint(config.Fingerprint) == nil {
		return nil, errors.New(`unknown "fingerprint": `, config.Fingerprint)
	}
	config.RejectUnknownSni = c.RejectUnknownSNI

	if c.PinnedPeerCertificateChainSha256 != nil {
		config.PinnedPeerCertificateChainSha256 = [][]byte{}
		for _, v := range *c.PinnedPeerCertificateChainSha256 {
			hashValue, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				return nil, err
			}
			config.PinnedPeerCertificateChainSha256 = append(config.PinnedPeerCertificateChainSha256, hashValue)
		}
	}

	if c.PinnedPeerCertificatePublicKeySha256 != nil {
		config.PinnedPeerCertificatePublicKeySha256 = [][]byte{}
		for _, v := range *c.PinnedPeerCertificatePublicKeySha256 {
			hashValue, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				return nil, err
			}
			config.PinnedPeerCertificatePublicKeySha256 = append(config.PinnedPeerCertificatePublicKeySha256, hashValue)
		}
	}

	config.MasterKeyLog = c.MasterKeyLog

	if c.ServerNameToVerify != "" {
		return nil, errors.PrintRemovedFeatureError(`"serverNameToVerify"`, `"verifyPeerCertInNames"`)
	}
	config.VerifyPeerCertInNames = c.VerifyPeerCertInNames

	return config, nil
}

type LimitFallback struct {
	AfterBytes       uint64
	BytesPerSec      uint64
	BurstBytesPerSec uint64
}

type REALITYConfig struct {
	MasterKeyLog string          `json:"masterKeyLog,omitzero"`
	Show         bool            `json:"show,omitzero"`
	Target       json.RawMessage `json:"target,omitzero"`
	Dest         json.RawMessage `json:"dest,omitzero"`
	Type         string          `json:"type,omitzero"`
	Xver         uint64          `json:"xver,omitzero"`
	ServerNames  []string        `json:"serverNames,omitzero"`
	PrivateKey   string          `json:"privateKey,omitzero"`
	MinClientVer string          `json:"minClientVer,omitzero"`
	MaxClientVer string          `json:"maxClientVer,omitzero"`
	MaxTimeDiff  uint64          `json:"maxTimeDiff,omitzero"`
	ShortIds     []string        `json:"shortIds,omitzero"`

	LimitFallbackUpload   LimitFallback `json:"limitFallbackUpload,omitzero"`
	LimitFallbackDownload LimitFallback `json:"limitFallbackDownload,omitzero"`

	Fingerprint string `json:"fingerprint,omitzero"`
	ServerName  string `json:"serverName,omitzero"`
	PublicKey   string `json:"publicKey,omitzero"`
	ShortId     string `json:"shortId,omitzero"`
	SpiderX     string `json:"spiderX,omitzero"`
}

func (c *REALITYConfig) Build() (proto.Message, error) {
	config := new(reality.Config)
	config.MasterKeyLog = c.MasterKeyLog
	config.Show = c.Show
	var err error
	if c.Target != nil {
		c.Dest = c.Target
	}
	if c.Dest != nil {
		var i uint16
		var s string
		if err = json.Unmarshal(c.Dest, &i); err == nil {
			s = strconv.Itoa(int(i))
		} else {
			_ = json.Unmarshal(c.Dest, &s)
		}
		if c.Type == "" && s != "" {
			switch s[0] {
			case '@', '/':
				c.Type = "unix"
				if s[0] == '@' && len(s) > 1 && s[1] == '@' && (runtime.GOOS == "linux" || runtime.GOOS == "android") {
					fullAddr := make([]byte, len(syscall.RawSockaddrUnix{}.Path)) // may need padding to work with haproxy
					copy(fullAddr, s[1:])
					s = string(fullAddr)
				}
			default:
				if _, err = strconv.Atoi(s); err == nil {
					s = "127.0.0.1:" + s
				}
				if _, _, err = net.SplitHostPort(s); err == nil {
					c.Type = "tcp"
				}
			}
		}
		if c.Type == "" {
			return nil, errors.New(`please fill in a valid value for "target"`)
		}
		if c.Xver > 2 {
			return nil, errors.New(`invalid PROXY protocol version, "xver" only accepts 0, 1, 2`)
		}
		if len(c.ServerNames) == 0 {
			return nil, errors.New(`empty "serverNames"`)
		}
		if c.PrivateKey == "" {
			return nil, errors.New(`empty "privateKey"`)
		}
		if config.PrivateKey, err = base64.RawURLEncoding.DecodeString(c.PrivateKey); err != nil || len(config.PrivateKey) != 32 {
			return nil, errors.New(`invalid "privateKey": `, c.PrivateKey)
		}
		if c.MinClientVer != "" {
			config.MinClientVer = make([]byte, 3)
			var u uint64
			for i, s := range strings.Split(c.MinClientVer, ".") {
				if i == 3 {
					return nil, errors.New(`invalid "minClientVer": `, c.MinClientVer)
				}
				if u, err = strconv.ParseUint(s, 10, 8); err != nil {
					return nil, errors.New(`"minClientVer[`, i, `]" should be less than 256`)
				} else {
					config.MinClientVer[i] = byte(u)
				}
			}
		}
		if c.MaxClientVer != "" {
			config.MaxClientVer = make([]byte, 3)
			var u uint64
			for i, s := range strings.Split(c.MaxClientVer, ".") {
				if i == 3 {
					return nil, errors.New(`invalid "maxClientVer": `, c.MaxClientVer)
				}
				if u, err = strconv.ParseUint(s, 10, 8); err != nil {
					return nil, errors.New(`"maxClientVer[`, i, `]" should be less than 256`)
				} else {
					config.MaxClientVer[i] = byte(u)
				}
			}
		}
		if len(c.ShortIds) == 0 {
			return nil, errors.New(`empty "shortIds"`)
		}
		config.ShortIds = make([][]byte, len(c.ShortIds))
		for i, s := range c.ShortIds {
			config.ShortIds[i] = make([]byte, 8)
			if _, err = hex.Decode(config.ShortIds[i], []byte(s)); err != nil {
				return nil, errors.New(`invalid "shortIds[`, i, `]": `, s)
			}
		}
		config.Dest = s
		config.Type = c.Type
		config.Xver = c.Xver
		config.ServerNames = c.ServerNames
		config.MaxTimeDiff = c.MaxTimeDiff

		config.LimitFallbackUpload = new(reality.LimitFallback)
		config.LimitFallbackUpload.AfterBytes = c.LimitFallbackUpload.AfterBytes
		config.LimitFallbackUpload.BytesPerSec = c.LimitFallbackUpload.BytesPerSec
		config.LimitFallbackUpload.BurstBytesPerSec = c.LimitFallbackUpload.BurstBytesPerSec
		config.LimitFallbackDownload = new(reality.LimitFallback)
		config.LimitFallbackDownload.AfterBytes = c.LimitFallbackDownload.AfterBytes
		config.LimitFallbackDownload.BytesPerSec = c.LimitFallbackDownload.BytesPerSec
		config.LimitFallbackDownload.BurstBytesPerSec = c.LimitFallbackDownload.BurstBytesPerSec
	} else {
		config.Fingerprint = strings.ToLower(c.Fingerprint)
		if config.Fingerprint == "unsafe" || config.Fingerprint == "hellogolang" {
			return nil, errors.New(`invalid "fingerprint": `, config.Fingerprint)
		}
		if tls.GetFingerprint(config.Fingerprint) == nil {
			return nil, errors.New(`unknown "fingerprint": `, config.Fingerprint)
		}
		if len(c.ServerNames) != 0 {
			return nil, errors.New(`non-empty "serverNames", please use "serverName" instead`)
		}
		if c.PublicKey == "" {
			return nil, errors.New(`empty "password"`)
		}
		if config.PublicKey, err = base64.RawURLEncoding.DecodeString(c.PublicKey); err != nil || len(config.PublicKey) != 32 {
			return nil, errors.New(`invalid "password": `, c.PublicKey)
		}
		if len(c.ShortIds) != 0 {
			return nil, errors.New(`non-empty "shortIds", please use "shortId" instead`)
		}
		config.ShortId = make([]byte, 8)
		if _, err = hex.Decode(config.ShortId, []byte(c.ShortId)); err != nil {
			return nil, errors.New(`invalid "shortId": `, c.ShortId)
		}
		if c.SpiderX == "" {
			c.SpiderX = "/"
		}
		if c.SpiderX[0] != '/' {
			return nil, errors.New(`invalid "spiderX": `, c.SpiderX)
		}
		config.SpiderY = make([]int64, 10)
		u, _ := url.Parse(c.SpiderX)
		q := u.Query()
		parse := func(param string, index int) {
			if q.Get(param) != "" {
				s := strings.Split(q.Get(param), "-")
				if len(s) == 1 {
					config.SpiderY[index], _ = strconv.ParseInt(s[0], 10, 64)
					config.SpiderY[index+1], _ = strconv.ParseInt(s[0], 10, 64)
				} else {
					config.SpiderY[index], _ = strconv.ParseInt(s[0], 10, 64)
					config.SpiderY[index+1], _ = strconv.ParseInt(s[1], 10, 64)
				}
			}
			q.Del(param)
		}
		parse("p", 0) // padding
		parse("c", 2) // concurrency
		parse("t", 4) // times
		parse("i", 6) // interval
		parse("r", 8) // return
		u.RawQuery = q.Encode()
		config.SpiderX = u.String()
		config.ServerName = c.ServerName
	}
	return config, nil
}

type TransportProtocol string

// Build implements Buildable.
func (p TransportProtocol) Build() (string, error) {
	switch strings.ToLower(string(p)) {
	case "raw", "tcp":
		return "tcp", nil
	case "xhttp", "splithttp":
		return "splithttp", nil
	case "kcp", "mkcp":
		return "mkcp", nil
	case "grpc":
		return "grpc", nil
	case "ws", "websocket":
		return "websocket", nil
	case "httpupgrade":
		return "httpupgrade", nil
	case "h2", "h3", "http":
		return "", errors.PrintRemovedFeatureError("HTTP transport (without header padding, etc.)", "XHTTP stream-one H2 & H3")
	case "quic":
		return "", errors.PrintRemovedFeatureError("QUIC transport (without web service, etc.)", "XHTTP stream-one H3")
	default:
		return "", errors.New("Config: unknown transport protocol: ", p)
	}
}

type CustomSockoptConfig struct {
	Syetem  string `json:"system,omitzero"`
	Network string `json:"network,omitzero"`
	Level   string `json:"level,omitzero"`
	Opt     string `json:"opt,omitzero"`
	Value   string `json:"value,omitzero"`
	Type    string `json:"type,omitzero"`
}

type HappyEyeballsConfig struct {
	PrioritizeIPv6   bool   `json:"prioritizeIPv6,omitzero"`
	TryDelayMs       uint64 `json:"tryDelayMs,omitzero"`
	Interleave       uint32 `json:"interleave,omitzero"`
	MaxConcurrentTry uint32 `json:"maxConcurrentTry,omitzero"`
}

func (h *HappyEyeballsConfig) UnmarshalJSON(data []byte) error {
	var innerHappyEyeballsConfig = struct {
		PrioritizeIPv6   bool   `json:"prioritizeIPv6"`
		TryDelayMs       uint64 `json:"tryDelayMs"`
		Interleave       uint32 `json:"interleave"`
		MaxConcurrentTry uint32 `json:"maxConcurrentTry"`
	}{PrioritizeIPv6: false, Interleave: 1, TryDelayMs: 0, MaxConcurrentTry: 4}
	if err := json.Unmarshal(data, &innerHappyEyeballsConfig); err != nil {
		return err
	}
	h.PrioritizeIPv6 = innerHappyEyeballsConfig.PrioritizeIPv6
	h.TryDelayMs = innerHappyEyeballsConfig.TryDelayMs
	h.Interleave = innerHappyEyeballsConfig.Interleave
	h.MaxConcurrentTry = innerHappyEyeballsConfig.MaxConcurrentTry
	return nil
}

type SocketConfig struct {
	Mark                  int32                  `json:"mark,omitzero"`
	TFO                   interface{}            `json:"tcpFastOpen,omitzero"`
	TProxy                string                 `json:"tproxy,omitzero"`
	AcceptProxyProtocol   bool                   `json:"acceptProxyProtocol,omitzero"`
	DomainStrategy        string                 `json:"domainStrategy,omitzero"`
	DialerProxy           string                 `json:"dialerProxy,omitzero"`
	TCPKeepAliveInterval  int32                  `json:"tcpKeepAliveInterval,omitzero"`
	TCPKeepAliveIdle      int32                  `json:"tcpKeepAliveIdle,omitzero"`
	TCPCongestion         string                 `json:"tcpCongestion,omitzero"`
	TCPWindowClamp        int32                  `json:"tcpWindowClamp,omitzero"`
	TCPMaxSeg             int32                  `json:"tcpMaxSeg,omitzero"`
	Penetrate             bool                   `json:"penetrate,omitzero"`
	TCPUserTimeout        int32                  `json:"tcpUserTimeout,omitzero"`
	V6only                bool                   `json:"v6only,omitzero"`
	Interface             string                 `json:"interface,omitzero"`
	TcpMptcp              bool                   `json:"tcpMptcp,omitzero"`
	CustomSockopt         []*CustomSockoptConfig `json:"customSockopt,omitzero"`
	AddressPortStrategy   string                 `json:"addressPortStrategy,omitzero"`
	HappyEyeballsSettings *HappyEyeballsConfig   `json:"happyEyeballs,omitzero"`
}

// Build implements Buildable.
func (c *SocketConfig) Build() (*internet.SocketConfig, error) {
	tfo := int32(0) // don't invoke setsockopt() for TFO
	if c.TFO != nil {
		switch v := c.TFO.(type) {
		case bool:
			if v {
				tfo = 256
			} else {
				tfo = -1 // TFO need to be disabled
			}
		case float64:
			tfo = int32(math.Min(v, math.MaxInt32))
		default:
			return nil, errors.New("tcpFastOpen: only boolean and integer value is acceptable")
		}
	}
	var tproxy internet.SocketConfig_TProxyMode
	switch strings.ToLower(c.TProxy) {
	case "tproxy":
		tproxy = internet.SocketConfig_TProxy
	case "redirect":
		tproxy = internet.SocketConfig_Redirect
	default:
		tproxy = internet.SocketConfig_Off
	}

	dStrategy := internet.DomainStrategy_AS_IS
	switch strings.ToLower(c.DomainStrategy) {
	case "asis", "":
		dStrategy = internet.DomainStrategy_AS_IS
	case "useip":
		dStrategy = internet.DomainStrategy_USE_IP
	case "useipv4":
		dStrategy = internet.DomainStrategy_USE_IP4
	case "useipv6":
		dStrategy = internet.DomainStrategy_USE_IP6
	case "useipv4v6":
		dStrategy = internet.DomainStrategy_USE_IP46
	case "useipv6v4":
		dStrategy = internet.DomainStrategy_USE_IP64
	case "forceip":
		dStrategy = internet.DomainStrategy_FORCE_IP
	case "forceipv4":
		dStrategy = internet.DomainStrategy_FORCE_IP4
	case "forceipv6":
		dStrategy = internet.DomainStrategy_FORCE_IP6
	case "forceipv4v6":
		dStrategy = internet.DomainStrategy_FORCE_IP46
	case "forceipv6v4":
		dStrategy = internet.DomainStrategy_FORCE_IP64
	default:
		return nil, errors.New("unsupported domain strategy: ", c.DomainStrategy)
	}

	var customSockopts []*internet.CustomSockopt

	for _, copt := range c.CustomSockopt {
		customSockopt := &internet.CustomSockopt{
			System:  copt.Syetem,
			Network: copt.Network,
			Level:   copt.Level,
			Opt:     copt.Opt,
			Value:   copt.Value,
			Type:    copt.Type,
		}
		customSockopts = append(customSockopts, customSockopt)
	}

	addressPortStrategy := internet.AddressPortStrategy_None
	switch strings.ToLower(c.AddressPortStrategy) {
	case "none", "":
		addressPortStrategy = internet.AddressPortStrategy_None
	case "srvportonly":
		addressPortStrategy = internet.AddressPortStrategy_SrvPortOnly
	case "srvaddressonly":
		addressPortStrategy = internet.AddressPortStrategy_SrvAddressOnly
	case "srvportandaddress":
		addressPortStrategy = internet.AddressPortStrategy_SrvPortAndAddress
	case "txtportonly":
		addressPortStrategy = internet.AddressPortStrategy_TxtPortOnly
	case "txtaddressonly":
		addressPortStrategy = internet.AddressPortStrategy_TxtAddressOnly
	case "txtportandaddress":
		addressPortStrategy = internet.AddressPortStrategy_TxtPortAndAddress
	default:
		return nil, errors.New("unsupported address and port strategy: ", c.AddressPortStrategy)
	}

	var happyEyeballs = &internet.HappyEyeballsConfig{Interleave: 1, PrioritizeIpv6: false, TryDelayMs: 0, MaxConcurrentTry: 4}
	if c.HappyEyeballsSettings != nil {
		happyEyeballs.PrioritizeIpv6 = c.HappyEyeballsSettings.PrioritizeIPv6
		happyEyeballs.Interleave = c.HappyEyeballsSettings.Interleave
		happyEyeballs.TryDelayMs = c.HappyEyeballsSettings.TryDelayMs
		happyEyeballs.MaxConcurrentTry = c.HappyEyeballsSettings.MaxConcurrentTry
	}

	return &internet.SocketConfig{
		Mark:                 c.Mark,
		Tfo:                  tfo,
		Tproxy:               tproxy,
		DomainStrategy:       dStrategy,
		AcceptProxyProtocol:  c.AcceptProxyProtocol,
		DialerProxy:          c.DialerProxy,
		TcpKeepAliveInterval: c.TCPKeepAliveInterval,
		TcpKeepAliveIdle:     c.TCPKeepAliveIdle,
		TcpCongestion:        c.TCPCongestion,
		TcpWindowClamp:       c.TCPWindowClamp,
		TcpMaxSeg:            c.TCPMaxSeg,
		Penetrate:            c.Penetrate,
		TcpUserTimeout:       c.TCPUserTimeout,
		V6Only:               c.V6only,
		Interface:            c.Interface,
		TcpMptcp:             c.TcpMptcp,
		CustomSockopt:        customSockopts,
		AddressPortStrategy:  addressPortStrategy,
		HappyEyeballs:        happyEyeballs,
	}, nil
}

type StreamConfig struct {
	Address             *Address           `json:"address,omitzero"`
	Port                uint16             `json:"port,omitzero"`
	Network             *TransportProtocol `json:"network,omitzero"`
	Security            string             `json:"security,omitzero"`
	TLSSettings         *TLSConfig         `json:"tlsSettings,omitzero"`
	REALITYSettings     *REALITYConfig     `json:"realitySettings,omitzero"`
	RAWSettings         *TCPConfig         `json:"rawSettings,omitzero"`
	TCPSettings         *TCPConfig         `json:"tcpSettings,omitzero"`
	XHTTPSettings       *SplitHTTPConfig   `json:"xhttpSettings,omitzero"`
	SplitHTTPSettings   *SplitHTTPConfig   `json:"splithttpSettings,omitzero"`
	KCPSettings         *KCPConfig         `json:"kcpSettings,omitzero"`
	GRPCSettings        *GRPCConfig        `json:"grpcSettings,omitzero"`
	WSSettings          *WebSocketConfig   `json:"wsSettings,omitzero"`
	HTTPUPGRADESettings *HttpUpgradeConfig `json:"httpupgradeSettings,omitzero"`
	SocketSettings      *SocketConfig      `json:"sockopt,omitzero"`
}

// Build implements Buildable.
func (c *StreamConfig) Build() (*internet.StreamConfig, error) {
	config := &internet.StreamConfig{
		Port:         uint32(c.Port),
		ProtocolName: "tcp",
	}
	if c.Address != nil {
		config.Address = c.Address.Build()
	}
	if c.Network != nil {
		protocol, err := c.Network.Build()
		if err != nil {
			return nil, err
		}
		config.ProtocolName = protocol
	}
	switch strings.ToLower(c.Security) {
	case "", "none":
	case "tls":
		tlsSettings := c.TLSSettings
		if tlsSettings == nil {
			tlsSettings = &TLSConfig{}
		}
		ts, err := tlsSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build TLS config.").Base(err)
		}
		tm := serial.ToTypedMessage(ts)
		config.SecuritySettings = append(config.SecuritySettings, tm)
		config.SecurityType = tm.Type
	case "reality":
		if config.ProtocolName != "tcp" && config.ProtocolName != "splithttp" && config.ProtocolName != "grpc" {
			return nil, errors.New("REALITY only supports RAW, XHTTP and gRPC for now.")
		}
		if c.REALITYSettings == nil {
			return nil, errors.New(`REALITY: Empty "realitySettings".`)
		}
		ts, err := c.REALITYSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build REALITY config.").Base(err)
		}
		tm := serial.ToTypedMessage(ts)
		config.SecuritySettings = append(config.SecuritySettings, tm)
		config.SecurityType = tm.Type
	case "xtls":
		return nil, errors.PrintRemovedFeatureError(`Legacy XTLS`, `xtls-rprx-vision with TLS or REALITY`)
	default:
		return nil, errors.New(`Unknown security "` + c.Security + `".`)
	}
	if c.RAWSettings != nil {
		c.TCPSettings = c.RAWSettings
	}
	if c.TCPSettings != nil {
		ts, err := c.TCPSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build RAW config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "tcp",
			Settings:     serial.ToTypedMessage(ts),
		})
	}
	if c.XHTTPSettings != nil {
		c.SplitHTTPSettings = c.XHTTPSettings
	}
	if c.SplitHTTPSettings != nil {
		hs, err := c.SplitHTTPSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build XHTTP config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "splithttp",
			Settings:     serial.ToTypedMessage(hs),
		})
	}
	if c.KCPSettings != nil {
		ts, err := c.KCPSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build mKCP config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "mkcp",
			Settings:     serial.ToTypedMessage(ts),
		})
	}
	if c.GRPCSettings != nil {
		gs, err := c.GRPCSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build gRPC config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "grpc",
			Settings:     serial.ToTypedMessage(gs),
		})
	}
	if c.WSSettings != nil {
		ts, err := c.WSSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build WebSocket config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "websocket",
			Settings:     serial.ToTypedMessage(ts),
		})
	}
	if c.HTTPUPGRADESettings != nil {
		hs, err := c.HTTPUPGRADESettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build HTTPUpgrade config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "httpupgrade",
			Settings:     serial.ToTypedMessage(hs),
		})
	}
	if c.SocketSettings != nil {
		ss, err := c.SocketSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build sockopt.").Base(err)
		}
		config.SocketSettings = ss
	}
	return config, nil
}

type ProxyConfig struct {
	Tag string `json:"tag,omitzero"`

	// TransportLayerProxy: For compatibility.
	TransportLayerProxy bool `json:"transportLayer,omitzero"`
}

// Build implements Buildable.
func (v *ProxyConfig) Build() (*internet.ProxyConfig, error) {
	if v.Tag == "" {
		return nil, errors.New("Proxy tag is not set.")
	}
	return &internet.ProxyConfig{
		Tag:                 v.Tag,
		TransportLayerProxy: v.TransportLayerProxy,
	}, nil
}
