package tls

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"sync"
	_ "unsafe"

	"github.com/xtls/reality"
	"github.com/xtls/xray-core/core"

	"github.com/miekg/dns"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	featdns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/crypto/cryptobyte"
)

type Namer interface {
	Name() string
}

func urlOverName(namer Namer) string {
	if urler, ok := namer.(interface {
		URL() string
	}); ok {
		return urler.URL()
	}
	return namer.Name()
}

type DialContext = func(ctx context.Context, dest net.Destination) (net.Conn, error)

var (
	globalServers    = map[string]featdns.HTTPSResolver{}
	globalServerLock sync.Mutex
)

//go:linkname newServer github.com/xtls/xray-core/app/dns.NewServerFromString
func newServer(ctx context.Context, urlstr string, dialer DialContext, disableCache bool, clientIP net.IP) (featdns.FullResolver, error)

func getHTTPSResolver(ctx context.Context, url string, sockopt *internet.SocketConfig) (featdns.HTTPSResolver, error) {
	globalServerLock.Lock()
	defer globalServerLock.Unlock()
	rs, ok := globalServers[url]
	if ok {
		return rs, nil
	}
	if sockopt == nil {
		sockopt = new(internet.SocketConfig)
	}
	rs, err := newServer(ctx, url, func(ctx context.Context, dest net.Destination) (net.Conn, error) {
		return internet.DialSystem(ctx, dest, sockopt)
	}, false, nil)
	if err != nil {
		return nil, err
	}
	globalServers[url] = rs
	return rs, nil
}

func ApplyECH(ctx context.Context, c *Config, config *tls.Config) error {
	var ECHConfig []byte
	var err error

	// for server
	if len(c.EchServerKeys) != 0 {
		KeySets, err := ConvertToGoECHKeys(c.EchServerKeys)
		if err != nil {
			errors.LogErrorInner(ctx, err, "Failed to unmarshal ECHKeySetList")
		}
		config.EncryptedClientHelloKeys = KeySets
	}

	// for client
	if len(c.EchConfigList) != 0 {
		defer func() {
			// if failed to get ECHConfig, use an invalid one to make connection fail
			if err != nil || len(ECHConfig) == 0 {
				if c.EchForceQuery == "full" {
					ECHConfig = []byte{1, 1, 4, 5, 1, 4}
					errors.LogErrorInner(ctx, err, "cannot apply ech")
				} else {
					errors.LogInfoInner(ctx, err, "cannot apply ech")
				}
			}
			config.EncryptedClientHelloConfigList = ECHConfig
		}()

		if strings.Contains(c.EchConfigList, "://") {
			var nameToQuery string
			if net.ParseAddress(config.ServerName).Family().IsDomain() {
				nameToQuery = config.ServerName
			}
			DNSServer := c.EchConfigList
			schema, _, _ := strings.Cut(c.EchConfigList, "://")
			nameOverride, _, ok := strings.Cut(schema, "+")
			if ok {
				nameToQuery = nameOverride
				DNSServer = c.EchConfigList[len(nameOverride)+1:]
			}
			var resolver featdns.HTTPSResolver
			if c.EchSocketSettings == nil { // prefer using global server when sockopt is set
				for _, s := range core.GetResolverFromContext[featdns.HTTPSResolver](ctx, nameToQuery) {
					if urlOverName(s) == DNSServer {
						resolver = s
						break
					}
				}
			}

			if resolver == nil {
				resolver, err = getHTTPSResolver(ctx, DNSServer, c.EchSocketSettings)
				if err != nil {
					err = errors.New("Failed go get HTTPSResolver").Base(err)
					return err
				}
			}
			rsp, err := resolver.LookupHTTPS(ctx, nameToQuery)
			if err != nil {
				err = errors.New("Failed to query ECH DNS record for domain: ", nameToQuery, " at server: ", DNSServer).Base(err)
				return err
			}
			for _, answer := range rsp {
				if answer.Hdr.Name != dns.Fqdn(nameToQuery) {
					continue
				}
				for _, v := range answer.Value {
					if echConfig, ok := v.(*dns.SVCBECHConfig); ok {
						errors.LogDebug(ctx, "Get ECH config:", echConfig.String(), " TTL:", answer.Hdr.Ttl)
						ECHConfig = echConfig.ECH
						return err
					}
				}
			}
		} else { // direct base64 config
			ECHConfig, err = base64.StdEncoding.DecodeString(c.EchConfigList)
			if err != nil {
				err = errors.New("Failed to unmarshal ECHConfigList").Base(err)
				return err
			}
		}
	}
	return nil
}

// reference github.com/OmarTariq612/goech
func MarshalBinary(ech reality.EchConfig) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint16(ech.Version)
	b.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddUint8(ech.ConfigID)
		child.AddUint16(ech.KemID)
		child.AddUint16(uint16(len(ech.PublicKey)))
		child.AddBytes(ech.PublicKey)
		child.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
			for _, cipherSuite := range ech.SymmetricCipherSuite {
				child.AddUint16(cipherSuite.KDFID)
				child.AddUint16(cipherSuite.AEADID)
			}
		})
		child.AddUint8(ech.MaxNameLength)
		child.AddUint8(uint8(len(ech.PublicName)))
		child.AddBytes(ech.PublicName)
		child.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
			for _, extention := range ech.Extensions {
				child.AddUint16(extention.Type)
				child.AddBytes(extention.Data)
			}
		})
	})
	return b.Bytes()
}

var ErrInvalidLen = errors.New("goech: invalid length")

func ConvertToGoECHKeys(data []byte) ([]tls.EncryptedClientHelloKey, error) {
	var keys []tls.EncryptedClientHelloKey
	s := cryptobyte.String(data)
	for !s.Empty() {
		if len(s) < 2 {
			return keys, ErrInvalidLen
		}
		keyLength := int(binary.BigEndian.Uint16(s[:2]))
		if len(s) < keyLength+4 {
			return keys, ErrInvalidLen
		}
		configLength := int(binary.BigEndian.Uint16(s[keyLength+2 : keyLength+4]))
		if len(s) < 2+keyLength+2+configLength {
			return keys, ErrInvalidLen
		}
		child := cryptobyte.String(s[:2+keyLength+2+configLength])
		var sk, config cryptobyte.String
		if !child.ReadUint16LengthPrefixed(&sk) || !child.ReadUint16LengthPrefixed(&config) || !child.Empty() {
			return keys, ErrInvalidLen
		}
		if !s.Skip(2 + keyLength + 2 + configLength) {
			return keys, ErrInvalidLen
		}
		keys = append(keys, tls.EncryptedClientHelloKey{
			Config:     config,
			PrivateKey: sk,
		})
	}
	return keys, nil
}
