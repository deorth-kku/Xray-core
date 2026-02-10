package tls

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"io"
	"strings"
	"sync"

	"github.com/xtls/xray-core/core"

	"github.com/miekg/dns"
	"github.com/xtls/reality"
	"github.com/xtls/reality/hpke"
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
	NewServerReg     func(ctx context.Context, urlstr string, dialer DialContext, disableCache bool, clientIP net.IP) (featdns.Resolver, error)
	globalServers    = map[string]featdns.HTTPSResolver{}
	globalServerLock sync.Mutex
)

func getDOHServer(ctx context.Context, url string, sockopt *internet.SocketConfig) (featdns.HTTPSResolver, error) {
	globalServerLock.Lock()
	defer globalServerLock.Unlock()
	rs, ok := globalServers[url]
	if ok {
		return rs, nil
	}
	if NewServerReg == nil {
		return nil, errors.New("app/dns not inited")
	}
	if sockopt == nil {
		sockopt = new(internet.SocketConfig)
	}
	r0, err := NewServerReg(ctx, url, func(ctx context.Context, dest net.Destination) (net.Conn, error) {
		return internet.DialSystem(ctx, dest, sockopt)
	}, false, sockopt.BindAddress)
	if err != nil {
		return nil, err
	}
	if rs, ok = r0.(featdns.HTTPSResolver); !ok {
		return nil, errors.New("dns server doesn't support LookupHTTPS ", url)
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
			return errors.New("Failed to unmarshal ECHKeySetList: ", err)
		}
		config.EncryptedClientHelloKeys = KeySets
	}

	// for client
	if len(c.EchConfigList) != 0 {
		ECHForceQuery := c.EchForceQuery
		switch ECHForceQuery {
		case "none", "half", "full":
		case "":
			ECHForceQuery = "none" // default to none
		default:
			panic("Invalid ECHForceQuery: " + c.EchForceQuery)
		}
		defer func() {
			// if failed to get ECHConfig, use an invalid one to make connection fail
			if err != nil || len(ECHConfig) == 0 {
				if ECHForceQuery == "full" {
					ECHConfig = []byte{1, 1, 4, 5, 1, 4}
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
			for _, s := range core.GetResolverFromContext[featdns.HTTPSResolver](ctx, nameToQuery) {
				if urlOverName(s) == DNSServer {
					resolver = s
					break
				}
			}
			if resolver == nil {
				resolver, err = getDOHServer(ctx, DNSServer, c.EchSocketSettings)
				if err != nil {
					return err
				}
			}
			rsp, err := resolver.LookupHTTPS(ctx, nameToQuery)
			if err != nil {
				return errors.New("Failed to query ECH DNS record for domain: ", nameToQuery, " at server: ", DNSServer).Base(err)
			}
			for _, answer := range rsp {
				if answer.Hdr.Name != dns.Fqdn(nameToQuery) {
					continue
				}
				for _, v := range answer.Value {
					if echConfig, ok := v.(*dns.SVCBECHConfig); ok {
						errors.LogDebug(context.Background(), "Get ECH config:", echConfig.String(), " TTL:", answer.Hdr.Ttl)
						ECHConfig = echConfig.ECH
						return nil
					}
				}
			}
		} else { // direct base64 config
			ECHConfig, err = base64.StdEncoding.DecodeString(c.EchConfigList)
			if err != nil {
				return errors.New("Failed to unmarshal ECHConfigList: ", err)
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
		var (
			sk, config cryptobyte.String
		)
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

const ExtensionEncryptedClientHello = 0xfe0d
const KDF_HKDF_SHA384 = 0x0002
const KDF_HKDF_SHA512 = 0x0003

func GenerateECHKeySet(configID uint8, domain string, kem uint16) (reality.EchConfig, []byte, error) {
	config := reality.EchConfig{
		Version:    ExtensionEncryptedClientHello,
		ConfigID:   configID,
		PublicName: []byte(domain),
		KemID:      kem,
		SymmetricCipherSuite: []reality.EchCipher{
			{KDFID: hpke.KDF_HKDF_SHA256, AEADID: hpke.AEAD_AES_128_GCM},
			{KDFID: hpke.KDF_HKDF_SHA256, AEADID: hpke.AEAD_AES_256_GCM},
			{KDFID: hpke.KDF_HKDF_SHA256, AEADID: hpke.AEAD_ChaCha20Poly1305},
			{KDFID: KDF_HKDF_SHA384, AEADID: hpke.AEAD_AES_128_GCM},
			{KDFID: KDF_HKDF_SHA384, AEADID: hpke.AEAD_AES_256_GCM},
			{KDFID: KDF_HKDF_SHA384, AEADID: hpke.AEAD_ChaCha20Poly1305},
			{KDFID: KDF_HKDF_SHA512, AEADID: hpke.AEAD_AES_128_GCM},
			{KDFID: KDF_HKDF_SHA512, AEADID: hpke.AEAD_AES_256_GCM},
			{KDFID: KDF_HKDF_SHA512, AEADID: hpke.AEAD_ChaCha20Poly1305},
		},
		MaxNameLength: 0,
		Extensions:    nil,
	}
	// if kem == hpke.DHKEM_X25519_HKDF_SHA256 {
	curve := ecdh.X25519()
	priv := make([]byte, 32) //x25519
	_, err := io.ReadFull(rand.Reader, priv)
	if err != nil {
		return config, nil, err
	}
	privKey, _ := curve.NewPrivateKey(priv)
	config.PublicKey = privKey.PublicKey().Bytes()
	return config, priv, nil
	// }
	// TODO: add mlkem768 (former kyber768 draft00). The golang mlkem private key is 64 bytes seed?
}
