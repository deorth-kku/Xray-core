package conf

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/common/protocol"
)

type StringList []string

func NewStringList(raw []string) *StringList {
	list := StringList(raw)
	return &list
}

func (v StringList) Len() int {
	return len(v)
}

func (v *StringList) UnmarshalJSON(data []byte) error {
	var strarray []string
	if err := json.Unmarshal(data, &strarray); err == nil {
		*v = *NewStringList(strarray)
		return nil
	}

	var rawstr string
	if err := json.Unmarshal(data, &rawstr); err == nil {
		strlist := strings.Split(rawstr, ",")
		*v = *NewStringList(strlist)
		return nil
	}
	return errors.New("unknown format of a string list: " + string(data))
}

type Address struct {
	net.Address
}

func (v *Address) UnmarshalJSON(data []byte) error {
	var rawStr string
	if err := json.Unmarshal(data, &rawStr); err != nil {
		return errors.New("invalid address: ", string(data)).Base(err)
	}
	if strings.HasPrefix(rawStr, "env:") {
		rawStr = platform.NewEnvFlag(rawStr[4:]).GetValue(func() string { return "" })
	}
	v.Address = net.ParseAddress(rawStr)

	return nil
}

func (v *Address) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(v.String())), nil
}

func (v *Address) Build() *net.IPOrDomain {
	return net.NewIPOrDomain(v.Address)
}

type Network string

func (v Network) Build() net.Network {
	switch strings.ToLower(string(v)) {
	case "tcp":
		return net.Network_TCP
	case "udp":
		return net.Network_UDP
	case "unix":
		return net.Network_UNIX
	default:
		return net.Network_Unknown
	}
}

type NetworkList []Network

func (v *NetworkList) UnmarshalJSON(data []byte) error {
	var strarray []Network
	if err := json.Unmarshal(data, &strarray); err == nil {
		nl := NetworkList(strarray)
		*v = nl
		return nil
	}

	var rawstr Network
	if err := json.Unmarshal(data, &rawstr); err == nil {
		strlist := strings.Split(string(rawstr), ",")
		nl := make([]Network, len(strlist))
		for idx, network := range strlist {
			nl[idx] = Network(network)
		}
		*v = nl
		return nil
	}
	return errors.New("unknown format of a string list: " + string(data))
}

func (v *NetworkList) Build() []net.Network {
	if v == nil {
		return []net.Network{net.Network_TCP}
	}

	list := make([]net.Network, 0, len(*v))
	for _, network := range *v {
		list = append(list, network.Build())
	}
	return list
}

func parseIntPort(data []byte) (net.Port, error) {
	var intPort uint32
	err := json.Unmarshal(data, &intPort)
	if err != nil {
		return net.Port(0), err
	}
	return net.PortFromInt(intPort)
}

func parseStringPort(s string) (net.Port, net.Port, error) {
	if strings.HasPrefix(s, "env:") {
		s = platform.NewEnvFlag(s[4:]).GetValue(func() string { return "" })
	}

	pair := strings.SplitN(s, "-", 2)
	if len(pair) == 0 {
		return net.Port(0), net.Port(0), errors.New("invalid port range: ", s)
	}
	if len(pair) == 1 {
		port, err := net.PortFromString(pair[0])
		return port, port, err
	}

	fromPort, err := net.PortFromString(pair[0])
	if err != nil {
		return net.Port(0), net.Port(0), err
	}
	toPort, err := net.PortFromString(pair[1])
	if err != nil {
		return net.Port(0), net.Port(0), err
	}
	return fromPort, toPort, nil
}

func parseJSONStringPort(data []byte) (net.Port, net.Port, error) {
	var s string
	err := json.Unmarshal(data, &s)
	if err != nil {
		return net.Port(0), net.Port(0), err
	}
	return parseStringPort(s)
}

type PortRange struct {
	From uint32
	To   uint32
}

func (v *PortRange) Build() *net.PortRange {
	return &net.PortRange{
		From: v.From,
		To:   v.To,
	}
}

// UnmarshalJSON implements encoding/json.Unmarshaler.UnmarshalJSON
func (v *PortRange) UnmarshalJSON(data []byte) error {
	port, err := parseIntPort(data)
	if err == nil {
		v.From = uint32(port)
		v.To = uint32(port)
		return nil
	}

	from, to, err := parseJSONStringPort(data)
	if err == nil {
		v.From = uint32(from)
		v.To = uint32(to)
		if v.From > v.To {
			return errors.New("invalid port range ", v.From, " -> ", v.To)
		}
		return nil
	}

	return errors.New("invalid port range: ", string(data))
}

type PortList struct {
	Range []PortRange
}

func (list *PortList) Build() *net.PortList {
	portList := new(net.PortList)
	for _, r := range list.Range {
		portList.Range = append(portList.Range, r.Build())
	}
	return portList
}

// UnmarshalJSON implements encoding/json.Unmarshaler.UnmarshalJSON
func (list *PortList) UnmarshalJSON(data []byte) error {
	var listStr string
	var number uint32
	if err := json.Unmarshal(data, &listStr); err != nil {
		if err2 := json.Unmarshal(data, &number); err2 != nil {
			return errors.New("invalid port: ", string(data)).Base(err2)
		}
	}
	rangelist := strings.Split(listStr, ",")
	for _, rangeStr := range rangelist {
		trimmed := strings.TrimSpace(rangeStr)
		if len(trimmed) > 0 {
			if strings.Contains(trimmed, "-") || strings.Contains(trimmed, "env:") {
				from, to, err := parseStringPort(trimmed)
				if err != nil {
					return errors.New("invalid port range: ", trimmed).Base(err)
				}
				list.Range = append(list.Range, PortRange{From: uint32(from), To: uint32(to)})
			} else {
				port, err := parseIntPort([]byte(trimmed))
				if err != nil {
					return errors.New("invalid port: ", trimmed).Base(err)
				}
				list.Range = append(list.Range, PortRange{From: uint32(port), To: uint32(port)})
			}
		}
	}
	if number != 0 {
		list.Range = append(list.Range, PortRange{From: number, To: number})
	}
	return nil
}

func (list *PortList) MarshalJSON() ([]byte, error) {
	if len(list.Range) == 1 && list.Range[0].From == list.Range[0].To {
		return json.Marshal(list.Range[0].From)
	}
	strs := make([]string, 0, len(list.Range))
	for _, rg := range list.Range {
		if rg.From == rg.To {
			strs = append(strs, fmt.Sprint(rg.From))
		} else {
			strs = append(strs, fmt.Sprintf("%d-%d", rg.From, rg.To))
		}
	}
	return []byte(strconv.Quote(strings.Join(strs, ","))), nil
}

type User struct {
	EmailString string `json:"email,omitempty"`
	LevelByte   byte   `json:"level,omitempty"`
}

func (v *User) Build() *protocol.User {
	return &protocol.User{
		Email: v.EmailString,
		Level: uint32(v.LevelByte),
	}
}

// Int32Range deserializes from "1-2" or 1, so can deserialize from both int and number.
// Negative integers can be passed as sentinel values, but do not parse as ranges.
type Int32Range struct {
	From int32
	To   int32
}

func (v *Int32Range) UnmarshalJSON(data []byte) error {
	var str string
	var rawint int32
	if err := json.Unmarshal(data, &str); err == nil {
		// for number in string format like "114" or "-1"
		if value, err := strconv.Atoi(str); err == nil {
			v.From = int32(value)
			v.To = int32(value)
			return nil
		}
		// for empty "", we treat it as 0
		if str == "" {
			v.From = 0
			v.To = 0
			return nil
		}
		// for range value, like "114-514"
		pair := strings.SplitN(str, "-", 2)
		if len(pair) == 2 {
			from, err := strconv.Atoi(pair[0])
			to, err2 := strconv.Atoi(pair[1])
			if err == nil && err2 == nil {
				v.From = int32(from)
				v.To = int32(to)
				return nil
			}
		}
	} else if err := json.Unmarshal(data, &rawint); err == nil {
		v.From = rawint
		v.To = rawint
		return nil
	}

	return errors.New("Invalid integer range, expected either string of form \"1-2\" or plain integer.")
}
