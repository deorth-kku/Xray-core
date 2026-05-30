package cfgproto

import (
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/runtime/protoimpl"
)

type ClientConfig struct {
	state             protoimpl.MessageState `protogen:"open.v1"`
	Address           string                 `protobuf:"bytes,1,opt,name=address,proto3" json:"address,omitempty"`
	Port              uint32                 `protobuf:"varint,2,opt,name=port,proto3" json:"port,omitempty"`
	Method            string                 `protobuf:"bytes,3,opt,name=method,proto3" json:"method,omitempty"`
	Key               string                 `protobuf:"bytes,4,opt,name=key,proto3" json:"key,omitempty"`
	UdpOverTcp        bool                   `protobuf:"varint,5,opt,name=udp_over_tcp,json=udpOverTcp,proto3" json:"udp_over_tcp,omitempty"`
	UdpOverTcpVersion uint32                 `protobuf:"varint,6,opt,name=udp_over_tcp_version,json=udpOverTcpVersion,proto3" json:"udp_over_tcp_version,omitempty"`
	unknownFields     protoimpl.UnknownFields
	sizeCache         protoimpl.SizeCache
}

func (*ClientConfig) ProtoMessage() {}

func (*ClientConfig) ProtoReflect() protoreflect.Message {
	return nil
}

func TestUnsafe(t *testing.T) {
	p := new(ClientConfig)
	p.sizeCache = 100
	WriteSizeCache(p, 123)
	if ReadSizeCache(p) != 123 {
		t.Error("cannot read")
	}
}
