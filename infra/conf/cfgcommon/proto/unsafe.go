package cfgproto

import (
	"reflect"
	"unsafe"

	"google.golang.org/protobuf/proto"
)

type msgPointer[T any] interface {
	*T
	proto.Message
}

func WriteSizeCache[P msgPointer[T], T any](v P, u int32) {
	ty := reflect.TypeFor[T]()
	f := ty.Field(ty.NumField() - 1)
	p := uintptr(unsafe.Pointer(v)) + f.Offset
	p0 := (*int32)(unsafe.Pointer(p))
	*p0 = u
}

func ReadSizeCache[P msgPointer[T], T any](v P) int32 {
	rv := reflect.ValueOf(v).Elem()
	rv = rv.Field(rv.NumField() - 1)
	return int32(rv.Int())
}
