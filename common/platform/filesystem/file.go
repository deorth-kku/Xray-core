package filesystem

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/platform"
)

type mergeReadCloser struct {
	io.Reader
	closers []io.Closer
}

func (m mergeReadCloser) Close() error {
	errs := make([]any, 0, len(m.closers))
	for _, c := range m.closers {
		err := c.Close()
		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("closers returned errors: %w"+strings.Repeat(",%w", len(errs)-1), errs...)
}

func NewFileReader(path string) (io.ReadCloser, error) {
	if filepath.Ext(path) != ".gz" {
		return os.Open(path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	gf, err := gzip.NewReader(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	return mergeReadCloser{gf, []io.Closer{gf, f}}, nil
}

func ReadFile(path string) ([]byte, error) {
	reader, err := NewFileReader(path)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return buf.ReadAllToBytes(reader)
}

func ReadAsset(file string) (io.ReadCloser, error) {
	return NewFileReader(platform.GetAssetLocation(file))
}

func CopyFile(dst string, src string) error {
	bytes, err := ReadFile(src)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(bytes)
	return err
}
