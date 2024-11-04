package filesystem

import (
	"compress/gzip"
	"io"
	"os"
	"strings"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/platform"
)

type FileReaderFunc func(path string) (io.ReadCloser, error)

var NewFileReader FileReaderFunc = func(path string) (io.ReadCloser, error) {
	return os.Open(path)
}

func ReadFile(path string) ([]byte, error) {
	var reader io.Reader
	freader, err := NewFileReader(path)
	if err != nil {
		return nil, err
	}
	defer freader.Close()
	if strings.HasSuffix(path, ".gz") {
		gzreader, err := gzip.NewReader(freader)
		if err != nil {
			return nil, err
		}
		defer gzreader.Close()
		reader = gzreader
	} else {
		reader = freader
	}

	return buf.ReadAllToBytes(reader)
}

func ReadAsset(file string) ([]byte, error) {
	return ReadFile(platform.GetAssetLocation(file))
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
