package autoupdate

import (
	"crypto/sha256"
	"encoding/base64"
	"hash"
	"io"
	"os"
)

type Hasher interface {
	Verify(reader io.Reader, sig string) (bool, error)
	Sum(reader io.Reader) (string, error)

	New() SumWriter
}

type SumWriter interface {
	io.Writer

	Sum() (string, error)
}

type sumWriter struct {
	h hash.Hash
}

func (w sumWriter) Write(b []byte) (int, error) {
	return w.h.Write(b)
}

func (w sumWriter) Sum() (string, error) {
	bs := w.h.Sum(nil)
	return base64.StdEncoding.EncodeToString(bs), nil
}

func WrapSumWriter(h hash.Hash) SumWriter {
	return sumWriter{
		h: h,
	}
}

var defaultHasher = shaHasher{}

type shaHasher struct{}

func (h shaHasher) New() SumWriter {
	return WrapSumWriter(sha256.New())
}

func (h shaHasher) Verify(reader io.Reader, sig string) (bool, error) {
	actual, err := h.Sum(reader)
	if err != nil {
		return false, err
	}
	return actual == sig, nil
}

func (shaHasher) Sum(reader io.Reader) (string, error) {
	h := sha256.New()
	_, err := io.Copy(h, reader)
	if err != nil {
		return "", err
	}
	bs := h.Sum(nil)
	return base64.StdEncoding.EncodeToString(bs), nil
}

func VerifyFile(hasher Hasher, filename string, sig string) (bool, error) {
	in, err := os.Open(filename)
	if err != nil {
		return false, err
	}
	defer in.Close()

	return hasher.Verify(in, sig)
}

func SumFile(hasher Hasher, filename string) (string, error) {
	in, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer in.Close()

	return hasher.Sum(in)
}
