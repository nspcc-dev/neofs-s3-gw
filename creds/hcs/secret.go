package hcs

import (
	"encoding/hex"
	"io"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/curve25519"
)

func (s *secret) Bytes() []byte {
	buf := make([]byte, curve25519.ScalarSize)
	copy(buf, *s)
	return buf
}

func (s *secret) String() string {
	buf := s.Bytes()
	return hex.EncodeToString(buf)
}

func (s *secret) PublicKey() PublicKey {
	sk := s.Bytes()

	pb, _ := curve25519.X25519(sk, curve25519.Basepoint)
	pk := public(pb)
	return &pk
}

func (s *secret) WriteTo(w io.Writer) (int64, error) {
	sb := s.Bytes()
	sl, err := w.Write(sb)
	return int64(sl), err
}

func privateKeyFromBytes(val []byte) (PrivateKey, error) {
	sk := secret(val)
	return &sk, nil
}

func privateKeyFromString(val string) (PrivateKey, error) {
	data, err := hex.DecodeString(val)
	if err != nil {
		return nil, err
	}

	return privateKeyFromBytes(data)
}

func loadPrivateKey(val string) (PrivateKey, error) {
	data, err := ioutil.ReadFile(val)
	if os.IsNotExist(err) {
		return privateKeyFromString(val)
	} else if err != nil {
		return nil, err
	}

	return privateKeyFromBytes(data)
}
