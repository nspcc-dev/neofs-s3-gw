package hcs

import (
	"encoding/hex"
	"io"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/curve25519"
)

func (p *public) Bytes() []byte {
	buf := make([]byte, curve25519.PointSize)
	copy(buf, *p)
	return buf
}

func (p *public) String() string {
	buf := p.Bytes()
	return hex.EncodeToString(buf)
}

func (p *public) WriteTo(w io.Writer) (int64, error) {
	pb := p.Bytes()
	pl, err := w.Write(pb)
	return int64(pl), err
}

func publicKeyFromBytes(v []byte) (PublicKey, error) {
	pub := public(v)
	return &pub, nil
}

func publicKeyFromString(val string) (PublicKey, error) {
	v, err := hex.DecodeString(val)
	if err != nil {
		return nil, err
	}

	return publicKeyFromBytes(v)
}

// NewPublicKeyFromReader reads new public key from given reader.
func NewPublicKeyFromReader(r io.Reader) (PublicKey, error) {
	data := make([]byte, curve25519.PointSize)
	if _, err := r.Read(data); err != nil {
		return nil, err
	}

	return publicKeyFromBytes(data)
}

// LoadPublicKey loads public key from given file or (serialized) string.
func LoadPublicKey(val string) (PublicKey, error) {
	data, err := ioutil.ReadFile(val)
	if err != nil {
		if os.IsNotExist(err) {
			return publicKeyFromString(val)
		}

		return nil, err
	}

	return publicKeyFromBytes(data)
}
