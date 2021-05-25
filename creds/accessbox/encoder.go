package accessbox

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/nspcc-dev/neofs-s3-gw/creds/hcs"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

type encoder struct {
	io.Writer

	owner hcs.PrivateKey
	keys  []hcs.PublicKey
}

// NewEncoder creates encoder
func NewEncoder(w io.Writer, owner hcs.PrivateKey, keys ...hcs.PublicKey) Encoder {
	return &encoder{
		Writer: w,
		owner:  owner,
		keys:   keys,
	}
}

func encrypt(owner hcs.PrivateKey, sender hcs.PublicKey, data []byte) ([]byte, error) {
	key, err := curve25519.X25519(owner.Bytes(), sender.Bytes())
	if err != nil {
		return nil, err
	}

	enc, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, enc.NonceSize(), enc.NonceSize()+len(data)+enc.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	return enc.Seal(nonce, nonce, data, nil), nil
}

// Encode and encrypt box through owner private key and public keys.
func (e *encoder) Encode(box Box) error {
	data, err := box.Marshal()
	if err != nil {
		return err
	}

	// write owner public key
	if _, err = e.owner.PublicKey().WriteTo(e); err != nil {
		return err
	}

	for i, sender := range e.keys {
		encrypted, err := encrypt(e.owner, sender, data)
		if err != nil {
			return fmt.Errorf("%w, sender = %d", err, i)
		}

		ln := len(encrypted)
		temp := make([]byte, ln+binary.MaxVarintLen64)
		size := binary.PutVarint(temp, int64(ln))
		copy(temp[size:], encrypted)
		if _, err := e.Write(temp[:size+ln]); err != nil {
			return fmt.Errorf("%w, sender = %d", err, i)
		}
	}

	return nil
}

// Encode and encrypt box through owner private key and public keys.
func Encode(box Box, owner hcs.PrivateKey, keys ...hcs.PublicKey) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := NewEncoder(buf, owner, keys...).Encode(box)
	return buf.Bytes(), err
}
