package accessbox

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/nspcc-dev/neofs-s3-gw/creds/hcs"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

type decoder struct {
	*bufio.Reader

	key hcs.PrivateKey
}

// NewDecoder returns new private key decoder.
func NewDecoder(r io.Reader, key hcs.PrivateKey) Decoder {
	return &decoder{Reader: bufio.NewReader(r), key: key}
}

func decrypt(owner hcs.PrivateKey, sender hcs.PublicKey, data []byte) ([]byte, error) {
	sb := sender.Bytes()

	key, err := curve25519.X25519(owner.Bytes(), sb)
	if err != nil {
		return nil, err
	}

	dec, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	if ld, ns := len(data), dec.NonceSize(); ld < ns {
		return nil, fmt.Errorf("wrong data size (%d), should be greater than %d", ld, ns)
	}

	nonce, cypher := data[:dec.NonceSize()], data[dec.NonceSize():]
	return dec.Open(nil, nonce, cypher, nil)
}

func (d *decoder) Decode(box Box) error {
	sender, err := hcs.NewPublicKeyFromReader(d)
	if err != nil {
		return err
	}

	var lastErr error

	for {
		size, err := binary.ReadVarint(d)
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		data := make([]byte, size)

		if ln, err := d.Read(data); err != nil {
			lastErr = err
			continue
		} else if ln != int(size) {
			lastErr = fmt.Errorf("expect %d bytes, but read only %d bytes", size, ln)
			continue
		} else if decoded, err := decrypt(d.key, sender, data); err != nil {
			lastErr = err
			continue
		} else if err = box.Unmarshal(decoded); err != nil {
			lastErr = err
			continue
		}

		return nil
	}

	return lastErr
}

// Decode unwraps serialized bearer token from data into box using owner key.
func Decode(data []byte, box Box, owner hcs.PrivateKey) error {
	return NewDecoder(bytes.NewBuffer(data), owner).Decode(box)
}
