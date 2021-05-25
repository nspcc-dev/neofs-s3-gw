package hcs

import (
	"errors"
	"io"

	"golang.org/x/crypto/curve25519"
)

type (
	Credentials interface {
		PublicKey() PublicKey
		PrivateKey() PrivateKey
	}

	keyer interface {
		io.WriterTo

		Bytes() []byte
		String() string
	}

	PublicKey interface {
		keyer
	}

	PrivateKey interface {
		keyer

		PublicKey() PublicKey
	}

	credentials struct {
		public PublicKey
		secret PrivateKey
	}

	public []byte
	secret []byte
)

var ErrEmptyCredentials = errors.New("empty credentials")

var _ = NewCredentials

func Generate(r io.Reader) (Credentials, error) {
	buf := make([]byte, curve25519.ScalarSize)

	if _, err := r.Read(buf); err != nil {
		return nil, err
	}

	sk := secret(buf)
	return &credentials{
		secret: &sk,
		public: sk.PublicKey(),
	}, nil
}

func NewCredentials(val string) (Credentials, error) {
	if val == "" {
		return nil, ErrEmptyCredentials
	}

	sk, err := loadPrivateKey(val)
	if err != nil {
		return nil, err
	}

	return &credentials{
		secret: sk,
		public: sk.PublicKey(),
	}, nil
}

func (c *credentials) PublicKey() PublicKey {
	return c.public
}

func (c *credentials) PrivateKey() PrivateKey {
	return c.secret
}
