package hcs

import (
	"errors"
	"io"

	"golang.org/x/crypto/curve25519"
)

type (
	// Credentials is an HCS interface (private/public key).
	Credentials interface {
		PublicKey() PublicKey
		PrivateKey() PrivateKey
	}

	keyer interface {
		io.WriterTo

		Bytes() []byte
		String() string
	}

	// PublicKey is a public key wrapper providing useful methods.
	PublicKey interface {
		keyer
	}

	// PrivateKey is private key wrapper providing useful methods.
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

// ErrEmptyCredentials is returned when no credentials are provided.
var ErrEmptyCredentials = errors.New("empty credentials")

var _ = NewCredentials

// Generate generates new key pair using given source of randomness.
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

// NewCredentials loads private key from the string given and returns Credentials wrapper.
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

// PublicKey returns public key.
func (c *credentials) PublicKey() PublicKey {
	return c.public
}

// PrivateKey returns private key.
func (c *credentials) PrivateKey() PrivateKey {
	return c.secret
}
