package neofs

import (
	"crypto/ecdsa"

	"github.com/nspcc-dev/neofs-api-go/pkg/owner"
	crypto "github.com/nspcc-dev/neofs-crypto"
)

type (
	// Credentials contains methods that needed to work with NeoFS.
	Credentials interface {
		WIF() string
		Owner() *owner.ID
		PublicKey() *ecdsa.PublicKey
		PrivateKey() *ecdsa.PrivateKey
	}

	cred struct {
		key   *ecdsa.PrivateKey
		owner *owner.ID
		wif   string
	}
)

// New creates an instance of Credentials through string representation of secret.
//     It allows passing WIF, path, hex-encoded and others.
func New(secret string) (Credentials, error) {
	key, err := crypto.LoadPrivateKey(secret)
	if err != nil {
		return nil, err
	}

	return setFromPrivateKey(key)
}

// PrivateKey returns ecdsa.PrivateKey.
func (c *cred) PrivateKey() *ecdsa.PrivateKey {
	return c.key
}

// PublicKey returns ecdsa.PublicKey.
func (c *cred) PublicKey() *ecdsa.PublicKey {
	return &c.key.PublicKey
}

// Owner returns owner.ID.
func (c *cred) Owner() *owner.ID {
	return c.owner
}

// WIF returns string representation of WIF.
func (c *cred) WIF() string {
	return c.wif
}

func setFromPrivateKey(key *ecdsa.PrivateKey) (*cred, error) {
	wallet, err := owner.NEO3WalletFromPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}

	ownerID := owner.NewIDFromNeo3Wallet(wallet)

	wif, err := crypto.WIFEncode(key)
	if err != nil {
		return nil, err
	}

	return &cred{key: key, owner: ownerID, wif: wif}, nil
}
