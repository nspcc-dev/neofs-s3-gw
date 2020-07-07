package layer

import (
	"crypto/rand"
	"crypto/rsa"

	"github.com/klauspost/compress/zstd"
	"github.com/nspcc-dev/neofs-api-go/service"
	"github.com/pkg/errors"
)

type KeyPair struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

type AuthCenter struct {
	gatewayKeys KeyPair
}

func NewAuthCenter() (*AuthCenter, error) {
	var kp KeyPair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	kp.PrivateKey = privateKey
	kp.PublicKey = &privateKey.PublicKey
	ac := &AuthCenter{
		gatewayKeys: kp,
	}
	return ac, nil
}

func (ac *AuthCenter) PackBearerToken(bt service.BearerToken) ([]byte, error) {
	// TODO
	panic("unimplemented method")
}

func (ac *AuthCenter) UnpackBearerToken(packedCredentials []byte) (service.BearerToken, error) {
	zstdDecoder, _ := zstd.NewReader(nil)
	// secretHash := packedCredentials[:32]
	_ = packedCredentials[:32]
	compressedKeyID := packedCredentials[32:]
	// Get an encrypted key.
	var encryptedKeyID []byte
	if _, err := zstdDecoder.DecodeAll(compressedKeyID, encryptedKeyID); err != nil {
		return nil, errors.Wrap(err, "failed to decompress key ID")
	}
	// TODO: Decrypt the key ID.
	var keyID []byte
	bearerToken := new(service.BearerTokenMsg)
	if err := bearerToken.Unmarshal(keyID); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal embedded bearer token")
	}
	return bearerToken, nil
}
