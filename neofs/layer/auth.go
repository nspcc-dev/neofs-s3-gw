package layer

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"

	"github.com/klauspost/compress/zstd"
	"github.com/nspcc-dev/neofs-api-go/service"
	"github.com/pkg/errors"
)

const (
	GatewayKeySize = 2048
)

type keyPair struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

type AuthCenter struct {
	gatewayKeys keyPair
}

func NewAuthCenter() (*AuthCenter, error) {
	var (
		err        error
		privateKey *rsa.PrivateKey
	)
	privateKey, err = pullGatewayPrivateKey()
	if err != nil {
		return nil, errors.Wrap(err, "failed to pull gateway private key from trusted enclave")
	}
	if privateKey == nil {
		if privateKey, err = rsa.GenerateKey(rand.Reader, GatewayKeySize); err != nil {
			return nil, errors.Wrap(err, "failed to generate gateway private key")
		}
		if err = pushGatewayPrivateKey(privateKey); err != nil {
			return nil, errors.Wrap(err, "failed to push gateway private key to trusted enclave")
		}
	}
	ac := &AuthCenter{gatewayKeys: keyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}}
	return ac, nil
}

func (ac *AuthCenter) PackBearerToken(bearerToken *service.BearerTokenMsg) ([]byte, error) {
	data, err := bearerToken.Marshal()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal bearer token")
	}
	encryptedKeyID, err := ac.encrypt(compress(data))
	if err != nil {
		return nil, errors.Wrap(err, "")
	}
	return append(sha256Hash(data), encryptedKeyID...), nil
}

func (ac *AuthCenter) UnpackBearerToken(packedBearerToken []byte) (*service.BearerTokenMsg, error) {
	compressedKeyID := packedBearerToken[32:]
	encryptedKeyID, err := decompress(compressedKeyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decompress key ID")
	}
	keyID, err := ac.decrypt(encryptedKeyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt key ID")
	}
	bearerToken := new(service.BearerTokenMsg)
	if err := bearerToken.Unmarshal(keyID); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal embedded bearer token")
	}
	return bearerToken, nil
}

func pullGatewayPrivateKey() (*rsa.PrivateKey, error) {
	// TODO: Pull the private key from a persistent and trusted enclave.
	return nil, nil
}

func pushGatewayPrivateKey(key *rsa.PrivateKey) error {
	// TODO: Push the private key to a persistent and trusted enclave.
	return nil
}

func (ac *AuthCenter) encrypt(data []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, ac.gatewayKeys.PublicKey, data, []byte{})
}

func (ac *AuthCenter) decrypt(data []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, ac.gatewayKeys.PrivateKey, data, []byte{})
}

func compress(data []byte) []byte {
	var compressedData []byte
	zstdEncoder, _ := zstd.NewWriter(nil)
	zstdEncoder.EncodeAll(data, compressedData)
	return compressedData
}

func decompress(data []byte) ([]byte, error) {
	var decompressedData []byte
	zstdDecoder, _ := zstd.NewReader(nil)
	if _, err := zstdDecoder.DecodeAll(data, decompressedData); err != nil {
		return nil, err
	}
	return decompressedData, nil
}

func sha256Hash(data []byte) []byte {
	hash := sha256.New()
	hash.Write(data)
	return hash.Sum(nil)
}
