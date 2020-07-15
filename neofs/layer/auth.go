package layer

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"

	"github.com/klauspost/compress/zstd"
	"github.com/nspcc-dev/neofs-api-go/service"
	"github.com/pkg/errors"
)

const (
	gatewayEncryptionKeySize = 2048
)

type (
	signatureKeyName  byte
	encryptionKeyName byte
)

const (
	_ signatureKeyName = iota
	// Indicates that the key is a NeoFS ECDSA key.
	gateNeoFSECDSAKey
	gateNeoFSEd25519Key
)

const (
	_ encryptionKeyName = iota
	// Indicates that the key is used to encrypt
	// a bearer token to pass auth procedure.
	gateUserAuthKey
)

type (
	signatureKeyPair struct {
		PrivateKey *ecdsa.PrivateKey
		PublicKey  *ecdsa.PublicKey
	}

	encryptionKeyPair struct {
		PrivateKey *rsa.PrivateKey
		PublicKey  *rsa.PublicKey
	}
)

type secureEnclave struct {
	signatureKeys  map[signatureKeyName]signatureKeyPair
	encryptionKeys map[encryptionKeyName]encryptionKeyPair
}

func newSecureEnclave() (*secureEnclave, error) {
	// TODO: Get private keys.
	// TODO: Fetch NeoFS and Auth private keys from app settings.
	return &secureEnclave{
		signatureKeys:  map[signatureKeyName]signatureKeyPair{},
		encryptionKeys: map[encryptionKeyName]encryptionKeyPair{},
	}, nil
}

func (se *secureEnclave) Encrypt(keyName encryptionKeyName, data []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, se.encryptionKeys[keyName].PublicKey, data, []byte{})
}

func (se *secureEnclave) Decrypt(keyName encryptionKeyName, data []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, se.encryptionKeys[keyName].PrivateKey, data, []byte{})
}

var globalEnclave *secureEnclave

func init() {
	var err error
	globalEnclave, err = newSecureEnclave()
	if err != nil {
		panic("failed to initialize secure enclave")
	}
}

// AuthCenter is a central app's authentication/authorization management unit.
type AuthCenter struct {
	zstdEncoder *zstd.Encoder
	zstdDecoder *zstd.Decoder
}

// NewAuthCenter creates an instance of AuthCenter.
func NewAuthCenter() (*AuthCenter, error) {
	// var (
	// 	err        error
	// 	privateKey *rsa.PrivateKey
	// )
	// secureEnclave := &SecureEnclave{}
	// privateKey, err = secureEnclave.PullGatewayEncryptionPrivateKey()
	// if err != nil {
	// 	return nil, errors.Wrap(err, "failed to pull gateway private key from trusted enclave")
	// }
	// if privateKey == nil {
	// 	// TODO: Move this logic to the enclave.
	// 	if privateKey, err = rsa.GenerateKey(rand.Reader, gatewayEncryptionKeySize); err != nil {
	// 		return nil, errors.Wrap(err, "failed to generate gateway private key")
	// 	}
	// 	// if err = keysEnclave.PushGatewayEncryptionPrivateKey(privateKey); err != nil {
	// 	// 	return nil, errors.Wrap(err, "failed to push gateway private key to trusted enclave")
	// 	// }
	// }
	zstdEncoder, _ := zstd.NewWriter(nil)
	zstdDecoder, _ := zstd.NewReader(nil)
	ac := &AuthCenter{zstdEncoder: zstdEncoder, zstdDecoder: zstdDecoder}
	return ac, nil
}

func (ac *AuthCenter) PackBearerToken(bearerToken *service.BearerTokenMsg) ([]byte, error) {
	data, err := bearerToken.Marshal()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal bearer token")
	}
	encryptedKeyID, err := globalEnclave.Encrypt(gateUserAuthKey, ac.compress(data))
	if err != nil {
		return nil, errors.Wrap(err, "")
	}
	return append(sha256Hash(data), encryptedKeyID...), nil
}

func (ac *AuthCenter) UnpackBearerToken(packedBearerToken []byte) (*service.BearerTokenMsg, error) {
	compressedKeyID := packedBearerToken[32:]
	encryptedKeyID, err := ac.decompress(compressedKeyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decompress key ID")
	}
	keyID, err := globalEnclave.Decrypt(gateUserAuthKey, encryptedKeyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt key ID")
	}
	bearerToken := new(service.BearerTokenMsg)
	if err := bearerToken.Unmarshal(keyID); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal embedded bearer token")
	}
	return bearerToken, nil
}

func (ac *AuthCenter) compress(data []byte) []byte {
	ac.zstdEncoder.Reset(nil)
	var compressedData []byte
	ac.zstdEncoder.EncodeAll(data, compressedData)
	return compressedData
}

func (ac *AuthCenter) decompress(data []byte) ([]byte, error) {
	ac.zstdDecoder.Reset(nil)
	var decompressedData []byte
	if _, err := ac.zstdDecoder.DecodeAll(data, decompressedData); err != nil {
		return nil, err
	}
	return decompressedData, nil
}

func sha256Hash(data []byte) []byte {
	hash := sha256.New()
	hash.Write(data)
	return hash.Sum(nil)
}
