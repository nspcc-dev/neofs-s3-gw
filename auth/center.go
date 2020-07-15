package auth

import (
	"crypto/sha256"

	"github.com/klauspost/compress/zstd"
	"github.com/nspcc-dev/neofs-api-go/service"
	"github.com/pkg/errors"
)

var _debug = false

func SetDebug() {
	_debug = true
}

// Center is a central app's authentication/authorization management unit.
type Center struct {
	zstdEncoder *zstd.Encoder
	zstdDecoder *zstd.Decoder
}

// NewAuthCenter creates an instance of AuthCenter.
func NewCenter() (*Center, error) {
	zstdEncoder, _ := zstd.NewWriter(nil)
	zstdDecoder, _ := zstd.NewReader(nil)
	ac := &Center{zstdEncoder: zstdEncoder, zstdDecoder: zstdDecoder}
	return ac, nil
}

func (ac *Center) PackBearerToken(bearerToken *service.BearerTokenMsg) ([]byte, error) {
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

func (ac *Center) UnpackBearerToken(packedBearerToken []byte) (*service.BearerTokenMsg, error) {
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

func (ac *Center) compress(data []byte) []byte {
	ac.zstdEncoder.Reset(nil)
	var compressedData []byte
	ac.zstdEncoder.EncodeAll(data, compressedData)
	return compressedData
}

func (ac *Center) decompress(data []byte) ([]byte, error) {
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
