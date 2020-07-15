package auth

import (
	"crypto/sha256"

	"github.com/klauspost/compress/zstd"
	"github.com/nspcc-dev/neofs-api-go/service"
	"github.com/pkg/errors"
)

// Center is a central app's authentication/authorization management unit.
type Center struct {
	enclave     *secureEnclave
	zstdEncoder *zstd.Encoder
	zstdDecoder *zstd.Decoder
}

// NewCenter creates an instance of AuthCenter.
func NewCenter(pathToRSAKey, pathToECDSAKey string) (*Center, error) {
	zstdEncoder, _ := zstd.NewWriter(nil)
	zstdDecoder, _ := zstd.NewReader(nil)
	enclave, err := newSecureEnclave(pathToRSAKey, pathToECDSAKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create secure enclave")
	}
	center := &Center{
		enclave:     enclave,
		zstdEncoder: zstdEncoder,
		zstdDecoder: zstdDecoder,
	}
	return center, nil
}

func (center *Center) PackBearerToken(bearerToken *service.BearerTokenMsg) ([]byte, error) {
	data, err := bearerToken.Marshal()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal bearer token")
	}
	encryptedKeyID, err := center.enclave.Encrypt(gateUserAuthKey, center.compress(data))
	if err != nil {
		return nil, errors.Wrap(err, "")
	}
	return append(sha256Hash(data), encryptedKeyID...), nil
}

func (center *Center) UnpackBearerToken(packedBearerToken []byte) (*service.BearerTokenMsg, error) {
	compressedKeyID := packedBearerToken[32:]
	encryptedKeyID, err := center.decompress(compressedKeyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decompress key ID")
	}
	keyID, err := center.enclave.Decrypt(gateUserAuthKey, encryptedKeyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt key ID")
	}
	bearerToken := new(service.BearerTokenMsg)
	if err := bearerToken.Unmarshal(keyID); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal embedded bearer token")
	}
	return bearerToken, nil
}

func (center *Center) compress(data []byte) []byte {
	center.zstdEncoder.Reset(nil)
	var compressedData []byte
	center.zstdEncoder.EncodeAll(data, compressedData)
	return compressedData
}

func (center *Center) decompress(data []byte) ([]byte, error) {
	center.zstdDecoder.Reset(nil)
	var decompressedData []byte
	if _, err := center.zstdDecoder.DecodeAll(data, decompressedData); err != nil {
		return nil, err
	}
	return decompressedData, nil
}

func sha256Hash(data []byte) []byte {
	hash := sha256.New()
	hash.Write(data)
	return hash.Sum(nil)
}
