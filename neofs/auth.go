package neofs

import (
	br "github.com/google/brotli/go/cbrotli"
	"github.com/nspcc-dev/neofs-api-go/service"
	"github.com/pkg/errors"
)

func UnpackBearerToken(packedCredentials []byte) (service.BearerToken, error) {
	// secretHash := packedCredentials[:32]
	_ = packedCredentials[:32]
	compressedKeyID := packedCredentials[32:]
	keyID, err := br.Decode(compressedKeyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decompress key ID")
	}
	bearerToken := new(service.BearerTokenMsg)
	if err = bearerToken.Unmarshal(keyID); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal embedded bearer token")
	}
	// TODO
	return bearerToken, nil
}
