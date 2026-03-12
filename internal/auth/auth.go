package auth

import (
	"strings"

	"github.com/mr-tron/base58"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3errors"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
)

const (
	// AccessKeyPartsNum describes SessionV1 access key id params length.
	AccessKeyPartsNum = 2
	// AccessKeyPartsNumV2 describes SessionV2 access key id params length.
	AccessKeyPartsNumV2 = 3
)

// ParseAccessKeyID parses passed accessKeyID.
func ParseAccessKeyID(accessKeyID string) (oid.Address, []byte, error) {
	var (
		parts = strings.Split(accessKeyID, "0")
		pLen  = len(parts)
		addr  oid.Address
	)

	if pLen < AccessKeyPartsNum {
		return oid.Address{}, nil, s3errors.GetAPIError(s3errors.ErrInvalidAccessKeyID)
	}

	addr, err := oid.DecodeAddressString(parts[0] + "/" + parts[1])
	if err != nil {
		return addr, nil, s3errors.GetAPIError(s3errors.ErrInvalidAccessKeyID)
	}

	if pLen == AccessKeyPartsNum {
		return addr, nil, nil
	}

	if pLen == AccessKeyPartsNumV2 {
		encodingKey, err := base58.Decode(parts[2])
		if err != nil {
			return addr, nil, s3errors.GetAPIError(s3errors.ErrInvalidAccessKeyID)
		}

		return addr, encodingKey, nil
	}

	return oid.Address{}, nil, s3errors.GetAPIError(s3errors.ErrInvalidAccessKeyID)
}
