package accessbox

import "github.com/nspcc-dev/neofs-api-go/pkg/token"

type (
	Box interface {
		Marshal() ([]byte, error)
		Unmarshal([]byte) error
	}

	Encoder interface {
		Encode(Box) error
	}

	Decoder interface {
		Decode(Box) error
	}

	BearerTokenBox interface {
		Box

		Token() *token.BearerToken
		SetToken(*token.BearerToken)
	}
)
