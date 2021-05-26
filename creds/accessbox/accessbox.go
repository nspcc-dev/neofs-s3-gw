package accessbox

import "github.com/nspcc-dev/neofs-api-go/pkg/token"

type (
	// Box provides marshalling/unmarshalling for the token.
	Box interface {
		Marshal() ([]byte, error)
		Unmarshal([]byte) error
	}

	// Encoder provides encoding method.
	Encoder interface {
		Encode(Box) error
	}

	// Decoder provides decoding method.
	Decoder interface {
		Decode(Box) error
	}

	// BearerTokenBox is a marshalling/unmarshalling bearer token wrapper.
	BearerTokenBox interface {
		Box

		Token() *token.BearerToken
		SetToken(*token.BearerToken)
	}
)
