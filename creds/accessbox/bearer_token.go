package accessbox

import (
	"github.com/nspcc-dev/neofs-api-go/pkg/token"
)

type bearerBox struct {
	tkn *token.BearerToken
}

// NewBearerBox wraps given bearer token into BearerTokenBox.
func NewBearerBox(token *token.BearerToken) BearerTokenBox {
	return &bearerBox{tkn: token}
}

// Marshal serializes bearer token.
func (b *bearerBox) Marshal() ([]byte, error) {
	return b.tkn.Marshal(nil)
}

// Marshal initializes bearer box from its serialized representation.
func (b *bearerBox) Unmarshal(data []byte) error {
	tkn := token.NewBearerToken()

	err := tkn.Unmarshal(data)
	if err != nil {
		return err
	}

	b.SetToken(tkn)

	return nil
}

// Token unwraps bearer token from the box.
func (b *bearerBox) Token() *token.BearerToken {
	return b.tkn
}

// SetToken sets new token in the box.
func (b *bearerBox) SetToken(tkn *token.BearerToken) {
	b.tkn = tkn
}
