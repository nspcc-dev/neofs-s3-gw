package accessbox

import (
	"github.com/nspcc-dev/neofs-api-go/pkg/token"
)

type bearerBox struct {
	tkn *token.BearerToken
}

func NewBearerBox(token *token.BearerToken) BearerTokenBox {
	return &bearerBox{tkn: token}
}

func (b *bearerBox) Marshal() ([]byte, error) {
	return b.tkn.Marshal(nil)
}

func (b *bearerBox) Unmarshal(data []byte) error {
	tkn := token.NewBearerToken()

	err := tkn.Unmarshal(data)
	if err != nil {
		return err
	}

	b.SetToken(tkn)

	return nil
}

func (b *bearerBox) Token() *token.BearerToken {
	return b.tkn
}

func (b *bearerBox) SetToken(tkn *token.BearerToken) {
	b.tkn = tkn
}
