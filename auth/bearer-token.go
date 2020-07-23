package auth

import (
	"context"

	"github.com/nspcc-dev/neofs-api-go/service"
	"github.com/pkg/errors"
)

type contextKey string

const bearerTokenContextKey contextKey = "bearer-token"

// GetBearerToken returns a bearer token embedded into a context or error, if any.
func GetBearerToken(ctx context.Context) (*service.BearerTokenMsg, error) {
	bt := ctx.Value(bearerTokenContextKey)
	if bt == nil {
		return nil, errors.New("got nil bearer token")
	}
	v, ok := bt.(*service.BearerTokenMsg)
	if !ok {
		return nil, errors.Errorf("extracted unexpected type other than bearer token's: %T", v)
	}
	return v, nil
}

// SetBearerToken return a context with embedded bearer token.
func SetBearerToken(ctx context.Context, bearerToken *service.BearerTokenMsg) context.Context {
	return context.WithValue(ctx, bearerTokenContextKey, bearerToken)
}
