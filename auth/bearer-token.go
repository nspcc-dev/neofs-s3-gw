package auth

import (
	"context"

	"github.com/nspcc-dev/neofs-api-go/service"
)

type contextKey string

const bearerTokenContextKey contextKey = "bearer-token"

// GetBearerToken returns a bearer token embedded into a context.
func GetBearerToken(ctx context.Context) *service.BearerTokenMsg {
	if bt := ctx.Value(bearerTokenContextKey); bt != nil {
		return bt.(*service.BearerTokenMsg)
	}
	return nil
}

// SetBearerToken return a context with embedded bearer token.
func SetBearerToken(ctx context.Context, bearerToken *service.BearerTokenMsg) context.Context {
	return context.WithValue(ctx, bearerTokenContextKey, bearerToken)
}
