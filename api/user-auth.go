package api

import (
	"context"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/nspcc-dev/neofs-s3-gw/api/auth"
	"go.uber.org/zap"
)

// BearerTokenKey is an ID used to store bearer token in a context.
const BearerTokenKey = "__context_bearer_token_key"

// AttachUserAuth adds user authentication via center to router using log for logging.
func AttachUserAuth(router *mux.Router, center auth.Center, log *zap.Logger) {
	router.Use(func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := center.Authenticate(r)
			if err != nil {
				log.Error("failed to pass authentication", zap.Error(err))
				WriteErrorResponse(r.Context(), w, GetAPIError(ErrAccessDenied), r.URL)
				return
			}

			h.ServeHTTP(w, r.WithContext(
				context.WithValue(r.Context(), BearerTokenKey, token)))
		})
	})
}
