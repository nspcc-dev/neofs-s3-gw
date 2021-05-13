package api

import (
	"net/http"

	"github.com/gorilla/mux"
	sdk "github.com/nspcc-dev/cdn-sdk"
	"github.com/nspcc-dev/neofs-s3-gate/api/auth"
	"go.uber.org/zap"
)

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
				sdk.SetBearerToken(r.Context(), token)))
		})
	})
}
