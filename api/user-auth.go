package api

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/nspcc-dev/neofs-s3-gate/auth"
	"go.uber.org/zap"
)

func AttachUserAuth(router *mux.Router, center *auth.Center, log *zap.Logger) {
	uamw := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bearerToken, err := center.AuthenticationPassed(r)
			if err != nil {
				log.Error("failed to pass authentication", zap.Error(err))
				WriteErrorResponse(r.Context(), w, GetAPIError(ErrAccessDenied), r.URL)
				return
			}
			h.ServeHTTP(w, r.WithContext(auth.SetBearerToken(r.Context(), bearerToken)))

		})
	}
	router.Use(uamw)
}
