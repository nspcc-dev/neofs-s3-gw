package main

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/minio/minio/auth"
	"go.uber.org/zap"
)

func attachNewUserAuth(router *mux.Router, center *auth.Center, log *zap.Logger) {
	uamw := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := center.AuthenticationPassed(r)
			if err != nil {
				log.Error("failed to pass authentication", zap.Error(err))
			}
			// TODO: Handle any auth error by rejecting request.
			h.ServeHTTP(w, r)

		})
	}
	// TODO: should not be used for all routes,
	//       only for API
	router.Use(uamw)
}
