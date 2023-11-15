package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/nspcc-dev/neofs-s3-gw/api/auth"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3errors"
	"go.uber.org/zap"
)

// KeyWrapper is wrapper for context keys.
type KeyWrapper string

// BoxData is an ID used to store accessbox.Box in a context.
var BoxData = KeyWrapper("__context_box_key")

// ClientTime is an ID used to store client time.Time in a context.
var ClientTime = KeyWrapper("__context_client_time")

// AnonymousRequest is a boolean flag to show explicitly that request was made without authorization.
// Typical usage with `--no-sign-request`.
var AnonymousRequest = KeyWrapper("__context_anonymous_request")

// AttachUserAuth adds user authentication via center to router using log for logging.
func AttachUserAuth(router *mux.Router, center auth.Center, log *zap.Logger) {
	router.Use(func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var ctx context.Context
			box, err := center.Authenticate(r)
			if err != nil {
				if errors.Is(err, auth.ErrNoAuthorizationHeader) {
					log.Debug("couldn't receive access box for gate key, random key will be used")
					// put clear indicator, that we should exec request as an anonymous user.
					ctx = context.WithValue(r.Context(), AnonymousRequest, true)
				} else {
					log.Error("failed to pass authentication", zap.Error(err))
					var s3err s3errors.Error
					if !errors.As(err, &s3err) {
						err = s3errors.GetAPIError(s3errors.ErrAccessDenied)
					}
					WriteErrorResponse(w, GetReqInfo(r.Context()), err)
					return
				}
			} else {
				ctx = context.WithValue(r.Context(), BoxData, box.AccessBox)
				if !box.ClientTime.IsZero() {
					ctx = context.WithValue(ctx, ClientTime, box.ClientTime)
				}
			}

			h.ServeHTTP(w, r.WithContext(ctx))
		})
	})
}

// IsAnonymousRequest helps to check the request was made as an anonymous user.
func IsAnonymousRequest(ctx context.Context) bool {
	if bd, ok := ctx.Value(AnonymousRequest).(bool); ok {
		return bd
	}

	return false
}
