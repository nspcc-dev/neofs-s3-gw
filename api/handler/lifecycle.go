package handler

import (
	"net/http"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3errors"
)

func (h *handler) GetBucketLifecycleHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(
		w,
		"The lifecycle configuration does not exist",
		api.GetReqInfo(r.Context()),
		s3errors.GetAPIError(s3errors.ErrNoSuchLifecycleConfiguration),
	)
}
