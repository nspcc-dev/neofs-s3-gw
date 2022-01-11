package handler

import (
	"net/http"

	"github.com/nspcc-dev/neofs-s3-gw/api"
)

func (h *handler) GetBucketLocationHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	bktInfo, err := h.obj.GetBucketInfo(r.Context(), reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	if err = checkOwner(bktInfo, r.Header.Get(api.AmzExpectedBucketOwner)); err != nil {
		h.logAndSendError(w, "expected owner doesn't match", reqInfo, err)
		return
	}

	if err = api.EncodeToResponse(w, LocationResponse{Location: bktInfo.LocationConstraint}); err != nil {
		h.logAndSendError(w, "couldn't encode bucket location response", reqInfo, err)
	}
}
