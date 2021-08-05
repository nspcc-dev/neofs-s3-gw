package handler

import (
	"net/http"

	"github.com/nspcc-dev/neofs-s3-gw/api"
)

func (h *handler) GetBucketLocationHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	if _, err := h.obj.GetBucketInfo(r.Context(), reqInfo.BucketName); err != nil {
		h.logAndSendError(w, "something went wrong", reqInfo, err)
		return
	}

	if err := api.EncodeToResponse(w, LocationResponse{Location: ""}); err != nil {
		h.logAndSendError(w, "something went wrong", reqInfo, err)
	}
}
