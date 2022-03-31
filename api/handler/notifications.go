package handler

import (
	"encoding/xml"
	"net/http"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
)

type NotificationConfiguration struct {
	XMLName                   xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ NotificationConfiguation"`
	NotificationConfiguration data.NotificationConfiguration
}

func (h *handler) PutBucketNotificationHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())
	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	p := &layer.PutBucketNotificationConfigurationParams{
		RequestInfo: reqInfo,
		BktInfo:     bktInfo,
		Reader:      r.Body,
	}

	if err := h.obj.PutBucketNotificationConfiguration(r.Context(), p); err != nil {
		h.logAndSendError(w, "couldn't put bucket configuration", reqInfo, err)
		return
	}
}

func (h *handler) GetBucketNotificationHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	conf, err := h.obj.GetBucketNotificationConfiguration(r.Context(), bktInfo)
	if err != nil {
		h.logAndSendError(w, "could not get bucket notification configuration", reqInfo, err)
		return
	}

	if err = api.EncodeToResponse(w, conf); err != nil {
		h.logAndSendError(w, "could not encode bucket notification configuration to response", reqInfo, err)
		return
	}
}
