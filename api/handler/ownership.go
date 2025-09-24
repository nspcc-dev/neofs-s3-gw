package handler

import (
	"encoding/xml"
	"io"
	"net/http"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3errors"
)

type (
	putBucketOwnershipControlsParams struct {
		Rules []objectOwnershipRules `xml:"Rule"`
	}

	objectOwnershipRules struct {
		ObjectOwnership string `xml:"ObjectOwnership"`
	}
)

const (
	xAmzExpectedBucketOwner = "x-amz-expected-bucket-owner"
)

func decodeXML(r io.Reader, destination any) error {
	if err := xml.NewDecoder(r).Decode(destination); err != nil {
		return s3errors.GetAPIError(s3errors.ErrMalformedXML)
	}

	return nil
}

func (h *handler) PutBucketOwnershipControlsHandler(w http.ResponseWriter, r *http.Request) {
	var (
		reqInfo = api.GetReqInfo(r.Context())
		params  putBucketOwnershipControlsParams
	)

	defer func() {
		_ = r.Body.Close()
	}()

	if err := decodeXML(r.Body, &params); err != nil {
		h.logAndSendError(w, "could not parse body", reqInfo, err)
		return
	}

	if len(params.Rules) == 0 {
		h.logAndSendError(w, "empty rules list", reqInfo, s3errors.GetAPIError(s3errors.ErrEmptyRequestBody))
		return
	}

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket objInfo", reqInfo, err)
		return
	}

	bktSettings, err := h.obj.GetBucketSettings(r.Context(), bktInfo)
	if err != nil {
		h.logAndSendError(w, "could not get bucket settings", reqInfo, err)
		return
	}

	switch params.Rules[0].ObjectOwnership {
	case amzBucketOwnerEnforced:
		bktSettings.BucketOwner = data.BucketOwnerEnforced
	case amzBucketOwnerPreferred:
		bktSettings.BucketOwner = data.BucketOwnerPreferred
	case amzBucketOwnerObjectWriter:
		bktSettings.BucketOwner = data.BucketOwnerObjectWriter
	default:
		h.logAndSendError(w, "invalid ownership", reqInfo, s3errors.GetAPIError(s3errors.ErrBadRequest))
		return
	}

	if expectedBucketOwner := r.Header.Get(xAmzExpectedBucketOwner); expectedBucketOwner != "" {
		if expectedBucketOwner != bktInfo.Owner.String() {
			h.logAndSendError(w, "bucket owner mismatch", reqInfo, s3errors.GetAPIError(s3errors.ErrAccessDenied))
		}
	}

	sp := &layer.PutSettingsParams{
		BktInfo:  bktInfo,
		Settings: bktSettings,
	}

	if err = h.obj.PutBucketSettings(r.Context(), sp); err != nil {
		h.logAndSendError(w, "couldn't put bucket settings", reqInfo, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (h *handler) GetBucketOwnershipControlsHandler(w http.ResponseWriter, r *http.Request) {
	var (
		reqInfo  = api.GetReqInfo(r.Context())
		response *putBucketOwnershipControlsParams
	)

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket objInfo", reqInfo, err)
		return
	}

	if expectedBucketOwner := r.Header.Get(xAmzExpectedBucketOwner); expectedBucketOwner != "" {
		if expectedBucketOwner != bktInfo.Owner.String() {
			h.logAndSendError(w, "bucket owner mismatch", reqInfo, s3errors.GetAPIError(s3errors.ErrAccessDenied))
		}
	}

	settings, err := h.obj.GetBucketSettings(r.Context(), bktInfo)
	if err != nil {
		h.logAndSendError(w, "could not get bucket settings", reqInfo, err)
		return
	}

	switch settings.BucketOwner {
	case data.BucketOwnerEnforced:
		response = &putBucketOwnershipControlsParams{
			Rules: []objectOwnershipRules{{ObjectOwnership: amzBucketOwnerEnforced}},
		}
	case data.BucketOwnerPreferred:
		response = &putBucketOwnershipControlsParams{
			Rules: []objectOwnershipRules{{ObjectOwnership: amzBucketOwnerPreferred}},
		}
	case data.BucketOwnerObjectWriter:
		response = &putBucketOwnershipControlsParams{
			Rules: []objectOwnershipRules{{ObjectOwnership: amzBucketOwnerObjectWriter}},
		}
	default:
		api.WriteSuccessResponseHeadersOnly(w)
		return
	}

	if err = api.EncodeToResponse(w, response); err != nil {
		h.logAndSendError(w, "something went wrong", reqInfo, err)
	}
}

func (h *handler) DeleteBucketOwnershipControlsHandler(w http.ResponseWriter, r *http.Request) {
	var (
		reqInfo = api.GetReqInfo(r.Context())
	)

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket objInfo", reqInfo, err)
		return
	}

	if expectedBucketOwner := r.Header.Get(xAmzExpectedBucketOwner); expectedBucketOwner != "" {
		if expectedBucketOwner != bktInfo.Owner.String() {
			h.logAndSendError(w, "bucket owner mismatch", reqInfo, s3errors.GetAPIError(s3errors.ErrAccessDenied))
		}
	}

	settings, err := h.obj.GetBucketSettings(r.Context(), bktInfo)
	if err != nil {
		h.logAndSendError(w, "could not get bucket settings", reqInfo, err)
		return
	}

	settings.BucketOwner = data.BucketOwnerEnforced

	p := layer.PutSettingsParams{
		BktInfo:  bktInfo,
		Settings: settings,
	}

	if err = h.obj.PutBucketSettings(r.Context(), &p); err != nil {
		h.logAndSendError(w, "couldn't put bucket settings", reqInfo, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}
