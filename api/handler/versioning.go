package handler

import (
	"encoding/xml"
	"net/http"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"go.uber.org/zap"
)

func (h *handler) PutBucketVersioningHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	configuration := new(VersioningConfiguration)
	if err := xml.NewDecoder(r.Body).Decode(configuration); err != nil {
		h.logAndSendError(w, "couldn't decode versioning configuration", reqInfo, errors.GetAPIError(errors.ErrIllegalVersioningConfigurationException))
		return
	}

	p := &layer.PutVersioningParams{
		Bucket:   reqInfo.BucketName,
		Settings: &layer.BucketSettings{VersioningEnabled: configuration.Status == "Enabled"},
	}

	bktInfo, err := h.obj.GetBucketInfo(r.Context(), reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}
	if err = checkOwner(bktInfo, r.Header.Get(api.AmzExpectedBucketOwner)); err != nil {
		h.logAndSendError(w, "expected owner doesn't match", reqInfo, err)
		return
	}

	if _, err := h.obj.PutBucketVersioning(r.Context(), p); err != nil {
		h.logAndSendError(w, "couldn't put update versioning settings", reqInfo, err)
	}
	w.WriteHeader(http.StatusOK)
}

// GetBucketVersioningHandler implements bucket versioning getter handler.
func (h *handler) GetBucketVersioningHandler(w http.ResponseWriter, r *http.Request) {
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

	settings, err := h.obj.GetBucketVersioning(r.Context(), reqInfo.BucketName)
	if err != nil {
		if errors.IsS3Error(err, errors.ErrNoSuchBucket) {
			h.logAndSendError(w, "couldn't get versioning settings", reqInfo, err)
			return
		}
		h.log.Warn("couldn't get version settings object: default version settings will be used",
			zap.String("request_id", reqInfo.RequestID),
			zap.String("method", reqInfo.API),
			zap.String("bucket_name", reqInfo.BucketName),
			zap.Error(err))
	}

	if err = api.EncodeToResponse(w, formVersioningConfiguration(settings)); err != nil {
		h.logAndSendError(w, "something went wrong", reqInfo, err)
	}
}

func formVersioningConfiguration(settings *layer.BucketSettings) *VersioningConfiguration {
	res := &VersioningConfiguration{}
	if settings == nil {
		return res
	}
	if settings.VersioningEnabled {
		res.Status = "Enabled"
	} else {
		res.Status = "Suspended"
	}
	return res
}
