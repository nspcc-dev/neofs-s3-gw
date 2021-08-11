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

	if _, err := h.obj.PutBucketVersioning(r.Context(), p); err != nil {
		h.logAndSendError(w, "couldn't put update versioning settings", reqInfo, err)
	}
}

// GetBucketVersioningHandler implements bucket versioning getter handler.
func (h *handler) GetBucketVersioningHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	settings, err := h.obj.GetBucketVersioning(r.Context(), reqInfo.BucketName)
	if err != nil {
		h.log.Warn("couldn't get version settings object: default version settings will be used",
			zap.String("request_id", reqInfo.RequestID),
			zap.String("method", reqInfo.API),
			zap.String("object_name", reqInfo.ObjectName),
			zap.Error(err))
		return
	}

	if err = api.EncodeToResponse(w, formVersioningConfiguration(settings)); err != nil {
		h.logAndSendError(w, "something went wrong", reqInfo, err)
	}
}

func formVersioningConfiguration(settings *layer.BucketSettings) *VersioningConfiguration {
	res := &VersioningConfiguration{Status: "Suspended"}
	if settings == nil {
		return res
	}
	if settings.VersioningEnabled {
		res.Status = "Enabled"
	}
	return res
}
