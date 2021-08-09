package handler

import (
	"encoding/xml"
	"net/http"
	"strconv"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"go.uber.org/zap"
)

func (h *handler) PutBucketVersioningHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	configuration := new(VersioningConfiguration)
	if err := xml.NewDecoder(r.Body).Decode(configuration); err != nil {
		h.logAndSendError(w, "couldn't decode versioning configuration", reqInfo, api.GetAPIError(api.ErrIllegalVersioningConfigurationException))
		return
	}

	p := &layer.PutVersioningParams{
		Bucket:            reqInfo.BucketName,
		VersioningEnabled: configuration.Status == "Enabled",
	}

	if _, err := h.obj.PutBucketVersioning(r.Context(), p); err != nil {
		h.logAndSendError(w, "couldn't put update versioning settings", reqInfo, err)
	}
}

// GetBucketVersioningHandler implements bucket versioning getter handler.
func (h *handler) GetBucketVersioningHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	objInfo, err := h.obj.GetBucketVersioning(r.Context(), reqInfo.BucketName)
	if err != nil {
		h.log.Warn("couldn't get version settings object: default version settings will be used",
			zap.String("request_id", reqInfo.RequestID),
			zap.String("method", reqInfo.API),
			zap.String("object_name", reqInfo.ObjectName),
			zap.Error(err))
	}

	if err = api.EncodeToResponse(w, formVersioningConfiguration(objInfo)); err != nil {
		h.logAndSendError(w, "something went wrong", reqInfo, err)
	}
}

func formVersioningConfiguration(inf *layer.ObjectInfo) *VersioningConfiguration {
	res := &VersioningConfiguration{Status: "Suspended"}

	if inf == nil {
		return res
	}

	enabled, ok := inf.Headers["S3-Settings-Versioning-enabled"]
	if ok {
		if parsed, err := strconv.ParseBool(enabled); err == nil && parsed {
			res.Status = "Enabled"
		}
	}
	return res
}
