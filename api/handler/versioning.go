package handler

import (
	"encoding/xml"
	"fmt"
	"net/http"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
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

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	settings, err := h.obj.GetBucketSettings(r.Context(), bktInfo)
	if err != nil {
		h.logAndSendError(w, "couldn't get bucket settings", reqInfo, err)
		return
	}

	settings.VersioningEnabled = configuration.Status == "Enabled"
	settings.IsNoneStatus = false

	p := &layer.PutSettingsParams{
		BktInfo:  bktInfo,
		Settings: settings,
	}

	if !p.Settings.VersioningEnabled && bktInfo.ObjectLockEnabled {
		h.logAndSendError(w, "couldn't suspend bucket versioning", reqInfo, fmt.Errorf("object lock is enabled"))
		return
	}

	if err = h.obj.PutBucketSettings(r.Context(), p); err != nil {
		h.logAndSendError(w, "couldn't put update versioning settings", reqInfo, err)
	}
}

// GetBucketVersioningHandler implements bucket versioning getter handler.
func (h *handler) GetBucketVersioningHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	settings, err := h.obj.GetBucketSettings(r.Context(), bktInfo)
	if err != nil {
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

func formVersioningConfiguration(settings *data.BucketSettings) *VersioningConfiguration {
	res := &VersioningConfiguration{}
	if settings.IsNoneStatus {
		return res
	}
	if settings.VersioningEnabled {
		res.Status = "Enabled"
	} else {
		res.Status = "Suspended"
	}
	return res
}
