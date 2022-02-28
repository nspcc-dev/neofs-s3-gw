package handler

import (
	"encoding/xml"
	"fmt"
	"net/http"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	apiErrors "github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
)

func (h *handler) PutBucketObjectLockConfigHandler(w http.ResponseWriter, r *http.Request) {
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

	if !bktInfo.ObjectLockEnabled {
		h.logAndSendError(w, "couldn't put object locking configuration", reqInfo,
			apiErrors.GetAPIError(apiErrors.ErrObjectLockConfigurationNotAllowed))
		return
	}

	lockingConf := &data.ObjectLockConfiguration{}
	if err = xml.NewDecoder(r.Body).Decode(lockingConf); err != nil {
		h.logAndSendError(w, "couldn't parse locking configuration", reqInfo, err)
		return
	}

	if err = checkLockConfiguration(lockingConf); err != nil {
		h.logAndSendError(w, "invalid lock configuration", reqInfo, err)
		return
	}

	settings, err := h.obj.GetBucketSettings(r.Context(), bktInfo)
	if err != nil {
		h.logAndSendError(w, "couldn't get bucket settings", reqInfo, err)
		return
	}

	settings.LockConfiguration = lockingConf

	sp := &layer.PutSettingsParams{
		BktInfo:  bktInfo,
		Settings: settings,
	}

	if err = h.obj.PutBucketSettings(r.Context(), sp); err != nil {
		h.logAndSendError(w, "couldn't put bucket settings", reqInfo, err)
		return
	}
}

func (h *handler) GetBucketObjectLockConfigHandler(w http.ResponseWriter, r *http.Request) {
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

	settings, err := h.obj.GetBucketSettings(r.Context(), bktInfo)
	if err != nil {
		h.logAndSendError(w, "couldn't get bucket settings", reqInfo, err)
		return
	}

	if !bktInfo.ObjectLockEnabled {
		h.logAndSendError(w, "object lock disabled", reqInfo,
			apiErrors.GetAPIError(apiErrors.ErrObjectLockConfigurationNotFound))
		return
	}

	if settings.LockConfiguration == nil {
		settings.LockConfiguration = &data.ObjectLockConfiguration{}
	}
	if settings.LockConfiguration.ObjectLockEnabled == "" {
		settings.LockConfiguration.ObjectLockEnabled = enabledValue
	}

	if err = api.EncodeToResponse(w, settings.LockConfiguration); err != nil {
		h.logAndSendError(w, "something went wrong", reqInfo, err)
	}
}

func checkLockConfiguration(conf *data.ObjectLockConfiguration) error {
	if conf.ObjectLockEnabled != "" && conf.ObjectLockEnabled != enabledValue {
		return fmt.Errorf("invalid ObjectLockEnabled value: %s", conf.ObjectLockEnabled)
	}

	if conf.Rule == nil || conf.Rule.DefaultRetention == nil {
		return nil
	}

	retention := conf.Rule.DefaultRetention
	if retention.Mode != "GOVERNANCE" && retention.Mode != "COMPLIANCE" {
		return fmt.Errorf("invalid Mode value: %s", retention.Mode)
	}

	if retention.Days == 0 && retention.Years == 0 {
		return fmt.Errorf("you must specify Days or Years")
	}

	if retention.Days != 0 && retention.Years != 0 {
		return fmt.Errorf("you cannot specify Days and Years at the same time")
	}

	return nil
}
