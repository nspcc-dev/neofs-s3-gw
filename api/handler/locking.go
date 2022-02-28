package handler

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	apiErrors "github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
)

const (
	dayDuration  = 24 * time.Hour
	yearDuration = 365 * dayDuration

	enabledValue   = "Enabled"
	governanceMode = "GOVERNANCE"
	complianceMode = "COMPLIANCE"
	legalHoldOn    = "ON"
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
	if retention.Mode != governanceMode && retention.Mode != complianceMode {
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

func formObjectLock(objectLock *data.ObjectLock, bktInfo *data.BucketInfo, defaultConfig *data.ObjectLockConfiguration, header http.Header) error {
	if !bktInfo.ObjectLockEnabled {
		if existLockHeaders(header) {
			return apiErrors.GetAPIError(apiErrors.ErrObjectLockConfigurationNotFound)
		}
		return nil
	}

	if defaultConfig == nil {
		defaultConfig = &data.ObjectLockConfiguration{}
	}

	if defaultConfig.Rule != nil && defaultConfig.Rule.DefaultRetention != nil {
		defaultRetention := defaultConfig.Rule.DefaultRetention
		objectLock.IsCompliance = defaultRetention.Mode == complianceMode
		now := time.Now()
		if defaultRetention.Days != 0 {
			objectLock.Until = now.Add(time.Duration(defaultRetention.Days) * dayDuration)
		} else {
			objectLock.Until = now.Add(time.Duration(defaultRetention.Years) * yearDuration)
		}
	}

	objectLock.LegalHold = header.Get(api.AmzObjectLockLegalHold) == legalHoldOn

	mode := header.Get(api.AmzObjectLockMode)
	if mode != "" {
		objectLock.IsCompliance = mode == complianceMode
	}

	until := header.Get(api.AmzObjectLockRetainUntilDate)
	if until != "" {
		retentionDate, err := time.Parse(time.RFC3339, until)
		if err != nil {
			return fmt.Errorf("invalid header %s: '%s'", api.AmzObjectLockRetainUntilDate, until)
		}
		objectLock.Until = retentionDate
	}

	return nil
}

func existLockHeaders(header http.Header) bool {
	return header.Get(api.AmzObjectLockMode) != "" ||
		header.Get(api.AmzObjectLockLegalHold) != "" ||
		header.Get(api.AmzObjectLockRetainUntilDate) != ""
}
