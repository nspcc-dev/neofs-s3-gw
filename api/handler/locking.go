package handler

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3errors"
)

const (
	dayDuration  = 24 * time.Hour
	yearDuration = 365 * dayDuration

	enabledValue   = "Enabled"
	governanceMode = "GOVERNANCE"
	complianceMode = "COMPLIANCE"
	legalHoldOn    = "ON"
	legalHoldOff   = "OFF"
)

var (
	errEmptyDaysErrors    = errors.New("you must specify Days or Years")
	errNonEmptyDaysErrors = errors.New("you cannot specify Days and Years at the same time")
)

func (h *handler) PutBucketObjectLockConfigHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	if !bktInfo.ObjectLockEnabled {
		h.logAndSendError(w, "couldn't put object locking configuration", reqInfo,
			s3errors.GetAPIError(s3errors.ErrObjectLockConfigurationNotAllowed))
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

	// settings pointer is stored in the cache, so modify a copy of the settings
	newSettings := *settings
	newSettings.LockConfiguration = lockingConf

	sp := &layer.PutSettingsParams{
		BktInfo:      bktInfo,
		Settings:     &newSettings,
		CopiesNumber: h.cfg.CopiesNumber,
	}

	if err = h.obj.PutBucketSettings(r.Context(), sp); err != nil {
		h.logAndSendError(w, "couldn't put bucket settings", reqInfo, err)
		return
	}
}

func (h *handler) GetBucketObjectLockConfigHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	if !bktInfo.ObjectLockEnabled {
		h.logAndSendError(w, "object lock disabled", reqInfo,
			s3errors.GetAPIError(s3errors.ErrObjectLockConfigurationNotFound))
		return
	}

	settings, err := h.obj.GetBucketSettings(r.Context(), bktInfo)
	if err != nil {
		h.logAndSendError(w, "couldn't get bucket settings", reqInfo, err)
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

func (h *handler) PutObjectLegalHoldHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	if !bktInfo.ObjectLockEnabled {
		h.logAndSendError(w, "object lock disabled", reqInfo,
			s3errors.GetAPIError(s3errors.ErrObjectLockConfigurationNotFound))
		return
	}

	legalHold := &data.LegalHold{}
	if err = xml.NewDecoder(r.Body).Decode(legalHold); err != nil {
		h.logAndSendError(w, "couldn't parse legal hold configuration", reqInfo, err)
		return
	}

	if legalHold.Status != legalHoldOn && legalHold.Status != legalHoldOff {
		h.logAndSendError(w, "invalid legal hold status", reqInfo,
			fmt.Errorf("invalid status %s", legalHold.Status))
		return
	}

	p := &layer.PutLockInfoParams{
		ObjVersion: &layer.ObjectVersion{
			BktInfo:    bktInfo,
			ObjectName: reqInfo.ObjectName,
			VersionID:  reqInfo.URL.Query().Get(api.QueryVersionID),
		},
		NewLock: &data.ObjectLock{
			LegalHold: &data.LegalHoldLock{
				Enabled: legalHold.Status == legalHoldOn,
			},
		},
		CopiesNumber: h.cfg.CopiesNumber,
	}

	if p.ObjVersion.VersionID == "" {
		shortInfoParams := &layer.ShortInfoParams{
			Owner:  bktInfo.Owner,
			CID:    bktInfo.CID,
			Object: reqInfo.ObjectName,
		}

		ei, err := h.obj.GetIDForVersioningContainer(r.Context(), shortInfoParams)
		if err != nil {
			h.logAndSendError(w, "could not find object", reqInfo, err)
			return
		}

		p.ObjVersion.VersionID = ei.EncodeToString()
	}

	if err = h.obj.PutLockInfo(r.Context(), p); err != nil {
		h.logAndSendError(w, "couldn't head put legal hold", reqInfo, err)
		return
	}
}

func (h *handler) GetObjectLegalHoldHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	if !bktInfo.ObjectLockEnabled {
		h.logAndSendError(w, "object lock disabled", reqInfo,
			s3errors.GetAPIError(s3errors.ErrObjectLockConfigurationNotFound))
		return
	}

	p := &layer.ObjectVersion{
		BktInfo:    bktInfo,
		ObjectName: reqInfo.ObjectName,
		VersionID:  reqInfo.URL.Query().Get(api.QueryVersionID),
	}

	lockInfo, err := h.obj.GetLockInfo(r.Context(), p)
	if err != nil {
		h.logAndSendError(w, "couldn't head lock object", reqInfo, err)
		return
	}

	legalHold := &data.LegalHold{Status: legalHoldOff}
	if lockInfo.IsLegalHoldSet() {
		legalHold.Status = legalHoldOn
	}

	if err = api.EncodeToResponse(w, legalHold); err != nil {
		h.logAndSendError(w, "something went wrong", reqInfo, err)
	}
}

func (h *handler) PutObjectRetentionHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}
	if !bktInfo.ObjectLockEnabled {
		h.logAndSendError(w, "object lock disabled", reqInfo,
			s3errors.GetAPIError(s3errors.ErrObjectLockConfigurationNotFound))
		return
	}

	retention := &data.Retention{}
	if err = xml.NewDecoder(r.Body).Decode(retention); err != nil {
		h.logAndSendError(w, "couldn't parse object retention", reqInfo, err)
		return
	}

	lock, err := formObjectLockFromRetention(r.Context(), retention, r.Header)
	if err != nil {
		h.logAndSendError(w, "invalid retention configuration", reqInfo, err)
		return
	}

	p := &layer.PutLockInfoParams{
		ObjVersion: &layer.ObjectVersion{
			BktInfo:    bktInfo,
			ObjectName: reqInfo.ObjectName,
			VersionID:  reqInfo.URL.Query().Get(api.QueryVersionID),
		},
		NewLock:      lock,
		CopiesNumber: h.cfg.CopiesNumber,
	}

	settings, err := h.obj.GetBucketSettings(r.Context(), bktInfo)
	if err != nil {
		h.logAndSendError(w, "could not get bucket settings", reqInfo, err)
		return
	}

	if settings.VersioningEnabled() && p.ObjVersion.VersionID == "" {
		shortInfoParams := &layer.ShortInfoParams{
			Owner:  bktInfo.Owner,
			CID:    bktInfo.CID,
			Object: reqInfo.ObjectName,
		}

		ei, err := h.obj.GetIDForVersioningContainer(r.Context(), shortInfoParams)
		if err != nil {
			h.logAndSendError(w, "could not find object", reqInfo, err)
			return
		}

		p.ObjVersion.VersionID = ei.EncodeToString()
	}

	if err = h.obj.PutLockInfo(r.Context(), p); err != nil {
		h.logAndSendError(w, "couldn't put legal hold", reqInfo, err)
		return
	}
}

func (h *handler) GetObjectRetentionHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	if !bktInfo.ObjectLockEnabled {
		h.logAndSendError(w, "object lock disabled", reqInfo,
			s3errors.GetAPIError(s3errors.ErrObjectLockConfigurationNotFound))
		return
	}

	settings, err := h.obj.GetBucketSettings(r.Context(), bktInfo)
	if err != nil {
		h.logAndSendError(w, "could not get bucket settings", reqInfo, err)
		return
	}

	p := &layer.ObjectVersion{
		BktInfo:    bktInfo,
		ObjectName: reqInfo.ObjectName,
		VersionID:  reqInfo.URL.Query().Get(api.QueryVersionID),
	}

	if settings.VersioningEnabled() && p.VersionID == "" {
		shortInfoParams := &layer.ShortInfoParams{
			Owner:  bktInfo.Owner,
			CID:    bktInfo.CID,
			Object: reqInfo.ObjectName,
		}

		ei, err := h.obj.GetIDForVersioningContainer(r.Context(), shortInfoParams)
		if err != nil {
			h.logAndSendError(w, "could not find object", reqInfo, err)
			return
		}

		p.VersionID = ei.EncodeToString()
	}

	lockInfo, err := h.obj.GetLockInfo(r.Context(), p)
	if err != nil {
		h.logAndSendError(w, "couldn't head lock object", reqInfo, err)
		return
	}

	if !lockInfo.IsRetentionSet() {
		h.logAndSendError(w, "retention lock isn't set", reqInfo, s3errors.GetAPIError(s3errors.ErrNoSuchKey))
		return
	}

	retention := &data.Retention{
		Mode:            governanceMode,
		RetainUntilDate: lockInfo.UntilDate(),
	}
	if lockInfo.IsCompliance() {
		retention.Mode = complianceMode
	}

	if err = api.EncodeToResponse(w, retention); err != nil {
		h.logAndSendError(w, "something went wrong", reqInfo, err)
	}
}

func checkLockConfiguration(conf *data.ObjectLockConfiguration) error {
	if conf.ObjectLockEnabled != "" && conf.ObjectLockEnabled != enabledValue {
		return s3errors.GetAPIErrorWithError(s3errors.ErrMalformedXML, fmt.Errorf("invalid ObjectLockEnabled value: %s", conf.ObjectLockEnabled))
	}

	if conf.Rule == nil || conf.Rule.DefaultRetention == nil {
		return nil
	}

	retention := conf.Rule.DefaultRetention
	if retention.Mode != governanceMode && retention.Mode != complianceMode {
		return s3errors.GetAPIErrorWithError(s3errors.ErrMalformedXML, fmt.Errorf("invalid Mode value: %s", retention.Mode))
	}

	if retention.Days <= 0 && retention.Years <= 0 {
		return s3errors.GetAPIErrorWithError(s3errors.ErrMalformedXML, errEmptyDaysErrors)
	}

	if retention.Days != 0 && retention.Years != 0 {
		return s3errors.GetAPIErrorWithError(s3errors.ErrMalformedXML, errNonEmptyDaysErrors)
	}

	return nil
}

func formObjectLock(ctx context.Context, bktInfo *data.BucketInfo, defaultConfig *data.ObjectLockConfiguration, header http.Header) (*data.ObjectLock, error) {
	if !bktInfo.ObjectLockEnabled {
		if existLockHeaders(header) {
			return nil, s3errors.GetAPIError(s3errors.ErrObjectLockConfigurationNotFound)
		}
		return nil, nil
	}

	objectLock := &data.ObjectLock{}

	if defaultConfig == nil {
		defaultConfig = &data.ObjectLockConfiguration{}
	}

	if defaultConfig.Rule != nil && defaultConfig.Rule.DefaultRetention != nil {
		retention := &data.RetentionLock{}
		defaultRetention := defaultConfig.Rule.DefaultRetention
		retention.IsCompliance = defaultRetention.Mode == complianceMode
		now := layer.TimeNow(ctx)
		if defaultRetention.Days != 0 {
			retention.Until = now.Add(time.Duration(defaultRetention.Days) * dayDuration)
		} else {
			retention.Until = now.Add(time.Duration(defaultRetention.Years) * yearDuration)
		}
		objectLock.Retention = retention
	}

	if header.Get(api.AmzObjectLockLegalHold) == legalHoldOn {
		objectLock.LegalHold = &data.LegalHoldLock{Enabled: true}
	}

	mode := header.Get(api.AmzObjectLockMode)
	until := header.Get(api.AmzObjectLockRetainUntilDate)

	if mode != "" && until == "" || mode == "" && until != "" {
		return nil, s3errors.GetAPIError(s3errors.ErrObjectLockInvalidHeaders)
	}

	if mode != "" {
		if objectLock.Retention == nil {
			objectLock.Retention = &data.RetentionLock{}
		}

		if mode != complianceMode && mode != governanceMode {
			return nil, s3errors.GetAPIError(s3errors.ErrUnknownWORMModeDirective)
		}

		objectLock.Retention.IsCompliance = mode == complianceMode
	}

	if until != "" {
		retentionDate, err := time.Parse(time.RFC3339, until)
		if err != nil {
			return nil, s3errors.GetAPIError(s3errors.ErrInvalidRetentionDate)
		}
		if objectLock.Retention == nil {
			objectLock.Retention = &data.RetentionLock{}
		}
		objectLock.Retention.Until = retentionDate
	}

	if objectLock.Retention != nil {
		if bypassStr := header.Get(api.AmzBypassGovernanceRetention); len(bypassStr) > 0 {
			bypass, err := strconv.ParseBool(bypassStr)
			if err != nil {
				return nil, fmt.Errorf("couldn't parse bypass governance header: %w", err)
			}
			objectLock.Retention.ByPassedGovernance = bypass
		}

		if objectLock.Retention.Until.Before(layer.TimeNow(ctx)) {
			return nil, s3errors.GetAPIError(s3errors.ErrPastObjectLockRetainDate)
		}
	}

	return objectLock, nil
}

func existLockHeaders(header http.Header) bool {
	return header.Get(api.AmzObjectLockMode) != "" ||
		header.Get(api.AmzObjectLockLegalHold) != "" ||
		header.Get(api.AmzObjectLockRetainUntilDate) != ""
}

func formObjectLockFromRetention(ctx context.Context, retention *data.Retention, header http.Header) (*data.ObjectLock, error) {
	if retention.Mode != governanceMode && retention.Mode != complianceMode {
		return nil, s3errors.GetAPIError(s3errors.ErrMalformedXML)
	}

	retentionDate, err := time.Parse(time.RFC3339, retention.RetainUntilDate)
	if err != nil {
		return nil, s3errors.GetAPIError(s3errors.ErrMalformedXML)
	}

	if retentionDate.Before(layer.TimeNow(ctx)) {
		return nil, s3errors.GetAPIError(s3errors.ErrPastObjectLockRetainDate)
	}

	var bypass bool
	if bypassStr := header.Get(api.AmzBypassGovernanceRetention); len(bypassStr) > 0 {
		bypass, err = strconv.ParseBool(bypassStr)
		if err != nil {
			return nil, fmt.Errorf("couldn't parse bypass governance header: %w", err)
		}
	}

	lock := &data.ObjectLock{
		Retention: &data.RetentionLock{
			Until:              retentionDate,
			IsCompliance:       retention.Mode == complianceMode,
			ByPassedGovernance: bypass,
		},
	}

	return lock, nil
}
