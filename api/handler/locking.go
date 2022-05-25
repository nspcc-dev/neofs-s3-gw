package handler

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	apiErrors "github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
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

func (h *handler) PutBucketObjectLockConfigHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
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

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	if !bktInfo.ObjectLockEnabled {
		h.logAndSendError(w, "object lock disabled", reqInfo,
			apiErrors.GetAPIError(apiErrors.ErrObjectLockConfigurationNotFound))
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
			apiErrors.GetAPIError(apiErrors.ErrObjectLockConfigurationNotFound))
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

	p := &layer.HeadObjectParams{
		BktInfo:   bktInfo,
		Object:    reqInfo.ObjectName,
		VersionID: reqInfo.URL.Query().Get(api.QueryVersionID),
	}

	objInfo, err := h.obj.GetObjectInfo(r.Context(), p)
	if err != nil {
		h.logAndSendError(w, "could not get object info", reqInfo, err)
		return
	}

	lockInfo, err := h.obj.HeadSystemObject(r.Context(), bktInfo, objInfo.LegalHoldObject())
	if err != nil && !apiErrors.IsS3Error(err, apiErrors.ErrNoSuchKey) {
		h.logAndSendError(w, "couldn't head lock object", reqInfo, err)
		return
	}

	if lockInfo == nil && legalHold.Status == legalHoldOff ||
		lockInfo != nil && legalHold.Status == legalHoldOn {
		return
	}

	if lockInfo != nil {
		if err = h.obj.DeleteSystemObject(r.Context(), bktInfo, objInfo.LegalHoldObject()); err != nil {
			h.logAndSendError(w, "couldn't delete legal hold", reqInfo, err)
			return
		}
	} else {
		ps := &layer.PutSystemObjectParams{
			BktInfo:  bktInfo,
			ObjName:  objInfo.LegalHoldObject(),
			Lock:     &data.ObjectLock{LegalHold: true, Objects: []oid.ID{objInfo.ID}},
			Metadata: make(map[string]string),
		}
		if _, err = h.obj.PutSystemObject(r.Context(), ps); err != nil {
			h.logAndSendError(w, "couldn't put legal hold", reqInfo, err)
			return
		}
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
			apiErrors.GetAPIError(apiErrors.ErrObjectLockConfigurationNotFound))
		return
	}

	p := &layer.HeadObjectParams{
		BktInfo:   bktInfo,
		Object:    reqInfo.ObjectName,
		VersionID: reqInfo.URL.Query().Get(api.QueryVersionID),
	}

	objInfo, err := h.obj.GetObjectInfo(r.Context(), p)
	if err != nil {
		h.logAndSendError(w, "could not get object info", reqInfo, err)
		return
	}

	lockInfo, err := h.obj.HeadSystemObject(r.Context(), bktInfo, objInfo.LegalHoldObject())
	if err != nil && !apiErrors.IsS3Error(err, apiErrors.ErrNoSuchKey) {
		h.logAndSendError(w, "couldn't head lock object", reqInfo, err)
		return
	}

	legalHold := &data.LegalHold{Status: legalHoldOff}
	if lockInfo != nil {
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
			apiErrors.GetAPIError(apiErrors.ErrObjectLockConfigurationNotFound))
		return
	}

	retention := &data.Retention{}
	if err = xml.NewDecoder(r.Body).Decode(retention); err != nil {
		h.logAndSendError(w, "couldn't parse object retention", reqInfo, err)
		return
	}

	lock, err := formObjectLockFromRetention(retention, r.Header)
	if err != nil {
		h.logAndSendError(w, "invalid retention configuration", reqInfo, err)
		return
	}

	p := &layer.HeadObjectParams{
		BktInfo:   bktInfo,
		Object:    reqInfo.ObjectName,
		VersionID: reqInfo.URL.Query().Get(api.QueryVersionID),
	}

	objInfo, err := h.obj.GetObjectInfo(r.Context(), p)
	if err != nil {
		h.logAndSendError(w, "could not get object info", reqInfo, err)
		return
	}
	lock.Objects = append(lock.Objects, objInfo.ID)

	lockInfo, err := h.obj.HeadSystemObject(r.Context(), bktInfo, objInfo.RetentionObject())
	if err != nil && !apiErrors.IsS3Error(err, apiErrors.ErrNoSuchKey) {
		h.logAndSendError(w, "couldn't head lock object", reqInfo, err)
		return
	}

	if err = checkLockInfo(lockInfo, r.Header); err != nil {
		h.logAndSendError(w, "couldn't change lock mode", reqInfo, err)
		return
	}

	ps := &layer.PutSystemObjectParams{
		BktInfo:  bktInfo,
		ObjName:  objInfo.RetentionObject(),
		Lock:     lock,
		Metadata: make(map[string]string),
	}
	if _, err = h.obj.PutSystemObject(r.Context(), ps); err != nil {
		h.logAndSendError(w, "couldn't put legal hold", reqInfo, err)
		return
	}
}

func checkLockInfo(lock *data.ObjectInfo, header http.Header) error {
	if lock == nil {
		return nil
	}

	if lock.Headers[layer.AttributeComplianceMode] != "" {
		return fmt.Errorf("it's forbidden to change compliance lock mode")
	}

	if bypass, err := strconv.ParseBool(header.Get(api.AmzBypassGovernanceRetention)); err != nil || !bypass {
		return fmt.Errorf("cannot bypass governance mode")
	}

	return nil
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
			apiErrors.GetAPIError(apiErrors.ErrObjectLockConfigurationNotFound))
		return
	}

	p := &layer.HeadObjectParams{
		BktInfo:   bktInfo,
		Object:    reqInfo.ObjectName,
		VersionID: reqInfo.URL.Query().Get(api.QueryVersionID),
	}

	objInfo, err := h.obj.GetObjectInfo(r.Context(), p)
	if err != nil {
		h.logAndSendError(w, "could not get object info", reqInfo, err)
		return
	}

	lockInfo, err := h.obj.HeadSystemObject(r.Context(), bktInfo, objInfo.RetentionObject())
	if err != nil {
		h.logAndSendError(w, "couldn't head lock object", reqInfo, err)
		return
	}

	retention := &data.Retention{
		Mode:            governanceMode,
		RetainUntilDate: lockInfo.Headers[layer.AttributeRetainUntil],
	}
	if lockInfo.Headers[layer.AttributeComplianceMode] != "" {
		retention.Mode = complianceMode
	}

	if err = api.EncodeToResponse(w, retention); err != nil {
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

func formObjectLock(bktInfo *data.BucketInfo, defaultConfig *data.ObjectLockConfiguration, header http.Header) (*data.ObjectLock, error) {
	if !bktInfo.ObjectLockEnabled {
		if existLockHeaders(header) {
			return nil, apiErrors.GetAPIError(apiErrors.ErrObjectLockConfigurationNotFound)
		}
		return nil, nil
	}

	objectLock := &data.ObjectLock{}

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
			return nil, fmt.Errorf("invalid header %s: '%s'", api.AmzObjectLockRetainUntilDate, until)
		}
		objectLock.Until = retentionDate
	}

	return objectLock, nil
}

func existLockHeaders(header http.Header) bool {
	return header.Get(api.AmzObjectLockMode) != "" ||
		header.Get(api.AmzObjectLockLegalHold) != "" ||
		header.Get(api.AmzObjectLockRetainUntilDate) != ""
}

func formObjectLockFromRetention(retention *data.Retention, header http.Header) (*data.ObjectLock, error) {
	if retention.Mode != governanceMode && retention.Mode != complianceMode {
		return nil, fmt.Errorf("invalid retention mode: %s", retention.Mode)
	}

	retentionDate, err := time.Parse(time.RFC3339, retention.RetainUntilDate)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse retain until date: %s", retention.RetainUntilDate)
	}

	lock := &data.ObjectLock{
		Until:        retentionDate,
		IsCompliance: retention.Mode == complianceMode,
	}

	return lock, nil
}
