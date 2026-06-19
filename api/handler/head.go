package handler

import (
	"bytes"
	"net/http"
	"strings"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3errors"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3headers"
	"go.uber.org/zap"
)

const sizeToDetectType = 512

func getRangeToDetectContentType(maxSize int64) *layer.RangeParams {
	end := min(sizeToDetectType, uint64(maxSize))

	return &layer.RangeParams{
		Start: 0,
		End:   end - 1,
	}
}

func (h *handler) HeadObjectHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	conditional, err := parseConditionalHeaders(r.Header)
	if err != nil {
		h.logAndSendError(w, "could not parse request params", reqInfo, err)
		return
	}

	p := &layer.HeadObjectParams{
		BktInfo:                   bktInfo,
		Object:                    reqInfo.ObjectName,
		VersionID:                 reqInfo.URL.Query().Get(api.QueryVersionID),
		IsBucketVersioningEnabled: bktInfo.Settings.VersioningEnabled(),
	}

	comprehensiveInfo, err := h.obj.ComprehensiveObjectInfo(r.Context(), p)
	if err != nil {
		h.logAndSendError(w, "could not find object", reqInfo, err)
		return
	}

	var info *data.ObjectInfo
	if comprehensiveInfo.ObjectInfo != nil {
		info = comprehensiveInfo.ObjectInfo
	} else {
		info, err = h.obj.GetObjectInfoByID(r.Context(), bktInfo, comprehensiveInfo.ID)
		if err != nil {
			h.logAndSendError(w, "could not get object info", reqInfo, err)
			return
		}
		// No tags from a separate object; try to extract inline tags from object headers.
		if len(comprehensiveInfo.TagSet) == 0 {
			for k, v := range info.Headers {
				if after, ok := strings.CutPrefix(k, s3headers.NeoFSSystemMetadataTagPrefix); ok {
					if comprehensiveInfo.TagSet == nil {
						comprehensiveInfo.TagSet = make(map[string]string)
					}
					comprehensiveInfo.TagSet[after] = v
				}
			}
		}
	}

	encryptionParams, err := formEncryptionParams(r)
	if err != nil {
		h.logAndSendError(w, "invalid sse headers", reqInfo, err)
		return
	}

	if err = encryptionParams.MatchObjectEncryption(layer.FormEncryptionInfoFromMeta(info.EncryptionMeta)); err != nil {
		h.logAndSendError(w, "encryption doesn't match object", reqInfo, s3errors.GetAPIError(s3errors.ErrBadRequest), zap.Error(err))
		return
	}

	if err = checkPreconditions(info, conditional); err != nil {
		h.logAndSendError(w, "precondition failed", reqInfo, err)
		return
	}

	if len(info.ContentType) == 0 {
		if info.ContentType = layer.MimeByFilePath(info.Name); len(info.ContentType) == 0 {
			buffer := bytes.NewBuffer(make([]byte, 0, sizeToDetectType))
			getParams := &layer.GetObjectParams{
				ObjectInfo: info,
				Writer:     buffer,
				Range:      getRangeToDetectContentType(info.Size),
				BucketInfo: bktInfo,
			}
			if err = h.obj.GetObject(r.Context(), getParams); err != nil {
				h.logAndSendError(w, "could not get object", reqInfo, err, zap.Stringer("oid", info.ID))
				return
			}
			info.ContentType = http.DetectContentType(buffer.Bytes())
		}
	}

	if err = h.setLockingHeaders(bktInfo, comprehensiveInfo.LockInfo, w.Header()); err != nil {
		h.logAndSendError(w, "could not get locking info", reqInfo, err)
		return
	}

	writeHeaders(w.Header(), r.Header, info, len(comprehensiveInfo.TagSet), bktInfo.Settings.Unversioned())
	w.WriteHeader(http.StatusOK)
}

func (h *handler) HeadBucketHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	w.Header().Set(api.ContainerID, bktInfo.CID.EncodeToString())
	w.Header().Set(api.AmzBucketRegion, bktInfo.LocationConstraint)
	api.WriteResponse(w, http.StatusOK, nil, api.MimeNone)
}

func (h *handler) setLockingHeaders(bktInfo *data.BucketInfo, lockInfo *data.LockInfo, header http.Header) error {
	if !bktInfo.ObjectLockEnabled {
		return nil
	}

	legalHold := &data.LegalHold{Status: legalHoldOff}
	retention := &data.Retention{Mode: governanceMode}

	if lockInfo.IsLegalHoldSet() {
		legalHold.Status = legalHoldOn
	}
	if lockInfo.IsRetentionSet() {
		retention.RetainUntilDate = lockInfo.UntilDate()
		if lockInfo.IsCompliance() {
			retention.Mode = complianceMode
		}
	}

	writeLockHeaders(header, legalHold, retention)
	return nil
}

func writeLockHeaders(h http.Header, legalHold *data.LegalHold, retention *data.Retention) {
	h.Set(api.AmzObjectLockLegalHold, legalHold.Status)

	if retention.RetainUntilDate != "" {
		h.Set(api.AmzObjectLockRetainUntilDate, retention.RetainUntilDate)
		h.Set(api.AmzObjectLockMode, retention.Mode)
	}
}
