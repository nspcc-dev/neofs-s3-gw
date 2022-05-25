package handler

import (
	"bytes"
	"context"
	"net/http"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"go.uber.org/zap"
)

const sizeToDetectType = 512

func getRangeToDetectContentType(maxSize int64) *layer.RangeParams {
	end := uint64(maxSize)
	if sizeToDetectType < end {
		end = sizeToDetectType
	}

	return &layer.RangeParams{
		Start: 0,
		End:   end - 1,
	}
}

func (h *handler) HeadObjectHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err  error
		info *data.ObjectInfo

		reqInfo = api.GetReqInfo(r.Context())
	)

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	p := &layer.HeadObjectParams{
		BktInfo:   bktInfo,
		Object:    reqInfo.ObjectName,
		VersionID: reqInfo.URL.Query().Get(api.QueryVersionID),
	}

	if info, err = h.obj.GetObjectInfo(r.Context(), p); err != nil {
		h.logAndSendError(w, "could not fetch object info", reqInfo, err)
		return
	}
	tagSet, err := h.obj.GetObjectTagging(r.Context(), info)
	if err != nil && !errors.IsS3Error(err, errors.ErrNoSuchKey) {
		h.logAndSendError(w, "could not get object tag set", reqInfo, err)
		return
	}

	if len(info.ContentType) == 0 {
		buffer := bytes.NewBuffer(make([]byte, 0, sizeToDetectType))
		getParams := &layer.GetObjectParams{
			ObjectInfo: info,
			Writer:     buffer,
			Range:      getRangeToDetectContentType(info.Size),
			VersionID:  reqInfo.URL.Query().Get(api.QueryVersionID),
		}
		if err = h.obj.GetObject(r.Context(), getParams); err != nil {
			h.logAndSendError(w, "could not get object", reqInfo, err, zap.Stringer("oid", info.ID))
			return
		}
		info.ContentType = http.DetectContentType(buffer.Bytes())
	}

	if err = h.setLockingHeaders(r.Context(), bktInfo, info, w.Header()); err != nil {
		h.logAndSendError(w, "could not get locking info", reqInfo, err)
		return
	}

	writeHeaders(w.Header(), info, len(tagSet))
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
	api.WriteResponse(w, http.StatusOK, nil, api.MimeNone)
}

func (h *handler) setLockingHeaders(ctx context.Context, bktInfo *data.BucketInfo, objInfo *data.ObjectInfo, header http.Header) error {
	if !bktInfo.ObjectLockEnabled {
		return nil
	}

	legalHold := &data.LegalHold{Status: legalHoldOff}
	legalHoldInfo, err := h.obj.HeadSystemObject(ctx, bktInfo, objInfo.LegalHoldObject())
	if err != nil && !errors.IsS3Error(err, errors.ErrNoSuchKey) {
		return err
	}

	if legalHoldInfo != nil {
		legalHold.Status = legalHoldOn
	}

	retention := &data.Retention{Mode: governanceMode}
	retentionInfo, err := h.obj.HeadSystemObject(ctx, bktInfo, objInfo.RetentionObject())
	if err != nil && !errors.IsS3Error(err, errors.ErrNoSuchKey) {
		return err
	}

	if retentionInfo != nil {
		retention.RetainUntilDate = retentionInfo.Headers[layer.AttributeRetainUntil]
		if retentionInfo.Headers[layer.AttributeComplianceMode] != "" {
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
