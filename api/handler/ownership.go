package handler

import (
	"encoding/xml"
	"io"
	"net/http"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3errors"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
)

type (
	putBucketOwnershipControlsParams struct {
		Rules []objectOwnershipRules `xml:"Rule"`
	}

	objectOwnershipRules struct {
		ObjectOwnership string `xml:"ObjectOwnership"`
	}
)

const (
	xAmzExpectedBucketOwner = "x-amz-expected-bucket-owner"
)

func decodeXML(r io.Reader, destination any) error {
	if err := xml.NewDecoder(r).Decode(destination); err != nil {
		return s3errors.GetAPIError(s3errors.ErrMalformedXML)
	}

	return nil
}

func (h *handler) PutBucketOwnershipControlsHandler(w http.ResponseWriter, r *http.Request) {
	var (
		reqInfo = api.GetReqInfo(r.Context())
		params  putBucketOwnershipControlsParams
		rec     *eacl.Record
	)

	defer func() {
		_ = r.Body.Close()
	}()

	if err := decodeXML(r.Body, &params); err != nil {
		h.logAndSendError(w, "could not parse body", reqInfo, err)
		return
	}

	if len(params.Rules) == 0 {
		h.logAndSendError(w, "empty rules list", reqInfo, s3errors.GetAPIError(s3errors.ErrEmptyRequestBody))
		return
	}

	switch params.Rules[0].ObjectOwnership {
	case amzBucketOwnerEnforced:
		rec = bucketOwnerEnforcedRecord()
	case amzBucketOwnerPreferred:
		rec = bucketOwnerPreferredRecord()
	case aclEnabledObjectWriter:
		rec = bucketACLObjectWriterRecord()
	default:
		h.logAndSendError(w, "invalid ownership", reqInfo, s3errors.GetAPIError(s3errors.ErrBadRequest))
		return
	}

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket objInfo", reqInfo, err)
		return
	}

	if expectedBucketOwner := r.Header.Get(xAmzExpectedBucketOwner); expectedBucketOwner != "" {
		if expectedBucketOwner != bktInfo.Owner.String() {
			h.logAndSendError(w, "bucket owner mismatch", reqInfo, s3errors.GetAPIError(s3errors.ErrAccessDenied))
		}
	}

	token, err := getSessionTokenSetEACL(r.Context())
	if err != nil {
		h.logAndSendError(w, "couldn't get eacl token", reqInfo, err)
		return
	}

	bucketACL, err := h.obj.GetBucketACL(r.Context(), bktInfo)
	if err != nil {
		h.logAndSendError(w, "could not get bucket eacl", reqInfo, err)
		return
	}

	var newEACL eacl.Table

	newRecords := updateBucketOwnership(bucketACL.EACL.Records(), *rec)
	for _, record := range newRecords {
		newEACL.AddRecord(&record)
	}

	p := layer.PutBucketACLParams{
		BktInfo:      bktInfo,
		EACL:         &newEACL,
		SessionToken: token,
	}

	if err = h.obj.PutBucketACL(r.Context(), &p); err != nil {
		h.logAndSendError(w, "could not put bucket eacl", reqInfo, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}
