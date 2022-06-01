package handler

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
)

type (
	GetObjectAttributesResponse struct {
		ETag         string       `xml:"ETag,omitempty"`
		ObjectSize   int64        `xml:"ObjectSize,omitempty"`
		StorageClass string       `xml:"StorageClass,omitempty"`
		ObjectParts  *ObjectParts `xml:"ObjectParts,omitempty"`
	}

	ObjectParts struct {
		IsTruncated          bool   `xml:"IsTruncated,omitempty"`
		MaxParts             int    `xml:"MaxParts,omitempty"`
		NextPartNumberMarker int    `xml:"NextPartNumberMarker,omitempty"`
		PartNumberMarker     int    `xml:"PartNumberMarker,omitempty"`
		Parts                []Part `xml:"Part,omitempty"`

		// Only this field is used.
		PartsCount int `xml:"PartsCount,omitempty"`
	}

	Part struct {
		PartNumber int `xml:"PartNumber,omitempty"`
		Size       int `xml:"Size,omitempty"`
	}

	GetObjectAttributesArgs struct {
		Attributes []string
		VersionID  string
	}
)

const (
	eTag         = "ETag"
	checksum     = "Checksum"
	objectParts  = "ObjectParts"
	storageClass = "StorageClass"
	objectSize   = "ObjectSize"
)

var validAttributes = map[string]struct{}{
	eTag:         {},
	checksum:     {},
	objectParts:  {},
	storageClass: {},
	objectSize:   {},
}

func (h *handler) GetObjectAttributesHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err  error
		info *data.ObjectInfo

		reqInfo = api.GetReqInfo(r.Context())
	)

	params, err := parseGetObjectAttributeArgs(r)
	if err != nil {
		h.logAndSendError(w, "invalid request", reqInfo, err)
		return
	}

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	p := &layer.HeadObjectParams{
		BktInfo:   bktInfo,
		Object:    reqInfo.ObjectName,
		VersionID: params.VersionID,
	}

	if info, err = h.obj.GetObjectInfo(r.Context(), p); err != nil {
		h.logAndSendError(w, "could not fetch object info", reqInfo, err)
		return
	}

	response, err := encodeToObjectAttributesResponse(info, params)
	if err != nil {
		h.logAndSendError(w, "couldn't encode object info to response", reqInfo, err)
		return
	}

	writeAttributesHeaders(w.Header(), info, params)
	if err = api.EncodeToResponse(w, response); err != nil {
		h.logAndSendError(w, "something went wrong", reqInfo, err)
	}
}

func writeAttributesHeaders(h http.Header, info *data.ObjectInfo, params *GetObjectAttributesArgs) {
	h.Set(api.LastModified, info.Created.UTC().Format(http.TimeFormat))
	if len(params.VersionID) != 0 {
		h.Set(api.AmzVersionID, info.Version())
	}

	if info.IsDeleteMarker {
		h.Set(api.AmzDeleteMarker, strconv.FormatBool(true))
	}

	// x-amz-request-charged
}

func parseGetObjectAttributeArgs(r *http.Request) (*GetObjectAttributesArgs, error) {
	res := &GetObjectAttributesArgs{
		VersionID: r.URL.Query().Get(api.QueryVersionID),
	}

	attributesVal := r.Header.Get(api.AmzObjectAttributes)
	if attributesVal == "" {
		return nil, errors.GetAPIError(errors.ErrInvalidAttributeName)
	}

	attributes := strings.Split(attributesVal, ",")
	for _, a := range attributes {
		if _, ok := validAttributes[a]; !ok {
			return nil, errors.GetAPIError(errors.ErrInvalidAttributeName)
		}
		res.Attributes = append(res.Attributes, a)
	}

	return res, nil
}

func encodeToObjectAttributesResponse(info *data.ObjectInfo, p *GetObjectAttributesArgs) (*GetObjectAttributesResponse, error) {
	resp := &GetObjectAttributesResponse{}

	for _, attr := range p.Attributes {
		switch attr {
		case eTag:
			resp.ETag = info.HashSum
		case storageClass:
			resp.StorageClass = "STANDARD"
		case objectSize:
			resp.ObjectSize = info.Size
		case objectParts:
			parts, err := formUploadAttributes(info)
			if err != nil {
				return nil, err
			}
			if parts != nil {
				resp.ObjectParts = parts
			}
		}
	}

	return resp, nil
}

func formUploadAttributes(info *data.ObjectInfo) (*ObjectParts, error) {
	var err error
	res := ObjectParts{}

	partsCountStr, ok := info.Headers[layer.UploadCompletedPartsCount]
	if !ok {
		return nil, nil
	}

	res.PartsCount, err = strconv.Atoi(partsCountStr)
	if err != nil {
		return nil, fmt.Errorf("invalid parts count header '%s': %w", partsCountStr, err)
	}

	return &res, nil
}
