package handler

import (
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
		PartsCount           int    `xml:"PartsCount,omitempty"`
	}

	Part struct {
		PartNumber int `xml:"PartNumber,omitempty"`
		Size       int `xml:"Size,omitempty"`
	}

	GetObjectAttributesArgs struct {
		MaxParts         int
		PartNumberMarker int
		Attributes       []string
		VersionID        string
	}
)

const (
	partNumberMarkerDefault = -1

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

	if _, ok := info.Headers[layer.VersionsDeleteMarkAttr]; ok {
		h.Set(api.AmzDeleteMarker, strconv.FormatBool(true))
	}

	// x-amz-request-charged
}

func parseGetObjectAttributeArgs(r *http.Request) (*GetObjectAttributesArgs, error) {
	var (
		err error

		res           = &GetObjectAttributesArgs{}
		attributesVal = r.Header.Get("X-Amz-Object-Attributes")
		maxPartsVal   = r.Header.Get("X-Amz-Max-Parts")
		markerVal     = r.Header.Get("X-Amz-Part-Number-Marker")
		queryValues   = r.URL.Query()
	)

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

	if maxPartsVal == "" {
		res.MaxParts = layer.MaxSizePartsList
	} else if res.MaxParts, err = strconv.Atoi(maxPartsVal); err != nil || res.MaxParts < 0 {
		return nil, errors.GetAPIError(errors.ErrInvalidMaxKeys)
	}

	if markerVal == "" {
		res.PartNumberMarker = partNumberMarkerDefault
	} else if res.PartNumberMarker, err = strconv.Atoi(markerVal); err != nil || res.PartNumberMarker < 0 {
		return nil, errors.GetAPIError(errors.ErrInvalidPartNumberMarker)
	}

	res.VersionID = queryValues.Get(api.QueryVersionID)

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
			parts, err := formUploadAttributes(info, p.MaxParts, p.PartNumberMarker)
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

func formUploadAttributes(info *data.ObjectInfo, maxParts, marker int) (*ObjectParts, error) {
	res := ObjectParts{}

	if _, ok := info.Headers[layer.UploadIDAttributeName]; !ok {
		return nil, nil
	}

	parts := make([]Part, 0)
	val, ok := info.Headers[layer.UploadCompletedParts]
	if ok {
		pairs := strings.Split(val, ",")
		for _, p := range pairs {
			// nums[0] -- part number, nums[1] -- part size
			nums := strings.Split(p, "=")
			if len(nums) != 2 {
				return nil, nil
			}
			num, err := strconv.Atoi(nums[0])
			if err != nil {
				return nil, err
			}
			size, err := strconv.Atoi(nums[1])
			if err != nil {
				return nil, err
			}
			parts = append(parts, Part{PartNumber: num, Size: size})
		}
	}

	res.PartsCount = len(parts)

	if marker != partNumberMarkerDefault {
		res.PartNumberMarker = marker
		for i, n := range parts {
			if n.PartNumber == marker {
				parts = parts[i:]
				break
			}
		}
	}
	res.MaxParts = maxParts
	if len(parts) > maxParts {
		res.IsTruncated = true
		res.NextPartNumberMarker = parts[maxParts].PartNumber
		parts = parts[:maxParts]
	}

	res.Parts = parts

	return &res, nil
}
