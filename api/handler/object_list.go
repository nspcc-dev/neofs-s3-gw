package handler

import (
	"net/http"
	"strconv"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
)

// ListObjectsV1Handler handles objects listing requests for API version 1.
func (h *handler) ListObjectsV1Handler(w http.ResponseWriter, r *http.Request) {
	params, err := parseListObjectsArgsV1(r)
	if err != nil {
		h.registerAndSendError(w, r, err, "failed to parse arguments")
		return
	}

	list, err := h.obj.ListObjectsV1(r.Context(), params)
	if err != nil {
		h.registerAndSendError(w, r, err, "something went wrong")
		return
	}

	err = api.EncodeToResponse(w, encodeV1(params, list))
	if err != nil {
		h.registerAndSendError(w, r, err, "something went wrong")
	}
}

func encodeV1(p *layer.ListObjectsParamsV1, list *layer.ListObjectsInfoV1) *ListObjectsV1Response {
	res := &ListObjectsV1Response{
		Name:         p.Bucket,
		EncodingType: p.Encode,
		Marker:       p.Marker,
		Prefix:       p.Prefix,
		MaxKeys:      p.MaxKeys,
		Delimiter:    p.Delimiter,

		IsTruncated: list.IsTruncated,
		NextMarker:  list.NextMarker,
	}

	res.CommonPrefixes = fillPrefixes(list.Prefixes, p.Encode)

	res.Contents = fillContentsWithOwner(list.Objects, p.Encode)

	return res
}

// ListObjectsV2Handler handles objects listing requests for API version 2.
func (h *handler) ListObjectsV2Handler(w http.ResponseWriter, r *http.Request) {
	params, err := parseListObjectsArgsV2(r)
	if err != nil {
		h.registerAndSendError(w, r, err, "failed to parse arguments")
		return
	}

	list, err := h.obj.ListObjectsV2(r.Context(), params)
	if err != nil {
		h.registerAndSendError(w, r, err, "something went wrong")
		return
	}

	err = api.EncodeToResponse(w, encodeV2(params, list))
	if err != nil {
		h.registerAndSendError(w, r, err, "something went wrong")
	}
}

func encodeV2(p *layer.ListObjectsParamsV2, list *layer.ListObjectsInfoV2) *ListObjectsV2Response {
	res := &ListObjectsV2Response{
		Name:         p.Bucket,
		EncodingType: p.Encode,
		Prefix:       s3PathEncode(p.Prefix, p.Encode),
		KeyCount:     len(list.Objects) + len(list.Prefixes),
		MaxKeys:      p.MaxKeys,
		Delimiter:    s3PathEncode(p.Delimiter, p.Encode),
		StartAfter:   s3PathEncode(p.StartAfter, p.Encode),

		IsTruncated: list.IsTruncated,

		ContinuationToken:     p.ContinuationToken,
		NextContinuationToken: list.NextContinuationToken,
	}

	res.CommonPrefixes = fillPrefixes(list.Prefixes, p.Encode)

	res.Contents = fillContents(list.Objects, p.Encode, p.FetchOwner)

	return res
}

func parseListObjectsArgsV1(r *http.Request) (*layer.ListObjectsParamsV1, error) {
	var (
		err         error
		res         layer.ListObjectsParamsV1
		queryValues = r.URL.Query()
	)

	common, err := parseListObjectArgs(r)
	if err != nil {
		return nil, err
	}
	res.ListObjectsParamsCommon = *common

	res.Marker = queryValues.Get("marker")

	return &res, nil
}

func parseListObjectsArgsV2(r *http.Request) (*layer.ListObjectsParamsV2, error) {
	var (
		err         error
		res         layer.ListObjectsParamsV2
		queryValues = r.URL.Query()
	)

	common, err := parseListObjectArgs(r)
	if err != nil {
		return nil, err
	}
	res.ListObjectsParamsCommon = *common

	res.ContinuationToken = queryValues.Get("continuation-token")
	res.StartAfter = queryValues.Get("start-after")
	res.FetchOwner, _ = strconv.ParseBool(queryValues.Get("fetch-owner"))
	return &res, nil
}

func parseListObjectArgs(r *http.Request) (*layer.ListObjectsParamsCommon, error) {
	var (
		err         error
		res         layer.ListObjectsParamsCommon
		queryValues = r.URL.Query()
	)

	if info := api.GetReqInfo(r.Context()); info != nil {
		res.Bucket = info.BucketName
	}

	res.Delimiter = queryValues.Get("delimiter")
	res.Encode = queryValues.Get("encoding-type")

	if queryValues.Get("max-keys") == "" {
		res.MaxKeys = maxObjectList
	} else if res.MaxKeys, err = strconv.Atoi(queryValues.Get("max-keys")); err != nil || res.MaxKeys < 0 {
		return nil, api.GetAPIError(api.ErrInvalidMaxKeys)
	}

	res.Prefix = queryValues.Get("prefix")

	return &res, nil
}

func fillPrefixes(src []string, encode string) []CommonPrefix {
	var dst []CommonPrefix
	for _, obj := range src {
		dst = append(dst, CommonPrefix{
			Prefix: s3PathEncode(obj, encode),
		})
	}
	return dst
}

func fillContentsWithOwner(src []*layer.ObjectInfo, encode string) []Object {
	return fillContents(src, encode, true)
}

func fillContents(src []*layer.ObjectInfo, encode string, fetchOwner bool) []Object {
	var dst []Object
	for _, obj := range src {
		res := Object{
			Key:          s3PathEncode(obj.Name, encode),
			Size:         obj.Size,
			LastModified: obj.Created.Format(time.RFC3339),
			ETag:         obj.HashSum,
		}

		if fetchOwner {
			res.Owner = &Owner{
				ID:          obj.Owner.String(),
				DisplayName: obj.Owner.String(),
			}
		}

		dst = append(dst, res)
	}
	return dst
}

func (h *handler) ListBucketObjectVersionsHandler(w http.ResponseWriter, r *http.Request) {
	p, err := parseListObjectVersionsRequest(r)
	if err != nil {
		h.registerAndSendError(w, r, err, "failed to parse request ")
		return
	}

	info, err := h.obj.ListObjectVersions(r.Context(), p)
	if err != nil {
		h.registerAndSendError(w, r, err, "something went wrong")
		return
	}

	response := encodeListObjectVersionsToResponse(info, p.Bucket)
	if err := api.EncodeToResponse(w, response); err != nil {
		h.registerAndSendError(w, r, err, "something went wrong")
	}
}

func parseListObjectVersionsRequest(r *http.Request) (*layer.ListObjectVersionsParams, error) {
	var (
		err         error
		res         layer.ListObjectVersionsParams
		queryValues = r.URL.Query()
	)

	if queryValues.Get("max-keys") == "" {
		res.MaxKeys = maxObjectList
	} else if res.MaxKeys, err = strconv.Atoi(queryValues.Get("max-keys")); err != nil || res.MaxKeys <= 0 {
		return nil, api.GetAPIError(api.ErrInvalidMaxKeys)
	}

	res.Prefix = queryValues.Get("prefix")
	res.KeyMarker = queryValues.Get("marker")
	res.Delimiter = queryValues.Get("delimiter")
	res.Encode = queryValues.Get("encoding-type")
	res.VersionIDMarker = queryValues.Get("version-id-marker")

	if info := api.GetReqInfo(r.Context()); info != nil {
		res.Bucket = info.BucketName
	}

	return &res, nil
}

func encodeListObjectVersionsToResponse(info *layer.ListObjectVersionsInfo, bucketName string) *ListObjectsVersionsResponse {
	res := ListObjectsVersionsResponse{
		Name:                bucketName,
		IsTruncated:         info.IsTruncated,
		KeyMarker:           info.KeyMarker,
		NextKeyMarker:       info.NextKeyMarker,
		NextVersionIDMarker: info.NextVersionIDMarker,
		VersionIDMarker:     info.VersionIDMarker,
	}

	for _, prefix := range info.CommonPrefixes {
		res.CommonPrefixes = append(res.CommonPrefixes, CommonPrefix{Prefix: *prefix})
	}

	for _, ver := range info.Version {
		res.Version = append(res.Version, ObjectVersionResponse{
			IsLatest:     ver.IsLatest,
			Key:          ver.Object.Name,
			LastModified: ver.Object.Created.Format(time.RFC3339),
			Owner: Owner{
				ID:          ver.Object.Owner.String(),
				DisplayName: ver.Object.Owner.String(),
			},
			Size:      ver.Object.Size,
			VersionID: ver.VersionID,
			ETag:      ver.Object.HashSum,
		})
	}
	// this loop is not starting till versioning is not implemented
	for _, del := range info.DeleteMarker {
		res.DeleteMarker = append(res.DeleteMarker, DeleteMarkerEntry{
			IsLatest:     del.IsLatest,
			Key:          del.Key,
			LastModified: del.LastModified,
			Owner: Owner{
				ID:          del.Owner.String(),
				DisplayName: del.Owner.String(),
			},
			VersionID: del.VersionID,
		})
	}

	return &res
}
