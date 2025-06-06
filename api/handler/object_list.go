package handler

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3errors"
)

// ListObjectsV1Handler handles objects listing requests for API version 1.
func (h *handler) ListObjectsV1Handler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())
	params, err := parseListObjectsArgsV1(reqInfo)
	if err != nil {
		h.logAndSendError(w, "failed to parse arguments", reqInfo, err)
		return
	}

	if params.BktInfo, err = h.getBucketAndCheckOwner(r, reqInfo.BucketName); err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	list, err := h.obj.ListObjectsV1(r.Context(), params)
	if err != nil {
		h.logAndSendError(w, "something went wrong", reqInfo, err)
		return
	}

	encoded, err := encodeV1(params, list)
	if err != nil {
		h.logAndSendError(w, "encode V1", reqInfo, err)
		return
	}

	if err = api.EncodeToResponse(w, encoded); err != nil {
		h.logAndSendError(w, "something went wrong", reqInfo, err)
	}
}

func encodeV1(p *layer.ListObjectsParamsV1, list *layer.ListObjectsInfoV1) (*ListObjectsV1Response, error) {
	res := &ListObjectsV1Response{
		Name:         p.BktInfo.Name,
		EncodingType: p.Encode,
		Marker:       p.Marker,
		Prefix:       p.Prefix,
		MaxKeys:      p.MaxKeys,
		Delimiter:    p.Delimiter,
		IsTruncated:  list.IsTruncated,
		NextMarker:   list.NextMarker,
	}

	res.CommonPrefixes = fillPrefixes(list.Prefixes, p.Encode)

	content, err := fillContentsWithOwner(list.Objects, p.Encode)
	if err != nil {
		return nil, fmt.Errorf("fill contents with owner: %w", err)
	}

	res.Contents = content

	return res, nil
}

// ListObjectsV2Handler handles objects listing requests for API version 2.
func (h *handler) ListObjectsV2Handler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())
	params, err := parseListObjectsArgsV2(reqInfo)
	if err != nil {
		h.logAndSendError(w, "failed to parse arguments", reqInfo, err)
		return
	}

	if params.BktInfo, err = h.getBucketAndCheckOwner(r, reqInfo.BucketName); err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	list, err := h.obj.ListObjectsV2(r.Context(), params)
	if err != nil {
		h.logAndSendError(w, "something went wrong", reqInfo, err)
		return
	}

	encoded, err := encodeV2(params, list)
	if err != nil {
		h.logAndSendError(w, "encode V2", reqInfo, err)
		return
	}

	if err = api.EncodeToResponse(w, encoded); err != nil {
		h.logAndSendError(w, "something went wrong", reqInfo, err)
	}
}

func encodeV2(p *layer.ListObjectsParamsV2, list *layer.ListObjectsInfoV2) (*ListObjectsV2Response, error) {
	res := &ListObjectsV2Response{
		Name:                  p.BktInfo.Name,
		EncodingType:          p.Encode,
		Prefix:                s3PathEncode(p.Prefix, p.Encode),
		KeyCount:              len(list.Objects) + len(list.Prefixes),
		MaxKeys:               p.MaxKeys,
		Delimiter:             s3PathEncode(p.Delimiter, p.Encode),
		StartAfter:            s3PathEncode(p.StartAfter, p.Encode),
		IsTruncated:           list.IsTruncated,
		ContinuationToken:     p.ContinuationToken,
		NextContinuationToken: list.NextContinuationToken,
	}

	res.CommonPrefixes = fillPrefixes(list.Prefixes, p.Encode)

	content, err := fillContents(list.Objects, p.Encode, p.FetchOwner)
	if err != nil {
		return nil, fmt.Errorf("fill content: %w", err)
	}

	res.Contents = content

	return res, nil
}

func parseListObjectsArgsV1(reqInfo *api.ReqInfo) (*layer.ListObjectsParamsV1, error) {
	var (
		res         layer.ListObjectsParamsV1
		queryValues = reqInfo.URL.Query()
	)

	common, err := parseListObjectArgs(reqInfo)
	if err != nil {
		return nil, err
	}
	res.ListObjectsParamsCommon = *common

	res.Marker = queryValues.Get("marker")

	return &res, nil
}

func parseListObjectsArgsV2(reqInfo *api.ReqInfo) (*layer.ListObjectsParamsV2, error) {
	var (
		res         layer.ListObjectsParamsV2
		queryValues = reqInfo.URL.Query()
	)

	common, err := parseListObjectArgs(reqInfo)
	if err != nil {
		return nil, err
	}
	res.ListObjectsParamsCommon = *common

	res.ContinuationToken, err = parseContinuationToken(queryValues)
	if err != nil {
		return nil, err
	}

	res.StartAfter = queryValues.Get("start-after")
	res.FetchOwner, _ = strconv.ParseBool(queryValues.Get("fetch-owner"))
	return &res, nil
}

func parseListObjectArgs(reqInfo *api.ReqInfo) (*layer.ListObjectsParamsCommon, error) {
	var (
		err         error
		res         layer.ListObjectsParamsCommon
		queryValues = reqInfo.URL.Query()
	)

	res.Delimiter = queryValues.Get("delimiter")
	res.Encode = queryValues.Get("encoding-type")

	if queryValues.Get("max-keys") == "" {
		res.MaxKeys = maxObjectList
	} else if res.MaxKeys, err = strconv.Atoi(queryValues.Get("max-keys")); err != nil || res.MaxKeys < 0 {
		return nil, s3errors.GetAPIError(s3errors.ErrInvalidMaxKeys)
	}

	res.Prefix = queryValues.Get("prefix")

	return &res, nil
}

func parseContinuationToken(queryValues url.Values) (string, error) {
	// There is a tricky situation. If a continuation-token has been passed, it must not be empty.
	if val, ok := queryValues["continuation-token"]; ok {
		if len(val) == 0 || val[0] == "" {
			return "", s3errors.GetAPIError(s3errors.ErrIncorrectContinuationToken)
		}
		return val[0], nil
	}
	return "", nil
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

func fillContentsWithOwner(src []data.ObjectListResponseContent, encode string) ([]Object, error) {
	return fillContents(src, encode, true)
}

func fillContents(src []data.ObjectListResponseContent, encode string, fetchOwner bool) ([]Object, error) {
	var dst []Object
	for _, obj := range src {
		res := Object{
			Key:          s3PathEncode(obj.Name, encode),
			Size:         obj.Size,
			LastModified: obj.Created.UTC().Format(time.RFC3339),
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
	return dst, nil
}

func (h *handler) ListBucketObjectVersionsHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())
	p, err := parseListObjectVersionsRequest(reqInfo)
	if err != nil {
		h.logAndSendError(w, "failed to parse request", reqInfo, err)
		return
	}

	if p.BktInfo, err = h.getBucketAndCheckOwner(r, reqInfo.BucketName); err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	info, err := h.obj.ListObjectVersions(r.Context(), p)
	if err != nil {
		h.logAndSendError(w, "something went wrong", reqInfo, err)
		return
	}

	response := encodeListObjectVersionsToResponse(info, p.BktInfo.Name, p.Prefix)
	if err = api.EncodeToResponse(w, response); err != nil {
		h.logAndSendError(w, "something went wrong", reqInfo, err)
	}
}

func parseListObjectVersionsRequest(reqInfo *api.ReqInfo) (*layer.ListObjectVersionsParams, error) {
	var (
		err         error
		res         layer.ListObjectVersionsParams
		queryValues = reqInfo.URL.Query()
	)

	if queryValues.Get("max-keys") == "" {
		res.MaxKeys = maxObjectList
	} else if res.MaxKeys, err = strconv.Atoi(queryValues.Get("max-keys")); err != nil || res.MaxKeys <= 0 {
		return nil, s3errors.GetAPIError(s3errors.ErrInvalidMaxKeys)
	}

	res.Prefix = queryValues.Get("prefix")
	res.KeyMarker = queryValues.Get("key-marker")
	res.Delimiter = queryValues.Get("delimiter")
	res.Encode = queryValues.Get("encoding-type")
	res.VersionIDMarker = queryValues.Get("version-id-marker")

	return &res, nil
}

func encodeListObjectVersionsToResponse(info *layer.ListObjectVersionsInfo, bucketName, requestPrefix string) *ListObjectsVersionsResponse {
	res := ListObjectsVersionsResponse{
		Name:                bucketName,
		IsTruncated:         info.IsTruncated,
		KeyMarker:           info.KeyMarker,
		NextKeyMarker:       info.NextKeyMarker,
		NextVersionIDMarker: info.NextVersionIDMarker,
		VersionIDMarker:     info.VersionIDMarker,
		Prefix:              requestPrefix,
	}

	for _, prefix := range info.CommonPrefixes {
		res.CommonPrefixes = append(res.CommonPrefixes, CommonPrefix{Prefix: prefix})
	}

	for _, ver := range info.Version {
		res.Version = append(res.Version, ObjectVersionResponse{
			IsLatest:     ver.IsLatest,
			Key:          ver.ObjectInfo.Name,
			LastModified: ver.ObjectInfo.Created.UTC().Format(time.RFC3339),
			Owner: Owner{
				ID:          ver.ObjectInfo.Owner.String(),
				DisplayName: ver.ObjectInfo.Owner.String(),
			},
			Size:      ver.ObjectInfo.Size,
			VersionID: ver.Version(),
			ETag:      ver.ObjectInfo.HashSum,
		})
	}
	// this loop is not starting till versioning is not implemented
	for _, del := range info.DeleteMarker {
		res.DeleteMarker = append(res.DeleteMarker, DeleteMarkerEntry{
			IsLatest:     del.IsLatest,
			Key:          del.ObjectInfo.Name,
			LastModified: del.ObjectInfo.Created.UTC().Format(time.RFC3339),
			Owner: Owner{
				ID:          del.ObjectInfo.Owner.String(),
				DisplayName: del.ObjectInfo.Owner.String(),
			},
			VersionID: del.Version(),
		})
	}

	return &res
}
