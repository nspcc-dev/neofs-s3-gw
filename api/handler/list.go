package handler

import (
	"encoding/xml"
	"net/http"
	"strconv"
	"time"

	"github.com/nspcc-dev/neofs-api-go/pkg/owner"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"go.uber.org/zap"
)

type listObjectsArgs struct {
	Bucket     string
	Delimiter  string
	Encode     string
	Marker     string
	StartAfter string
	MaxKeys    int
	Prefix     string
	APIVersion int
}

// VersioningConfiguration contains VersioningConfiguration XML representation.
type VersioningConfiguration struct {
	XMLName xml.Name `xml:"VersioningConfiguration"`
	Text    string   `xml:",chardata"`
	Xmlns   string   `xml:"xmlns,attr"`
}

// ListMultipartUploadsResult contains ListMultipartUploadsResult XML representation.
type ListMultipartUploadsResult struct {
	XMLName xml.Name `xml:"ListMultipartUploadsResult"`
	Text    string   `xml:",chardata"`
	Xmlns   string   `xml:"xmlns,attr"`
}

const maxObjectList = 1000 // Limit number of objects in a listObjectsResponse/listObjectsVersionsResponse.

func (h *handler) registerAndSendError(w http.ResponseWriter, r *http.Request, err error, logText string) {
	rid := api.GetRequestID(r.Context())
	h.log.Error(logText,
		zap.String("request_id", rid),
		zap.Error(err))

	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           api.GetAPIError(api.ErrBadRequest).Code,
		Description:    err.Error(),
		HTTPStatusCode: http.StatusBadRequest,
	}, r.URL)
}

// ListBucketsHandler handles bucket listing requests.
func (h *handler) ListBucketsHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err error
		own = owner.NewID()
		res *ListBucketsResponse
		rid = api.GetRequestID(r.Context())
	)

	list, err := h.obj.ListBuckets(r.Context())
	if err != nil {
		h.log.Error("something went wrong",
			zap.String("request_id", rid),
			zap.Error(err))

		api.WriteErrorResponse(r.Context(), w, api.Error{
			Code:           api.GetAPIError(api.ErrInternalError).Code,
			Description:    err.Error(),
			HTTPStatusCode: http.StatusInternalServerError,
		}, r.URL)

		return
	}

	if len(list) > 0 {
		own = list[0].Owner
	}

	res = &ListBucketsResponse{
		Owner: Owner{
			ID:          own.String(),
			DisplayName: own.String(),
		},
	}

	for _, item := range list {
		res.Buckets.Buckets = append(res.Buckets.Buckets, Bucket{
			Name:         item.Name,
			CreationDate: item.Created.Format(time.RFC3339),
		})
	}

	if err = api.EncodeToResponse(w, res); err != nil {
		h.log.Error("something went wrong",
			zap.String("request_id", rid),
			zap.Error(err))

		api.WriteErrorResponse(r.Context(), w, api.Error{
			Code:           api.GetAPIError(api.ErrInternalError).Code,
			Description:    err.Error(),
			HTTPStatusCode: http.StatusInternalServerError,
		}, r.URL)
	}
}

func (h *handler) listObjects(w http.ResponseWriter, r *http.Request) (*listObjectsArgs, *layer.ListObjectsInfo, error) {
	var (
		err error
		arg *listObjectsArgs
		rid = api.GetRequestID(r.Context())
	)

	if arg, err = parseListObjectArgs(r); err != nil {
		h.log.Error("something went wrong",
			zap.String("request_id", rid),
			zap.Error(err))

		api.WriteErrorResponse(r.Context(), w, err, r.URL)
		return nil, nil, err
	}

	marker := arg.Marker
	if arg.APIVersion == 2 {
		marker = arg.StartAfter
	}

	list, err := h.obj.ListObjects(r.Context(), &layer.ListObjectsParams{
		Bucket:    arg.Bucket,
		Prefix:    arg.Prefix,
		MaxKeys:   arg.MaxKeys,
		Delimiter: arg.Delimiter,
		Marker:    marker,
		Version:   arg.APIVersion,
	})
	if err != nil {
		h.log.Error("something went wrong",
			zap.String("request_id", rid),
			zap.Error(err))

		api.WriteErrorResponse(r.Context(), w, api.Error{
			Code:           api.GetAPIError(api.ErrInternalError).Code,
			Description:    err.Error(),
			HTTPStatusCode: http.StatusInternalServerError,
		}, r.URL)

		return nil, nil, err
	}

	return arg, list, nil
}

// ListObjectsV1Handler handles objects listing requests for API version 1.
func (h *handler) ListObjectsV1Handler(w http.ResponseWriter, r *http.Request) {
	var rid = api.GetRequestID(r.Context())
	if arg, list, err := h.listObjects(w, r); err != nil {
		// error already sent to client
		return
	} else if err := api.EncodeToResponse(w, encodeV1(arg, list)); err != nil {
		h.log.Error("something went wrong",
			zap.String("request_id", rid),
			zap.Error(err))

		api.WriteErrorResponse(r.Context(), w, api.Error{
			Code:           api.GetAPIError(api.ErrInternalError).Code,
			Description:    err.Error(),
			HTTPStatusCode: http.StatusInternalServerError,
		}, r.URL)
	}
}

func encodeV1(arg *listObjectsArgs, list *layer.ListObjectsInfo) *ListObjectsResponse {
	res := &ListObjectsResponse{
		Name:         arg.Bucket,
		EncodingType: arg.Encode,
		Marker:       arg.Marker,
		Prefix:       arg.Prefix,
		MaxKeys:      arg.MaxKeys,
		Delimiter:    arg.Delimiter,

		IsTruncated: list.IsTruncated,
		NextMarker:  list.NextMarker,
	}

	// fill common prefixes
	for i := range list.Prefixes {
		res.CommonPrefixes = append(res.CommonPrefixes, CommonPrefix{
			Prefix: s3PathEncode(list.Prefixes[i], arg.Encode),
		})
	}

	// fill contents
	for _, obj := range list.Objects {
		res.Contents = append(res.Contents, Object{
			Key:          s3PathEncode(obj.Name, arg.Encode),
			Size:         obj.Size,
			LastModified: obj.Created.Format(time.RFC3339),

			Owner: Owner{
				ID:          obj.Owner.String(),
				DisplayName: obj.Owner.String(),
			},

			ETag: obj.HashSum,
			// StorageClass: "",
		})
	}

	return res
}

// ListObjectsV2Handler handles objects listing requests for API version 2.
func (h *handler) ListObjectsV2Handler(w http.ResponseWriter, r *http.Request) {
	var rid = api.GetRequestID(r.Context())
	if arg, list, err := h.listObjects(w, r); err != nil {
		// error already sent to client
		return
	} else if err := api.EncodeToResponse(w, encodeV2(arg, list)); err != nil {
		h.log.Error("something went wrong",
			zap.String("request_id", rid),
			zap.Error(err))

		api.WriteErrorResponse(r.Context(), w, api.Error{
			Code:           api.GetAPIError(api.ErrInternalError).Code,
			Description:    err.Error(),
			HTTPStatusCode: http.StatusInternalServerError,
		}, r.URL)
	}
}

func encodeV2(arg *listObjectsArgs, list *layer.ListObjectsInfo) *ListObjectsV2Response {
	res := &ListObjectsV2Response{
		Name:         arg.Bucket,
		EncodingType: arg.Encode,
		Prefix:       s3PathEncode(arg.Prefix, arg.Encode),
		KeyCount:     len(list.Objects) + len(list.Prefixes),
		MaxKeys:      arg.MaxKeys,
		Delimiter:    s3PathEncode(arg.Delimiter, arg.Encode),
		StartAfter:   s3PathEncode(arg.StartAfter, arg.Encode),

		IsTruncated: list.IsTruncated,

		ContinuationToken:     arg.Marker,
		NextContinuationToken: list.NextContinuationToken,
	}

	// fill common prefixes
	for i := range list.Prefixes {
		res.CommonPrefixes = append(res.CommonPrefixes, CommonPrefix{
			Prefix: s3PathEncode(list.Prefixes[i], arg.Encode),
		})
	}

	// fill contents
	for _, obj := range list.Objects {
		res.Contents = append(res.Contents, Object{
			Key:          s3PathEncode(obj.Name, arg.Encode),
			Size:         obj.Size,
			LastModified: obj.Created.Format(time.RFC3339),

			Owner: Owner{
				ID:          obj.Owner.String(),
				DisplayName: obj.Owner.String(),
			},

			ETag: obj.HashSum,
			// StorageClass: "",
		})
	}

	return res
}

func parseListObjectArgs(r *http.Request) (*listObjectsArgs, error) {
	var (
		err error
		res listObjectsArgs
	)

	if r.URL.Query().Get("max-keys") == "" {
		res.MaxKeys = maxObjectList
	} else if res.MaxKeys, err = strconv.Atoi(r.URL.Query().Get("max-keys")); err != nil || res.MaxKeys < 0 {
		return nil, api.GetAPIError(api.ErrInvalidMaxKeys)
	}

	res.Prefix = r.URL.Query().Get("prefix")
	res.Marker = r.URL.Query().Get("marker")
	res.Delimiter = r.URL.Query().Get("delimiter")
	res.Encode = r.URL.Query().Get("encoding-type")
	res.StartAfter = r.URL.Query().Get("start-after")
	apiVersionStr := r.URL.Query().Get("list-type")

	res.APIVersion = 1
	if len(apiVersionStr) != 0 {
		if apiVersion, err := strconv.Atoi(apiVersionStr); err != nil || apiVersion != 2 {
			return nil, api.GetAPIError(api.ErrIllegalVersioningConfigurationException)
		}
		res.APIVersion = 2
	}

	if info := api.GetReqInfo(r.Context()); info != nil {
		res.Bucket = info.BucketName
	}

	return &res, nil
}

// GetBucketVersioningHandler implements bucket versioning getter handler.
func (h *handler) GetBucketVersioningHandler(w http.ResponseWriter, r *http.Request) {
	var (
		rid = api.GetRequestID(r.Context())
		res = new(VersioningConfiguration)
	)

	res.Xmlns = "http://s3.amazonaws.com/doc/2006-03-01/"

	if err := api.EncodeToResponse(w, res); err != nil {
		h.log.Error("something went wrong",
			zap.String("request_id", rid),
			zap.Error(err))

		api.WriteErrorResponse(r.Context(), w, api.Error{
			Code:           api.GetAPIError(api.ErrInternalError).Code,
			Description:    err.Error(),
			HTTPStatusCode: http.StatusInternalServerError,
		}, r.URL)
	}
}

// ListMultipartUploadsHandler implements multipart uploads listing handler.
func (h *handler) ListMultipartUploadsHandler(w http.ResponseWriter, r *http.Request) {
	var (
		rid = api.GetRequestID(r.Context())
		res = new(ListMultipartUploadsResult)
	)

	res.Xmlns = "http://s3.amazonaws.com/doc/2006-03-01/"

	if err := api.EncodeToResponse(w, res); err != nil {
		h.log.Error("something went wrong",
			zap.String("request_id", rid),
			zap.Error(err))

		api.WriteErrorResponse(r.Context(), w, api.Error{
			Code:           api.GetAPIError(api.ErrInternalError).Code,
			Description:    err.Error(),
			HTTPStatusCode: http.StatusInternalServerError,
		}, r.URL)
	}
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
		err error
		res layer.ListObjectVersionsParams
	)

	if r.URL.Query().Get("max-keys") == "" {
		res.MaxKeys = maxObjectList
	} else if res.MaxKeys, err = strconv.Atoi(r.URL.Query().Get("max-keys")); err != nil || res.MaxKeys < 0 {
		return nil, api.GetAPIError(api.ErrInvalidMaxKeys)
	}

	res.Prefix = r.URL.Query().Get("prefix")
	res.KeyMarker = r.URL.Query().Get("marker")
	res.Delimiter = r.URL.Query().Get("delimiter")
	res.Encode = r.URL.Query().Get("encoding-type")
	res.VersionIDMarker = r.URL.Query().Get("version-id-marker")

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
