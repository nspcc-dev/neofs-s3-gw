package handler

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/nspcc-dev/neofs-api-go/pkg/acl"
	"github.com/nspcc-dev/neofs-node/pkg/policy"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"go.uber.org/zap"
)

// keywords of predefined basic ACL values.
const (
	basicACLPrivate  = "private"
	basicACLReadOnly = "public-read"
	basicACLPublic   = "public-read-write"
	defaultPolicy    = "REP 3"
)

func (h *handler) PutObjectHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err  error
		info *layer.ObjectInfo
		req  = mux.Vars(r)
		bkt  = req["bucket"]
		obj  = req["object"]
		rid  = api.GetRequestID(r.Context())
	)

	if _, err := h.obj.GetBucketInfo(r.Context(), bkt); err != nil {
		h.log.Error("could not find bucket",
			zap.String("request_id", rid),
			zap.String("bucket_name", bkt),
			zap.Error(err))

		api.WriteErrorResponse(r.Context(), w, api.Error{
			Code:           api.GetAPIError(api.ErrBadRequest).Code,
			Description:    err.Error(),
			HTTPStatusCode: http.StatusBadRequest,
		}, r.URL)

		return
	}

	metadata := parseMetadata(r)

	params := &layer.PutObjectParams{
		Bucket: bkt,
		Object: obj,
		Reader: r.Body,
		Size:   r.ContentLength,
		Header: metadata,
	}

	if info, err = h.obj.PutObject(r.Context(), params); err != nil {
		h.log.Error("could not upload object",
			zap.String("request_id", rid),
			zap.String("bucket_name", bkt),
			zap.String("object_name", obj),
			zap.Error(err))

		api.WriteErrorResponse(r.Context(), w, api.Error{
			Code:           api.GetAPIError(api.ErrInternalError).Code,
			Description:    err.Error(),
			HTTPStatusCode: http.StatusInternalServerError,
		}, r.URL)

		return
	}

	w.Header().Set(api.ETag, info.HashSum)
	api.WriteSuccessResponseHeadersOnly(w)
}

func parseMetadata(r *http.Request) map[string]string {
	res := make(map[string]string)
	for k, v := range r.Header {
		if strings.HasPrefix(k, api.MetadataPrefix) {
			key := strings.TrimPrefix(k, api.MetadataPrefix)
			res[key] = v[0]
		}
	}
	return res
}

func (h *handler) CreateBucketHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err error
		p   = layer.CreateBucketParams{}
		rid = api.GetRequestID(r.Context())
		req = mux.Vars(r)
	)
	p.Name = req["bucket"]
	if val, ok := r.Header["X-Amz-Acl"]; ok {
		p.ACL, err = parseBasicACL(val[0])
	} else {
		p.ACL = acl.PrivateBasicRule
	}

	if err != nil {
		h.log.Error("could not parse basic ACL",
			zap.String("request_id", rid),
			zap.Error(err))

		api.WriteErrorResponse(r.Context(), w, api.Error{
			Code:           api.GetAPIError(api.ErrBadRequest).Code,
			Description:    err.Error(),
			HTTPStatusCode: http.StatusBadRequest,
		}, r.URL)
	}

	p.Policy, err = policy.Parse(defaultPolicy)
	if err != nil {
		h.log.Error("could not parse policy",
			zap.String("request_id", rid),
			zap.Error(err))

		api.WriteErrorResponse(r.Context(), w, api.Error{
			Code:           api.GetAPIError(api.ErrBadRequest).Code,
			Description:    err.Error(),
			HTTPStatusCode: http.StatusBadRequest,
		}, r.URL)
	}

	cid, err := h.obj.CreateBucket(r.Context(), &p)
	if err != nil {
		h.log.Error("could not create bucket",
			zap.String("request_id", rid),
			zap.Error(err))

		api.WriteErrorResponse(r.Context(), w, api.Error{
			Code:           api.GetAPIError(api.ErrInternalError).Code,
			Description:    err.Error(),
			HTTPStatusCode: http.StatusInternalServerError,
		}, r.URL)
	}

	h.log.Info("bucket is created",
		zap.String("container_id", cid.String()))

	api.WriteSuccessResponseHeadersOnly(w)
}

func parseBasicACL(basicACL string) (uint32, error) {
	switch basicACL {
	case basicACLPublic:
		return acl.PublicBasicRule, nil
	case basicACLPrivate:
		return acl.PrivateBasicRule, nil
	case basicACLReadOnly:
		return acl.ReadOnlyBasicRule, nil
	default:
		basicACL = strings.Trim(strings.ToLower(basicACL), "0x")

		value, err := strconv.ParseUint(basicACL, 16, 32)
		if err != nil {
			return 0, fmt.Errorf("can't parse basic ACL: %s", basicACL)
		}

		return uint32(value), nil
	}
}
