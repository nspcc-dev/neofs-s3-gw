package handler

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"strconv"
	"strings"

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

	publicBasicRule = 0x0FFFFFFF
)

type createBucketParams struct {
	XMLName            xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ CreateBucketConfiguration" json:"-"`
	LocationConstraint string
}

func (h *handler) PutObjectHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err     error
		info    *layer.ObjectInfo
		reqInfo = api.GetReqInfo(r.Context())
	)

	metadata := parseMetadata(r)

	params := &layer.PutObjectParams{
		Bucket: reqInfo.BucketName,
		Object: reqInfo.ObjectName,
		Reader: r.Body,
		Size:   r.ContentLength,
		Header: metadata,
	}

	if info, err = h.obj.PutObject(r.Context(), params); err != nil {
		h.logAndSendError(w, "could not upload object", reqInfo, err)
		return
	}

	w.Header().Set(api.ETag, info.HashSum)
	api.WriteSuccessResponseHeadersOnly(w)
}

func parseMetadata(r *http.Request) map[string]string {
	res := make(map[string]string)
	for k, v := range r.Header {
		if strings.HasPrefix(k, api.MetadataPrefix) {
			key := strings.ToLower(strings.TrimPrefix(k, api.MetadataPrefix))
			res[key] = v[0]
		}
	}
	return res
}

func (h *handler) CreateBucketHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err     error
		reqInfo = api.GetReqInfo(r.Context())
		p       = layer.CreateBucketParams{Name: reqInfo.BucketName}
	)

	if val, ok := r.Header["X-Amz-Acl"]; ok {
		p.ACL, err = parseBasicACL(val[0])
	} else {
		p.ACL = publicBasicRule
	}

	if err != nil {
		h.logAndSendError(w, "could not parse basic ACL", reqInfo, err)
		return
	}

	createParams, err := parseLocationConstraint(r)
	if err != nil {
		h.logAndSendError(w, "could not parse body", reqInfo, err)
		return
	}

	p.BoxData, err = layer.GetBoxData(r.Context())
	if err != nil {
		h.logAndSendError(w, "could not get boxData", reqInfo, err)
		return
	}

	if createParams.LocationConstraint != "" {
		for _, placementPolicy := range p.BoxData.Policies {
			if placementPolicy.LocationConstraint == createParams.LocationConstraint {
				p.Policy = placementPolicy.Policy
				break
			}
		}
	}
	if p.Policy == nil {
		p.Policy, err = policy.Parse(defaultPolicy)
		if err != nil {
			h.logAndSendError(w, "could not parse policy", reqInfo, err)
			return
		}
	}

	cid, err := h.obj.CreateBucket(r.Context(), &p)
	if err != nil {
		h.logAndSendError(w, "could not create bucket", reqInfo, err)
		return
	}

	h.log.Info("bucket is created",
		zap.String("container_id", cid.String()))

	api.WriteSuccessResponseHeadersOnly(w)
}

func parseLocationConstraint(r *http.Request) (*createBucketParams, error) {
	if r.ContentLength == 0 {
		return new(createBucketParams), nil
	}

	params := new(createBucketParams)
	if err := xml.NewDecoder(r.Body).Decode(params); err != nil {
		return nil, err
	}
	return params, nil
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
