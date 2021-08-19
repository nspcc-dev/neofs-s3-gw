package handler

import (
	"encoding/xml"
	"net"
	"net/http"
	"strings"

	"github.com/nspcc-dev/neofs-node/pkg/policy"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"go.uber.org/zap"
)

// keywords of predefined basic ACL values.
const (
	basicACLPrivate   = "private"
	basicACLReadOnly  = "public-read"
	basicACLPublic    = "public-read-write"
	cannedACLAuthRead = "authenticated-read"
	defaultPolicy     = "REP 3"

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

	objectACL, err := parseACLHeaders(r)
	if err != nil {
		h.logAndSendError(w, "could not parse object acl", reqInfo, err)
		return
	}
	objectACL.Resource = reqInfo.BucketName + "/" + reqInfo.ObjectName

	bktPolicy, err := aclToPolicy(objectACL)
	if err != nil {
		h.logAndSendError(w, "could not translate object acl to bucket policy", reqInfo, err)
		return
	}

	astChild, err := policyToAst(bktPolicy)
	if err != nil {
		h.logAndSendError(w, "could not translate policy to ast", reqInfo, err)
		return
	}

	bacl, err := h.obj.GetBucketACL(r.Context(), reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket eacl", reqInfo, err)
		return
	}

	if err = checkOwner(bacl.Info, r.Header.Get(api.AmzExpectedBucketOwner)); err != nil {
		h.logAndSendError(w, "expected owner doesn't match", reqInfo, err)
		return
	}

	parentAst := tableToAst(bacl.EACL, reqInfo.BucketName)
	for _, resource := range parentAst.Resources {
		if resource.Name == bacl.Info.CID.String() {
			resource.Name = reqInfo.BucketName
		}
	}

	resAst, updated := mergeAst(parentAst, astChild)
	table, err := astToTable(resAst, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not translate ast to table", reqInfo, err)
		return
	}

	metadata := parseMetadata(r)
	if contentType := r.Header.Get(api.ContentType); len(contentType) > 0 {
		metadata[api.ContentType] = contentType
	}

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

	if updated {
		p := &layer.PutBucketACLParams{
			Name: reqInfo.BucketName,
			EACL: table,
		}

		if err = h.obj.PutBucketACL(r.Context(), p); err != nil {
			h.logAndSendError(w, "could not put bucket acl", reqInfo, err)
			return
		}
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
		reqInfo = api.GetReqInfo(r.Context())
		p       = layer.CreateBucketParams{Name: reqInfo.BucketName, ACL: publicBasicRule}
	)

	if err := checkBucketName(reqInfo.BucketName); err != nil {
		h.logAndSendError(w, "invalid bucket name", reqInfo, err)
		return
	}

	bktACL, err := parseACLHeaders(r)
	if err != nil {
		h.logAndSendError(w, "could not parse bucket acl", reqInfo, err)
		return
	}
	bktACL.IsBucket = true

	p.EACL, err = bucketACLToTable(bktACL)
	if err != nil {
		h.logAndSendError(w, "could translate bucket acl to eacl", reqInfo, err)
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

func checkBucketName(bucketName string) error {
	if len(bucketName) < 3 || len(bucketName) > 63 {
		return errors.GetAPIError(errors.ErrInvalidBucketName)
	}

	if strings.HasPrefix(bucketName, "xn--") || strings.HasSuffix(bucketName, "-s3alias") {
		return errors.GetAPIError(errors.ErrInvalidBucketName)
	}
	if net.ParseIP(bucketName) != nil {
		return errors.GetAPIError(errors.ErrInvalidBucketName)
	}

	labels := strings.Split(bucketName, ".")
	for _, label := range labels {
		if len(label) == 0 {
			return errors.GetAPIError(errors.ErrInvalidBucketName)
		}
		for i, r := range label {
			if !isAlphaNum(r) && r != '-' {
				return errors.GetAPIError(errors.ErrInvalidBucketName)
			}
			if (i == 0 || i == len(label)-1) && r == '-' {
				return errors.GetAPIError(errors.ErrInvalidBucketName)
			}
		}
	}

	return nil
}

func isAlphaNum(char int32) bool {
	return 'a' <= char && char <= 'z' || '0' <= char && char <= '9'
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
