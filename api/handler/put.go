package handler

import (
	"encoding/xml"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/nspcc-dev/neofs-api-go/pkg/acl/eacl"
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

	publicBasicRule = 0x0FFFFFFF
)

type createBucketParams struct {
	XMLName            xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ CreateBucketConfiguration" json:"-"`
	LocationConstraint string
}

func (h *handler) PutObjectHandler(w http.ResponseWriter, r *http.Request) {
	var newEaclTable *eacl.Table
	reqInfo := api.GetReqInfo(r.Context())
	tagSet, err := parseTaggingHeader(r.Header)
	if err != nil {
		h.logAndSendError(w, "could not parse tagging header", reqInfo, err)
		return
	}

	if containsACLHeaders(r) {
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

		parentAst := tableToAst(bacl.EACL, reqInfo.BucketName)
		for _, resource := range parentAst.Resources {
			if resource.Name == bacl.Info.CID.String() {
				resource.Name = reqInfo.BucketName
			}
		}

		if resAst, updated := mergeAst(parentAst, astChild); updated {
			if newEaclTable, err = astToTable(resAst, reqInfo.BucketName); err != nil {
				h.logAndSendError(w, "could not translate ast to table", reqInfo, err)
				return
			}
		}
	}

	bktInfo, err := h.obj.GetBucketInfo(r.Context(), reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket eacl", reqInfo, err)
		return
	}
	if err = checkOwner(bktInfo, r.Header.Get(api.AmzExpectedBucketOwner)); err != nil {
		h.logAndSendError(w, "expected owner doesn't match", reqInfo, err)
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

	info, err := h.obj.PutObject(r.Context(), params)
	if err != nil {
		h.logAndSendError(w, "could not upload object", reqInfo, err)
		return
	}

	if tagSet != nil {
		if err = h.obj.PutObjectTagging(r.Context(), &layer.PutTaggingParams{ObjectInfo: info, TagSet: tagSet}); err != nil {
			h.logAndSendError(w, "could not upload object tagging", reqInfo, err)
			return
		}
	}

	if newEaclTable != nil {
		p := &layer.PutBucketACLParams{
			Name: reqInfo.BucketName,
			EACL: newEaclTable,
		}

		if err = h.obj.PutBucketACL(r.Context(), p); err != nil {
			h.logAndSendError(w, "could not put bucket acl", reqInfo, err)
			return
		}
	}

	if versioning, err := h.obj.GetBucketVersioning(r.Context(), reqInfo.BucketName); err != nil {
		h.log.Warn("couldn't get bucket versioning", zap.String("bucket name", reqInfo.BucketName), zap.Error(err))
	} else if versioning.VersioningEnabled {
		w.Header().Set(api.AmzVersionID, info.Version())
	}

	w.Header().Set(api.ETag, info.HashSum)
	api.WriteSuccessResponseHeadersOnly(w)
}

func containsACLHeaders(r *http.Request) bool {
	return r.Header.Get(api.AmzACL) != "" || r.Header.Get(api.AmzGrantRead) != "" ||
		r.Header.Get(api.AmzGrantFullControl) != "" || r.Header.Get(api.AmzGrantWrite) != ""
}

func parseTaggingHeader(header http.Header) (map[string]string, error) {
	var tagSet map[string]string
	if tagging := header.Get(api.AmzTagging); len(tagging) > 0 {
		queries, err := url.ParseQuery(tagging)
		if err != nil {
			return nil, errors.GetAPIError(errors.ErrInvalidArgument)
		}
		if len(queries) > maxTags {
			return nil, errors.GetAPIError(errors.ErrInvalidTagsSizeExceed)
		}
		tagSet = make(map[string]string, len(queries))
		for k, v := range queries {
			tag := Tag{Key: k, Value: v[0]}
			if err = checkTag(tag); err != nil {
				return nil, err
			}
			tagSet[tag.Key] = tag.Value
		}
	}
	return tagSet, nil
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
		p.Policy = h.cfg.DefaultPolicy
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
