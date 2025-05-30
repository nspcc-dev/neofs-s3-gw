package handler

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nspcc-dev/neo-go/pkg/util"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/auth"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer/encryption"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3errors"
	"github.com/nspcc-dev/neofs-s3-gw/creds/accessbox"
	"github.com/nspcc-dev/neofs-s3-gw/internal/models"
	apistatus "github.com/nspcc-dev/neofs-sdk-go/client/status"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/session"
	"go.uber.org/zap"
)

type postPolicy struct {
	Expiration time.Time          `json:"expiration"`
	Conditions []*policyCondition `json:"conditions"`
	empty      bool
}

func (p *postPolicy) condition(key string) *policyCondition {
	for _, condition := range p.Conditions {
		if condition.Key == key {
			return condition
		}
	}
	return nil
}

func (p *postPolicy) CheckContentLength(size int64) bool {
	if p.empty {
		return true
	}
	for _, condition := range p.Conditions {
		if condition.Matching == "content-length-range" {
			length := strconv.FormatInt(size, 10)
			return condition.Key <= length && length <= condition.Value
		}
	}
	return true
}

func (p *policyCondition) match(value string) bool {
	switch p.Matching {
	case "eq":
		p.Matched = p.Value == value
	case "starts-with":
		if p.Key == api.ContentType {
			p.Matched = true
			for _, contentType := range strings.Split(value, ",") {
				if !strings.HasPrefix(contentType, p.Value) {
					p.Matched = false
				}
			}
		} else {
			p.Matched = strings.HasPrefix(value, p.Value)
		}
	}
	return p.Matched
}

func (p *postPolicy) CheckField(key string, value string) error {
	if p.empty {
		return nil
	}
	cond := p.condition(key)
	if cond == nil {
		return s3errors.GetAPIError(s3errors.ErrPostPolicyConditionInvalidFormat)
	}

	if !cond.match(value) {
		return s3errors.GetAPIError(s3errors.ErrPostPolicyConditionInvalidFormat)
	}

	return nil
}

func (p *postPolicy) AllConditionMatched() bool {
	for _, condition := range p.Conditions {
		if !condition.Matched {
			return false
		}
	}
	return true
}

type policyCondition struct {
	Matching string
	Key      string
	Value    string
	Matched  bool
}

var errInvalidCondition = fmt.Errorf("invalid condition")

func (p *policyCondition) UnmarshalJSON(data []byte) error {
	var (
		ok bool
		v  any
	)

	if err := json.Unmarshal(data, &v); err != nil {
		return fmt.Errorf("unmarshal policy condition: %w", err)
	}

	switch v := v.(type) {
	case []any:
		if len(v) != 3 {
			return errInvalidCondition
		}
		if p.Matching, ok = v[0].(string); !ok {
			return errInvalidCondition
		}

		if p.Matching == "content-length-range" {
			minV, ok := v[1].(float64)
			maxV, ok2 := v[2].(float64)
			if !ok || !ok2 {
				return errInvalidCondition
			}
			p.Key = strconv.FormatFloat(minV, 'f', 0, 32)
			p.Value = strconv.FormatFloat(maxV, 'f', 0, 32)
		} else {
			key, ok2 := v[1].(string)
			p.Value, ok = v[2].(string)
			if !ok || !ok2 {
				return errInvalidCondition
			}
			p.Key = strings.ToLower(strings.TrimPrefix(key, "$"))
		}

	case map[string]any:
		p.Matching = "eq"
		for key, val := range v {
			p.Key = strings.ToLower(key)
			if p.Value, ok = val.(string); !ok {
				return errInvalidCondition
			}
		}
	default:
		return fmt.Errorf("unknown condition type")
	}

	return nil
}

// keywords of predefined basic ACL values.
const (
	basicACLPrivate                 = "private"
	basicACLReadOnly                = "public-read"
	basicACLPublic                  = "public-read-write"
	cannedACLAuthRead               = "authenticated-read"
	cannedACLBucketOwnerFullControl = "bucket-owner-full-control"

	amzBucketOwnerField        = "BucketOwnerField"
	amzBucketOwnerEnforced     = "BucketOwnerEnforced"
	amzBucketOwnerPreferred    = "BucketOwnerPreferred"
	amzBucketOwnerObjectWriter = "ObjectWriter"
)

type createBucketParams struct {
	XMLName            xml.Name `xml:"CreateBucketConfiguration" json:"-"`
	LocationConstraint string
}

func (h *handler) PutObjectHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err              error
		newEaclTable     *eacl.Table
		sessionTokenEACL *session.Container
		containsACL      = containsACLHeaders(r)
		reqInfo          = api.GetReqInfo(r.Context())
	)

	if containsACL {
		if sessionTokenEACL, err = getSessionTokenSetEACL(r.Context()); err != nil {
			h.logAndSendError(w, "could not get eacl session token from a box", reqInfo, err)
			return
		}
	}

	tagSet, err := parseTaggingHeader(r.Header)
	if err != nil {
		h.logAndSendError(w, "could not parse tagging header", reqInfo, err)
		return
	}

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket objInfo", reqInfo, err)
		return
	}

	settings, err := h.obj.GetBucketSettings(r.Context(), bktInfo)
	if err != nil {
		h.logAndSendError(w, "could not get bucket settings", reqInfo, err)
		return
	}

	if containsACL {
		if settings.BucketOwner == data.BucketOwnerEnforced {
			if !isValidOwnerEnforced(r) {
				h.logAndSendError(w, "access control list not supported", reqInfo, s3errors.GetAPIError(s3errors.ErrAccessControlListNotSupported))
				return
			}
			r.Header.Set(api.AmzACL, "")
		}
	}

	if settings.BucketOwner == data.BucketOwnerPreferredAndRestricted {
		if !isValidOwnerPreferred(r) {
			h.logAndSendError(w, "header x-amz-acl:bucket-owner-full-control must be set", reqInfo, s3errors.GetAPIError(s3errors.ErrAccessDenied))
			return
		}
		r.Header.Set(api.AmzACL, "")
	}

	metadata := parseMetadata(r)
	if contentType := r.Header.Get(api.ContentType); len(contentType) > 0 {
		metadata[api.ContentType] = contentType
	}
	if cacheControl := r.Header.Get(api.CacheControl); len(cacheControl) > 0 {
		metadata[api.CacheControl] = cacheControl
	}
	if expires := r.Header.Get(api.Expires); len(expires) > 0 {
		metadata[api.Expires] = expires
	}

	copiesNumber, err := getCopiesNumberOrDefault(metadata, h.cfg.CopiesNumber)
	if err != nil {
		h.logAndSendError(w, "invalid copies number", reqInfo, err)
		return
	}

	encryptionParams, err := formEncryptionParams(r)
	if err != nil {
		h.logAndSendError(w, "invalid sse headers", reqInfo, err)
		return
	}

	cl, err := contentLengthFromRequest(r)
	if err != nil {
		h.logAndSendError(w, "content length parse failed", reqInfo, err)
		return
	}

	params := &layer.PutObjectParams{
		BktInfo:      bktInfo,
		Object:       reqInfo.ObjectName,
		Reader:       r.Body,
		Size:         cl,
		Header:       metadata,
		Encryption:   encryptionParams,
		CopiesNumber: copiesNumber,
		Tags:         tagSet,
	}

	params.Lock, err = formObjectLock(r.Context(), bktInfo, settings.LockConfiguration, r.Header)
	if err != nil {
		h.logAndSendError(w, "could not form object lock", reqInfo, err)
		return
	}

	extendedObjInfo, err := h.obj.PutObject(r.Context(), params)
	if err != nil {
		_, err2 := io.Copy(io.Discard, r.Body)
		err3 := r.Body.Close()
		if errors.Is(err, apistatus.ErrObjectAccessDenied) {
			h.logAndSendError(w, "could not upload object", reqInfo, s3errors.GetAPIError(s3errors.ErrAccessDenied), zap.Error(err))
			return
		}

		h.logAndSendError(w, "could not upload object", reqInfo, err, zap.Errors("body close errors", []error{err2, err3}))
		return
	}
	objInfo := extendedObjInfo.ObjectInfo

	s := &SendNotificationParams{
		Event:            EventObjectCreatedPut,
		NotificationInfo: data.NotificationInfoFromObject(objInfo),
		BktInfo:          bktInfo,
		ReqInfo:          reqInfo,
	}
	if err = h.sendNotifications(r.Context(), s); err != nil {
		h.log.Error("couldn't send notification: %w", zap.Error(err))
	}

	// The bucket policy could change ACL headers. Check actual state.
	if containsACLHeaders(r) {
		if newEaclTable, err = h.getNewEAclTable(r, bktInfo, objInfo); err != nil {
			h.logAndSendError(w, "could not get new eacl table", reqInfo, err)
			return
		}
	}

	if newEaclTable != nil {
		p := &layer.PutBucketACLParams{
			BktInfo:      bktInfo,
			EACL:         newEaclTable,
			SessionToken: sessionTokenEACL,
		}

		if err = h.obj.PutBucketACL(r.Context(), p); err != nil {
			h.logAndSendError(w, "could not put bucket acl", reqInfo, err)
			return
		}
	}

	if settings.VersioningEnabled() {
		w.Header().Set(api.AmzVersionID, objInfo.VersionID())
	}
	if encryptionParams.Enabled() {
		addSSECHeaders(w.Header(), r.Header)
	}

	w.Header().Set(api.ETag, objInfo.HashSum)
	api.WriteSuccessResponseHeadersOnly(w)
}

func getCopiesNumberOrDefault(metadata map[string]string, defaultCopiesNumber uint32) (uint32, error) {
	copiesNumberStr, ok := metadata[layer.AttributeNeofsCopiesNumber]
	if !ok {
		return defaultCopiesNumber, nil
	}

	copiesNumber, err := strconv.ParseUint(copiesNumberStr, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("pasrse copies number: %w", err)
	}

	return uint32(copiesNumber), nil
}

func formEncryptionParams(r *http.Request) (enc encryption.Params, err error) {
	sseCustomerAlgorithm := r.Header.Get(api.AmzServerSideEncryptionCustomerAlgorithm)
	sseCustomerKey := r.Header.Get(api.AmzServerSideEncryptionCustomerKey)
	sseCustomerKeyMD5 := r.Header.Get(api.AmzServerSideEncryptionCustomerKeyMD5)

	if len(sseCustomerAlgorithm) == 0 && len(sseCustomerKey) == 0 && len(sseCustomerKeyMD5) == 0 {
		return
	}

	if r.TLS == nil {
		return enc, errors.New("encryption available only when TLS is enabled")
	}

	if sseCustomerAlgorithm != layer.AESEncryptionAlgorithm {
		return enc, s3errors.GetAPIError(s3errors.ErrInvalidEncryptionAlgorithm)
	}

	key, err := base64.StdEncoding.DecodeString(sseCustomerKey)
	if err != nil {
		return enc, s3errors.GetAPIError(s3errors.ErrInvalidSSECustomerKey)
	}

	if len(key) != layer.AESKeySize {
		return enc, s3errors.GetAPIError(s3errors.ErrInvalidSSECustomerKey)
	}

	keyMD5, err := base64.StdEncoding.DecodeString(sseCustomerKeyMD5)
	if err != nil {
		return enc, s3errors.GetAPIError(s3errors.ErrSSECustomerKeyMD5Mismatch)
	}

	md5Sum := md5.Sum(key)
	if !bytes.Equal(md5Sum[:], keyMD5) {
		return enc, s3errors.GetAPIError(s3errors.ErrSSECustomerKeyMD5Mismatch)
	}

	params, err := encryption.NewParams(key)
	if err == nil {
		enc = *params
	}

	return enc, err
}

func (h *handler) PostObject(w http.ResponseWriter, r *http.Request) {
	var (
		newEaclTable     *eacl.Table
		tagSet           map[string]string
		sessionTokenEACL *session.Container
		reqInfo          = api.GetReqInfo(r.Context())
		metadata         = make(map[string]string)
		containsACL      = containsACLHeaders(r)
	)

	policy, err := checkPostPolicy(r, reqInfo, metadata)
	if err != nil {
		h.logAndSendError(w, "failed check policy", reqInfo, err)
		return
	}

	if tagging := auth.MultipartFormValue(r, "tagging"); tagging != "" {
		buffer := bytes.NewBufferString(tagging)
		tagSet, err = readTagSet(buffer)
		if err != nil {
			h.logAndSendError(w, "could not read tag set", reqInfo, err)
			return
		}
	}

	if containsACL {
		if sessionTokenEACL, err = getSessionTokenSetEACL(r.Context()); err != nil {
			h.logAndSendError(w, "could not get eacl session token from a box", reqInfo, err)
			return
		}
	}

	var contentReader io.Reader
	var size int64
	if content, ok := r.MultipartForm.Value["file"]; ok {
		contentReader = bytes.NewBufferString(content[0])
		size = int64(len(content[0]))
	} else {
		file, head, err := r.FormFile("file")
		if err != nil {
			h.logAndSendError(w, "could get uploading file", reqInfo, err)
			return
		}
		contentReader = file
		size = head.Size
		reqInfo.ObjectName = strings.ReplaceAll(reqInfo.ObjectName, "${filename}", head.Filename)
	}
	if !policy.CheckContentLength(size) {
		h.logAndSendError(w, "invalid content-length", reqInfo, s3errors.GetAPIError(s3errors.ErrInvalidArgument))
		return
	}

	bktInfo, err := h.obj.GetBucketInfo(r.Context(), reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	settings, err := h.obj.GetBucketSettings(r.Context(), bktInfo)
	if err != nil {
		h.logAndSendError(w, "could not get bucket settings", reqInfo, err)
		return
	}

	if containsACL {
		if settings.BucketOwner == data.BucketOwnerEnforced {
			if !isValidOwnerEnforced(r) {
				h.logAndSendError(w, "access control list not supported", reqInfo, s3errors.GetAPIError(s3errors.ErrAccessControlListNotSupported))
				return
			}
			r.Header.Set(api.AmzACL, "")
		}
	}

	if settings.BucketOwner == data.BucketOwnerPreferredAndRestricted {
		if !isValidOwnerPreferred(r) {
			h.logAndSendError(w, "header x-amz-acl:bucket-owner-full-control must be set", reqInfo, s3errors.GetAPIError(s3errors.ErrAccessDenied))
			return
		}
		r.Header.Set(api.AmzACL, "")
	}

	params := &layer.PutObjectParams{
		BktInfo: bktInfo,
		Object:  reqInfo.ObjectName,
		Reader:  contentReader,
		Size:    size,
		Header:  metadata,
		Tags:    tagSet,
	}

	extendedObjInfo, err := h.obj.PutObject(r.Context(), params)
	if err != nil {
		h.logAndSendError(w, "could not upload object", reqInfo, err)
		return
	}
	objInfo := extendedObjInfo.ObjectInfo

	s := &SendNotificationParams{
		Event:            EventObjectCreatedPost,
		NotificationInfo: data.NotificationInfoFromObject(objInfo),
		BktInfo:          bktInfo,
		ReqInfo:          reqInfo,
	}
	if err = h.sendNotifications(r.Context(), s); err != nil {
		h.log.Error("couldn't send notification: %w", zap.Error(err))
	}

	if acl := auth.MultipartFormValue(r, "acl"); acl != "" {
		if api.IsAnonymousRequest(r.Context()) {
			h.logAndSendError(w, "anonymous can't override ACL rules", reqInfo, s3errors.GetAPIError(s3errors.ErrNotImplemented))
			return
		}

		r.Header.Set(api.AmzACL, acl)
		r.Header.Set(api.AmzGrantFullControl, "")
		r.Header.Set(api.AmzGrantWrite, "")
		r.Header.Set(api.AmzGrantRead, "")

		if newEaclTable, err = h.getNewEAclTable(r, bktInfo, objInfo); err != nil {
			h.logAndSendError(w, "could not get new eacl table", reqInfo, err)
			return
		}
	}

	if newEaclTable != nil {
		p := &layer.PutBucketACLParams{
			BktInfo:      bktInfo,
			EACL:         newEaclTable,
			SessionToken: sessionTokenEACL,
		}

		if err = h.obj.PutBucketACL(r.Context(), p); err != nil {
			h.logAndSendError(w, "could not put bucket acl", reqInfo, err)
			return
		}
	}

	if settings, err := h.obj.GetBucketSettings(r.Context(), bktInfo); err != nil {
		h.log.Warn("couldn't get bucket versioning", zap.String("bucket name", reqInfo.BucketName), zap.Error(err))
	} else if settings.VersioningEnabled() {
		w.Header().Set(api.AmzVersionID, objInfo.VersionID())
	}

	if redirectURL := auth.MultipartFormValue(r, "success_action_redirect"); redirectURL != "" {
		http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
		return
	}
	status := http.StatusNoContent
	if statusStr := auth.MultipartFormValue(r, "success_action_status"); statusStr != "" {
		switch statusStr {
		case "200":
			status = http.StatusOK
		case "201":
			status = http.StatusCreated
			resp := &PostResponse{
				Bucket: objInfo.Bucket,
				Key:    objInfo.Name,
				ETag:   objInfo.HashSum,
			}
			w.WriteHeader(status)
			if _, err = w.Write(api.EncodeResponse(resp)); err != nil {
				h.logAndSendError(w, "something went wrong", reqInfo, err)
			}
			return
		}
	}

	w.Header().Set(api.ETag, objInfo.HashSum)
	w.WriteHeader(status)
}

func checkPostPolicy(r *http.Request, reqInfo *api.ReqInfo, metadata map[string]string) (*postPolicy, error) {
	policy := &postPolicy{empty: true}
	if policyStr := auth.MultipartFormValue(r, "policy"); policyStr != "" {
		policyData, err := base64.StdEncoding.DecodeString(policyStr)
		if err != nil {
			return nil, fmt.Errorf("could not decode policy: %w", err)
		}
		if err = json.Unmarshal(policyData, policy); err != nil {
			return nil, fmt.Errorf("could not unmarshal policy: %w", err)
		}
		if policy.Expiration.Before(time.Now()) {
			return nil, fmt.Errorf("policy is expired: %w", s3errors.GetAPIError(s3errors.ErrInvalidArgument))
		}
		policy.empty = false
	}

	for key, v := range r.MultipartForm.Value {
		value := v[0]
		if key == "file" || key == "policy" || key == "x-amz-signature" || strings.HasPrefix(key, "x-ignore-") {
			continue
		}
		if err := policy.CheckField(key, value); err != nil {
			return nil, fmt.Errorf("'%s' form field doesn't match the policy: %w", key, err)
		}

		prefix := strings.ToLower(api.MetadataPrefix)
		if strings.HasPrefix(key, prefix) {
			metadata[strings.TrimPrefix(key, prefix)] = value
		}

		if key == "content-type" {
			metadata[api.ContentType] = value
		}

		if key == "key" {
			reqInfo.ObjectName = value
		}
	}

	for _, cond := range policy.Conditions {
		if cond.Key == "bucket" {
			if !cond.match(reqInfo.BucketName) {
				return nil, s3errors.GetAPIError(s3errors.ErrPostPolicyConditionInvalidFormat)
			}
		}
	}

	return policy, nil
}

func containsACLHeaders(r *http.Request) bool {
	return r.Header.Get(api.AmzACL) != "" || r.Header.Get(api.AmzGrantRead) != "" ||
		r.Header.Get(api.AmzGrantFullControl) != "" || r.Header.Get(api.AmzGrantWrite) != ""
}

func (h *handler) getNewEAclTable(r *http.Request, bktInfo *data.BucketInfo, objInfo *data.ObjectInfo) (*eacl.Table, error) {
	var newEaclTable *eacl.Table

	iss, err := h.bearerTokenIssuer(r.Context())
	if err != nil {
		return nil, fmt.Errorf("get bearer token issuer: %w", err)
	}
	objectACL, err := parseACLHeaders(r.Header, iss)
	if err != nil {
		return nil, fmt.Errorf("could not parse object acl: %w", err)
	}

	resInfo := &resourceInfo{
		Bucket:  objInfo.Bucket,
		Object:  objInfo.Name,
		Version: objInfo.VersionID(),
	}

	bktPolicy, err := aclToPolicy(objectACL, resInfo)
	if err != nil {
		return nil, fmt.Errorf("could not translate object acl to bucket policy: %w", err)
	}

	astChild, err := policyToAst(bktPolicy)
	if err != nil {
		return nil, fmt.Errorf("could not translate policy to ast: %w", err)
	}

	bacl, err := h.obj.GetBucketACL(r.Context(), bktInfo)
	if err != nil {
		return nil, fmt.Errorf("could not get bucket eacl: %w", err)
	}

	parentAst := tableToAst(bacl.EACL, objInfo.Bucket)
	strCID := bacl.Info.CID.EncodeToString()

	for _, resource := range parentAst.Resources {
		if resource.Bucket == strCID {
			resource.Bucket = objInfo.Bucket
		}
	}

	if resAst, updated := mergeAst(parentAst, astChild); updated {
		if newEaclTable, err = astToTable(resAst); err != nil {
			return nil, fmt.Errorf("could not translate ast to table: %w", err)
		}
	}

	return newEaclTable, nil
}

func parseTaggingHeader(header http.Header) (map[string]string, error) {
	var tagSet map[string]string
	if tagging := header.Get(api.AmzTagging); len(tagging) > 0 {
		queries, err := url.ParseQuery(tagging)
		if err != nil {
			return nil, s3errors.GetAPIError(s3errors.ErrInvalidArgument)
		}
		if len(queries) > maxTags {
			return nil, s3errors.GetAPIError(s3errors.ErrInvalidTagsSizeExceed)
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
	reqInfo := api.GetReqInfo(r.Context())
	p := &layer.CreateBucketParams{
		Name: reqInfo.BucketName,
	}

	if err := checkBucketName(reqInfo.BucketName); err != nil {
		h.logAndSendError(w, "invalid bucket name", reqInfo, err)
		return
	}

	iss, err := h.bearerTokenIssuer(r.Context())
	if err != nil {
		h.logAndSendError(w, "couldn't get bearer token issuer", reqInfo, err)
		return
	}

	bktACL, err := parseACLHeaders(r.Header, iss)
	if err != nil {
		h.logAndSendError(w, "could not parse bucket acl", reqInfo, err)
		return
	}

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

	var policies []*accessbox.ContainerPolicy
	var userAddr util.Uint160
	boxData, err := layer.GetBoxData(r.Context())
	if err == nil {
		policies = boxData.Policies
		p.SessionContainerCreation = boxData.Gate.SessionTokenForPut()
		p.SessionEACL = boxData.Gate.SessionTokenForSetEACL()
		userAddr = boxData.Gate.BearerToken.Issuer().ScriptHash()
	}

	if p.SessionContainerCreation == nil {
		h.logAndSendError(w, "couldn't find session token for put", reqInfo, s3errors.GetAPIError(s3errors.ErrAccessDenied))
		return
	}

	if p.SessionEACL == nil {
		h.logAndSendError(w, "couldn't find session token for setEACL", reqInfo, s3errors.GetAPIError(s3errors.ErrAccessDenied))
		return
	}

	h.setPolicy(p, userAddr, createParams.LocationConstraint, policies)

	p.ObjectLockEnabled = isLockEnabled(r.Header)

	bktInfo, err := h.obj.CreateBucket(r.Context(), p)
	if err != nil {
		h.logAndSendError(w, "could not create bucket", reqInfo, err)
		return
	}

	h.log.Info("bucket is created", zap.String("reqId", reqInfo.RequestID),
		zap.String("bucket", reqInfo.BucketName), zap.Stringer("container_id", bktInfo.CID))

	if p.ObjectLockEnabled {
		sp := &layer.PutSettingsParams{
			BktInfo:      bktInfo,
			Settings:     &data.BucketSettings{Versioning: data.VersioningEnabled},
			CopiesNumber: h.cfg.CopiesNumber,
		}
		if err = h.obj.PutBucketSettings(r.Context(), sp); err != nil {
			h.logAndSendError(w, "couldn't enable bucket versioning", reqInfo, err,
				zap.String("container_id", bktInfo.CID.EncodeToString()))
			return
		}
	}

	api.WriteSuccessResponseHeadersOnly(w)
}

func (h handler) setPolicy(prm *layer.CreateBucketParams, userAddr util.Uint160, locationConstraint string, userPolicies []*accessbox.ContainerPolicy) {
	prm.Policy = layer.PlacementPolicy{
		Version:     layer.PlacementPolicyV1,
		Placement:   h.cfg.Policy.Default(),
		Consistency: h.cfg.ContainerMetadataPolicy,
	}

	if locationConstraint == "" {
		return
	}

	if policy, ok := h.cfg.Policy.Get(locationConstraint); ok {
		prm.Policy = layer.PlacementPolicy{
			Version:     layer.PlacementPolicyV1,
			Placement:   policy,
			Consistency: h.cfg.ContainerMetadataPolicy,
		}
		prm.LocationConstraint = locationConstraint
	}

	for _, placementPolicy := range userPolicies {
		if placementPolicy.LocationConstraint == locationConstraint {
			prm.Policy = layer.PlacementPolicy{
				Version:     layer.PlacementPolicyV1,
				Placement:   placementPolicy.Policy,
				Consistency: h.cfg.ContainerMetadataPolicy,
			}
			prm.LocationConstraint = locationConstraint
			return
		}
	}

	policy, err := h.cfg.PlacementPolicyProvider.GetPlacementPolicy(userAddr, locationConstraint)
	if err != nil {
		// nothing to do.
		if errors.Is(err, models.ErrNotFound) {
			return
		}

		h.log.Error("get policy from provider", zap.Error(err))
		return
	}

	prm.Policy = *policy
	prm.LocationConstraint = locationConstraint
}

func isLockEnabled(header http.Header) bool {
	lockEnabledStr := header.Get(api.AmzBucketObjectLockEnabled)
	lockEnabled, _ := strconv.ParseBool(lockEnabledStr)
	return lockEnabled
}

func checkBucketName(bucketName string) error {
	if len(bucketName) < 3 || len(bucketName) > 63 {
		return s3errors.GetAPIError(s3errors.ErrInvalidBucketName)
	}

	if strings.HasPrefix(bucketName, "xn--") || strings.HasSuffix(bucketName, "-s3alias") {
		return s3errors.GetAPIError(s3errors.ErrInvalidBucketName)
	}
	if net.ParseIP(bucketName) != nil {
		return s3errors.GetAPIError(s3errors.ErrInvalidBucketName)
	}

	labels := strings.Split(bucketName, ".")
	for _, label := range labels {
		if len(label) == 0 {
			return s3errors.GetAPIError(s3errors.ErrInvalidBucketName)
		}
		for i, r := range label {
			if !isAlphaNum(r) && r != '-' {
				return s3errors.GetAPIError(s3errors.ErrInvalidBucketName)
			}
			if (i == 0 || i == len(label)-1) && r == '-' {
				return s3errors.GetAPIError(s3errors.ErrInvalidBucketName)
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
		return nil, s3errors.GetAPIError(s3errors.ErrMalformedXML)
	}
	return params, nil
}
