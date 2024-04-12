package handler

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3errors"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/session"
	"go.uber.org/zap"
)

var (
	writeOps    = []eacl.Operation{eacl.OperationPut, eacl.OperationDelete}
	writeOpsMap = map[eacl.Operation]struct{}{
		eacl.OperationPut:    {},
		eacl.OperationDelete: {},
	}
	readOps = []eacl.Operation{eacl.OperationGet, eacl.OperationHead,
		eacl.OperationSearch, eacl.OperationRange, eacl.OperationRangeHash}
	readOpsMap = map[eacl.Operation]struct{}{
		eacl.OperationGet:       {},
		eacl.OperationHead:      {},
		eacl.OperationSearch:    {},
		eacl.OperationRange:     {},
		eacl.OperationRangeHash: {},
	}
	fullOps = []eacl.Operation{eacl.OperationGet, eacl.OperationHead, eacl.OperationPut,
		eacl.OperationDelete, eacl.OperationSearch, eacl.OperationRange, eacl.OperationRangeHash}
)

var actionToOpMap = map[string][]eacl.Operation{
	s3DeleteObject: {eacl.OperationDelete},
	s3GetObject:    readOps,
	s3PutObject:    {eacl.OperationPut},
	s3ListBucket:   readOps,
}

var (
	errInvalidPublicKey = errors.New("invalid public key")
)

const (
	arnAwsPrefix     = "arn:aws:s3:::"
	allUsersWildcard = "*"
	allUsersGroup    = "http://acs.amazonaws.com/groups/global/AllUsers"

	s3DeleteObject               = "s3:DeleteObject"
	s3GetObject                  = "s3:GetObject"
	s3PutObject                  = "s3:PutObject"
	s3ListBucket                 = "s3:ListBucket"
	s3ListBucketVersions         = "s3:ListBucketVersions"
	s3ListBucketMultipartUploads = "s3:ListBucketMultipartUploads"
	s3GetObjectVersion           = "s3:GetObjectVersion"
)

// enum of Amazon S3 ACL permissions.
type amazonS3Permission string

// various access permissions defined in
// https://docs.aws.amazon.com/AmazonS3/latest/API/API_Grant.html.
//
// See also https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html#permissions.
const (
	awsPermFullControl amazonS3Permission = "FULL_CONTROL"
	awsPermWrite       amazonS3Permission = "WRITE"
	awsPermRead        amazonS3Permission = "READ"
)

// enum of Amazon S3 ACL permission grantees.
type granteeType string

// various grantee types defined in
// https://docs.aws.amazon.com/AmazonS3/latest/API/API_Grantee.html
const (
	granteeCanonicalUser         granteeType = "CanonicalUser"
	granteeAmazonCustomerByEmail granteeType = "AmazonCustomerByEmail"
	granteeGroup                 granteeType = "Group"
)

type bucketPolicy struct {
	Version   string      `json:"Version"`
	ID        string      `json:"Id"`
	Statement []statement `json:"Statement"`
	Bucket    string      `json:"-"`
}

type statement struct {
	Sid       string    `json:"Sid"`
	Effect    string    `json:"Effect"`
	Principal principal `json:"Principal"`
	Action    []string  `json:"Action"`
	Resource  []string  `json:"Resource"`
}

type principal struct {
	AWS           string `json:"AWS,omitempty"`
	CanonicalUser string `json:"CanonicalUser,omitempty"`
}

type orderedAstResource struct {
	Index    int
	Resource *astResource
}

type ast struct {
	Resources []*astResource
}

type astResource struct {
	resourceInfo
	Operations []*astOperation
}

type resourceInfo struct {
	Bucket  string
	Object  string
	Version string
}

func (r *resourceInfo) Name() string {
	if len(r.Object) == 0 {
		return r.Bucket
	}
	if len(r.Version) == 0 {
		return r.Bucket + "/" + r.Object
	}
	return r.Bucket + "/" + r.Object + ":" + r.Version
}

func (r *resourceInfo) IsBucket() bool {
	return len(r.Object) == 0
}

type astOperation struct {
	Users  []string
	Op     eacl.Operation
	Action eacl.Action
}

func (a astOperation) IsGroupGrantee() bool {
	return len(a.Users) == 0
}

const (
	serviceRecordResourceKey    = "Resource"
	serviceRecordGroupLengthKey = "GroupLength"
)

type ServiceRecord struct {
	Resource           string
	GroupRecordsLength int
}

func (h *handler) GetBucketACLHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	bucketACL, err := h.obj.GetBucketACL(r.Context(), bktInfo)
	if err != nil {
		h.logAndSendError(w, "could not fetch bucket acl", reqInfo, err)
		return
	}

	if err = api.EncodeToResponse(w, h.encodeBucketACL(bktInfo.Name, bucketACL)); err != nil {
		h.logAndSendError(w, "something went wrong", reqInfo, err)
		return
	}
}

func (h *handler) bearerTokenIssuerKey(ctx context.Context) (*keys.PublicKey, error) {
	box, err := layer.GetBoxData(ctx)
	if err != nil {
		return nil, err
	}

	key, err := keys.NewPublicKeyFromBytes(box.Gate.BearerToken.SigningKeyBytes(), elliptic.P256())
	if err != nil {
		return nil, fmt.Errorf("public key from bytes: %w", err)
	}

	return key, nil
}

func (h *handler) PutBucketACLHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())
	key, err := h.bearerTokenIssuerKey(r.Context())
	if err != nil {
		h.logAndSendError(w, "couldn't get bearer token issuer key", reqInfo, err)
		return
	}

	token, err := getSessionTokenSetEACL(r.Context())
	if err != nil {
		h.logAndSendError(w, "couldn't get eacl token", reqInfo, err)
		return
	}

	list := &AccessControlPolicy{}
	if r.ContentLength == 0 {
		list, err = parseACLHeaders(r.Header, key)
		if err != nil {
			h.logAndSendError(w, "could not parse bucket acl", reqInfo, err)
			return
		}
	} else if err = xml.NewDecoder(r.Body).Decode(list); err != nil {
		h.logAndSendError(w, "could not parse bucket acl", reqInfo, s3errors.GetAPIError(s3errors.ErrMalformedXML))
		return
	}

	resInfo := &resourceInfo{Bucket: reqInfo.BucketName}
	astBucket, err := aclToAst(list, resInfo)
	if err != nil {
		h.logAndSendError(w, "could not translate acl to policy", reqInfo, err)
		return
	}

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	if _, err = h.updateBucketACL(r, astBucket, bktInfo, token); err != nil {
		h.logAndSendError(w, "could not update bucket acl", reqInfo, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *handler) updateBucketACL(r *http.Request, astChild *ast, bktInfo *data.BucketInfo, sessionToken *session.Container) (bool, error) {
	bucketACL, err := h.obj.GetBucketACL(r.Context(), bktInfo)
	if err != nil {
		return false, fmt.Errorf("could not get bucket eacl: %w", err)
	}

	parentAst := tableToAst(bucketACL.EACL, bktInfo.Name)
	strCID := bucketACL.Info.CID.EncodeToString()

	for _, resource := range parentAst.Resources {
		if resource.Bucket == strCID {
			resource.Bucket = bktInfo.Name
		}
	}

	resAst, updated := mergeAst(parentAst, astChild)
	if !updated {
		return false, nil
	}

	table, err := astToTable(resAst)
	if err != nil {
		return false, fmt.Errorf("could not translate ast to table: %w", err)
	}

	p := &layer.PutBucketACLParams{
		BktInfo:      bktInfo,
		EACL:         table,
		SessionToken: sessionToken,
	}

	if err = h.obj.PutBucketACL(r.Context(), p); err != nil {
		return false, fmt.Errorf("could not put bucket acl: %w", err)
	}

	return true, nil
}

func (h *handler) GetObjectACLHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	bucketACL, err := h.obj.GetBucketACL(r.Context(), bktInfo)
	if err != nil {
		h.logAndSendError(w, "could not fetch bucket acl", reqInfo, err)
		return
	}

	prm := &layer.HeadObjectParams{
		BktInfo:   bktInfo,
		Object:    reqInfo.ObjectName,
		VersionID: reqInfo.URL.Query().Get(api.QueryVersionID),
	}

	objInfo, err := h.obj.GetObjectInfo(r.Context(), prm)
	if err != nil {
		h.logAndSendError(w, "could not object info", reqInfo, err)
		return
	}

	if err = api.EncodeToResponse(w, encodeObjectACL(h.log, bucketACL, reqInfo.BucketName, objInfo.VersionID())); err != nil {
		h.logAndSendError(w, "failed to encode response", reqInfo, err)
	}
}

func (h *handler) PutObjectACLHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())
	versionID := reqInfo.URL.Query().Get(api.QueryVersionID)
	key, err := h.bearerTokenIssuerKey(r.Context())
	if err != nil {
		h.logAndSendError(w, "couldn't get gate key", reqInfo, err)
		return
	}

	token, err := getSessionTokenSetEACL(r.Context())
	if err != nil {
		h.logAndSendError(w, "couldn't get eacl token", reqInfo, err)
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
		VersionID: versionID,
	}

	objInfo, err := h.obj.GetObjectInfo(r.Context(), p)
	if err != nil {
		h.logAndSendError(w, "could not get object info", reqInfo, err)
		return
	}

	list := &AccessControlPolicy{}
	if r.ContentLength == 0 {
		list, err = parseACLHeaders(r.Header, key)
		if err != nil {
			h.logAndSendError(w, "could not parse bucket acl", reqInfo, err)
			return
		}
	} else if err = xml.NewDecoder(r.Body).Decode(list); err != nil {
		h.logAndSendError(w, "could not parse bucket acl", reqInfo, s3errors.GetAPIError(s3errors.ErrMalformedXML))
		return
	}

	resInfo := &resourceInfo{
		Bucket:  reqInfo.BucketName,
		Object:  reqInfo.ObjectName,
		Version: objInfo.VersionID(),
	}

	astObject, err := aclToAst(list, resInfo)
	if err != nil {
		h.logAndSendError(w, "could not translate acl to ast", reqInfo, err)
		return
	}

	updated, err := h.updateBucketACL(r, astObject, bktInfo, token)
	if err != nil {
		h.logAndSendError(w, "could not update bucket acl", reqInfo, err)
		return
	}
	if updated {
		s := &SendNotificationParams{
			Event:            EventObjectACLPut,
			NotificationInfo: data.NotificationInfoFromObject(objInfo),
			BktInfo:          bktInfo,
			ReqInfo:          reqInfo,
		}
		if err = h.sendNotifications(r.Context(), s); err != nil {
			h.log.Error("couldn't send notification: %w", zap.Error(err))
		}
	}
	w.WriteHeader(http.StatusOK)
}

func (h *handler) GetBucketPolicyHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	bucketACL, err := h.obj.GetBucketACL(r.Context(), bktInfo)
	if err != nil {
		h.logAndSendError(w, "could not fetch bucket acl", reqInfo, err)
		return
	}

	ast := tableToAst(bucketACL.EACL, reqInfo.BucketName)
	bktPolicy := astToPolicy(ast)

	w.WriteHeader(http.StatusOK)

	if err = json.NewEncoder(w).Encode(bktPolicy); err != nil {
		h.logAndSendError(w, "something went wrong", reqInfo, err)
	}
}

func checkOwner(info *data.BucketInfo, owner string) error {
	if owner == "" {
		return nil
	}

	// may need to convert owner to appropriate format
	if info.Owner.String() != owner {
		return s3errors.GetAPIError(s3errors.ErrAccessDenied)
	}

	return nil
}

func (h *handler) PutBucketPolicyHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	token, err := getSessionTokenSetEACL(r.Context())
	if err != nil {
		h.logAndSendError(w, "couldn't get eacl token", reqInfo, err)
		return
	}

	bktPolicy := &bucketPolicy{Bucket: reqInfo.BucketName}
	if err = json.NewDecoder(r.Body).Decode(bktPolicy); err != nil {
		h.logAndSendError(w, "could not parse bucket policy", reqInfo, err)
		return
	}

	astPolicy, err := policyToAst(bktPolicy)
	if err != nil {
		h.logAndSendError(w, "could not translate policy to ast", reqInfo, err)
		return
	}

	if _, err = h.updateBucketACL(r, astPolicy, bktInfo, token); err != nil {
		h.logAndSendError(w, "could not update bucket acl", reqInfo, err)
		return
	}
}

func parseACLHeaders(header http.Header, key *keys.PublicKey) (*AccessControlPolicy, error) {
	var err error
	acp := &AccessControlPolicy{Owner: Owner{
		ID:          hex.EncodeToString(key.Bytes()),
		DisplayName: key.Address(),
	}}
	acp.AccessControlList = []*Grant{{
		Grantee: &Grantee{
			ID:          hex.EncodeToString(key.Bytes()),
			DisplayName: key.Address(),
			Type:        granteeCanonicalUser,
		},
		Permission: awsPermFullControl,
	}}

	cannedACL := header.Get(api.AmzACL)
	if cannedACL != "" {
		return addPredefinedACP(acp, cannedACL)
	}

	if acp.AccessControlList, err = addGrantees(acp.AccessControlList, header, api.AmzGrantFullControl); err != nil {
		return nil, fmt.Errorf("add grantees full control: %w", err)
	}
	if acp.AccessControlList, err = addGrantees(acp.AccessControlList, header, api.AmzGrantRead); err != nil {
		return nil, fmt.Errorf("add grantees read: %w", err)
	}
	if acp.AccessControlList, err = addGrantees(acp.AccessControlList, header, api.AmzGrantWrite); err != nil {
		return nil, fmt.Errorf("add grantees write: %w", err)
	}

	return acp, nil
}

func addGrantees(list []*Grant, headers http.Header, hdr string) ([]*Grant, error) {
	grant := headers.Get(hdr)
	if grant == "" {
		return list, nil
	}

	permission, err := grantHdrToPermission(hdr)
	if err != nil {
		return nil, fmt.Errorf("parse header: %w", err)
	}

	grantees, err := parseGrantee(grant)
	if err != nil {
		return nil, fmt.Errorf("parse grantee: %w", err)
	}

	for _, grantee := range grantees {
		if grantee.Type == granteeAmazonCustomerByEmail || (grantee.Type == granteeGroup && grantee.URI != allUsersGroup) {
			return nil, s3errors.GetAPIError(s3errors.ErrNotSupported)
		}

		list = append(list, &Grant{
			Grantee:    grantee,
			Permission: permission,
		})
	}
	return list, nil
}

func grantHdrToPermission(grant string) (amazonS3Permission, error) {
	switch grant {
	case api.AmzGrantFullControl:
		return awsPermFullControl, nil
	case api.AmzGrantRead:
		return awsPermRead, nil
	case api.AmzGrantWrite:
		return awsPermWrite, nil
	}
	return "", fmt.Errorf("unsuppoted header: %s", grant)
}

func parseGrantee(grantees string) ([]*Grantee, error) {
	var result []*Grantee

	split := strings.Split(grantees, ", ")
	for _, pair := range split {
		split2 := strings.Split(pair, "=")
		if len(split2) != 2 {
			return nil, s3errors.GetAPIError(s3errors.ErrInvalidArgument)
		}

		grantee, err := formGrantee(split2[0], split2[1])
		if err != nil {
			return nil, fmt.Errorf("form grantee: %w", err)
		}
		result = append(result, grantee)
	}

	return result, nil
}

func formGrantee(granteeType, value string) (*Grantee, error) {
	value = strings.Trim(value, "\"")
	switch granteeType {
	case "id":
		return &Grantee{
			ID:   value,
			Type: granteeCanonicalUser,
		}, nil
	case "uri":
		return &Grantee{
			URI:  value,
			Type: granteeGroup,
		}, nil
	case "emailAddress":
		return &Grantee{
			EmailAddress: value,
			Type:         granteeAmazonCustomerByEmail,
		}, nil
	}
	// do not return grantee type to avoid sensitive data logging (#489)
	return nil, fmt.Errorf("unknown grantee type")
}

func addPredefinedACP(acp *AccessControlPolicy, cannedACL string) (*AccessControlPolicy, error) {
	switch cannedACL {
	case basicACLPrivate:
	case basicACLPublic:
		acp.AccessControlList = append(acp.AccessControlList, &Grant{
			Grantee: &Grantee{
				URI:  allUsersGroup,
				Type: granteeGroup,
			},
			Permission: awsPermFullControl,
		})
	case cannedACLAuthRead:
		fallthrough
	case basicACLReadOnly:
		acp.AccessControlList = append(acp.AccessControlList, &Grant{
			Grantee: &Grantee{
				URI:  allUsersGroup,
				Type: granteeGroup,
			},
			Permission: awsPermRead,
		})
	default:
		return nil, s3errors.GetAPIError(s3errors.ErrInvalidArgument)
	}

	return acp, nil
}

func tableToAst(table *eacl.Table, bktName string) *ast {
	resourceMap := make(map[string]orderedAstResource)

	var groupRecordsLeft int
	var currentResource orderedAstResource
	for i, record := range table.Records() {
		if serviceRec := tryServiceRecord(record); serviceRec != nil {
			resInfo := resourceInfoFromName(serviceRec.Resource, bktName)
			groupRecordsLeft = serviceRec.GroupRecordsLength

			currentResource = getResourceOrCreate(resourceMap, i, resInfo)
			resourceMap[resInfo.Name()] = currentResource
		} else if groupRecordsLeft != 0 {
			groupRecordsLeft--
			addOperationsAndUpdateMap(currentResource, record, resourceMap)
		} else {
			resInfo := resInfoFromFilters(bktName, record.Filters())
			resource := getResourceOrCreate(resourceMap, i, resInfo)
			addOperationsAndUpdateMap(resource, record, resourceMap)
		}
	}

	return &ast{
		Resources: formReverseOrderResources(resourceMap),
	}
}

func formReverseOrderResources(resourceMap map[string]orderedAstResource) []*astResource {
	orderedResources := make([]orderedAstResource, 0, len(resourceMap))
	for _, resource := range resourceMap {
		orderedResources = append(orderedResources, resource)
	}
	sort.Slice(orderedResources, func(i, j int) bool {
		return orderedResources[i].Index >= orderedResources[j].Index // reverse order
	})

	result := make([]*astResource, len(orderedResources))
	for i, ordered := range orderedResources {
		res := ordered.Resource
		for j, k := 0, len(res.Operations)-1; j < k; j, k = j+1, k-1 {
			res.Operations[j], res.Operations[k] = res.Operations[k], res.Operations[j]
		}

		result[i] = res
	}

	return result
}

func addOperationsAndUpdateMap(orderedRes orderedAstResource, record eacl.Record, resMap map[string]orderedAstResource) {
	for _, target := range record.Targets() {
		orderedRes.Resource.Operations = addToList(orderedRes.Resource.Operations, record, target)
	}
	resMap[orderedRes.Resource.Name()] = orderedRes
}

func getResourceOrCreate(resMap map[string]orderedAstResource, index int, resInfo resourceInfo) orderedAstResource {
	resource, ok := resMap[resInfo.Name()]
	if !ok {
		resource = orderedAstResource{
			Index:    index,
			Resource: &astResource{resourceInfo: resInfo},
		}
	}
	return resource
}

func resInfoFromFilters(bucketName string, filters []eacl.Filter) resourceInfo {
	resInfo := resourceInfo{Bucket: bucketName}
	for _, filter := range filters {
		if filter.Matcher() == eacl.MatchStringEqual {
			if filter.Key() == object.AttributeFilePath {
				resInfo.Object = filter.Value()
			} else if filter.Key() == eacl.FilterObjectID {
				resInfo.Version = filter.Value()
			}
		}
	}

	return resInfo
}

func mergeAst(parent, child *ast) (*ast, bool) {
	updated := false
	for _, resource := range child.Resources {
		parentResource := getParentResource(parent, resource)
		if parentResource == nil {
			parent.Resources = append(parent.Resources, resource)
			updated = true
			continue
		}

		var newOps []*astOperation
		for _, astOp := range resource.Operations {
			// get parent matched operations
			ops := getAstOps(parentResource, astOp)
			switch len(ops) {
			case 2: // parent contains different actions for the same child operation
				// potential inconsistency
				if groupGrantee := astOp.IsGroupGrantee(); groupGrantee {
					// it is not likely (such state must be detected early)
					// inconsistency
					action := eacl.ActionAllow
					if astOp.Action == eacl.ActionAllow {
						action = eacl.ActionDeny
					}
					removeAstOp(parentResource, groupGrantee, astOp.Op, action)
					updated = true
					continue
				}

				opToAdd, opToDelete := ops[0], ops[1]
				if ops[1].Action == astOp.Action {
					opToAdd, opToDelete = ops[1], ops[0]
				}

				if handleAddOperations(parentResource, astOp, opToAdd) {
					updated = true
				}
				if handleRemoveOperations(parentResource, astOp, opToDelete) {
					updated = true
				}
			case 1: // parent contains some action for the same child operation
				if astOp.Action != ops[0].Action {
					// potential inconsistency
					if groupGrantee := astOp.IsGroupGrantee(); groupGrantee {
						// inconsistency
						ops[0].Action = astOp.Action
						updated = true
						continue
					}

					if handleRemoveOperations(parentResource, astOp, ops[0]) {
						updated = true
					}
					parentResource.Operations = append(parentResource.Operations, astOp)
					continue
				}

				if handleAddOperations(parentResource, astOp, ops[0]) {
					updated = true
				}
			case 0: // parent doesn't contain actions for the same child operation
				newOps = append(newOps, astOp)
				updated = true
			}
		}

		if newOps != nil {
			parentResource.Operations = append(newOps, parentResource.Operations...)
		}
	}

	return parent, updated
}

func handleAddOperations(parentResource *astResource, astOp, existedOp *astOperation) bool {
	var needToAdd []string
	for _, user := range astOp.Users {
		if !containsStr(existedOp.Users, user) {
			needToAdd = append(needToAdd, user)
		}
	}
	if len(needToAdd) != 0 {
		addUsers(parentResource, existedOp, needToAdd)
		return true
	}
	return false
}

func handleRemoveOperations(parentResource *astResource, astOp, existedOp *astOperation) bool {
	var needToRemove []string
	for _, user := range astOp.Users {
		if containsStr(existedOp.Users, user) {
			needToRemove = append(needToRemove, user)
		}
	}
	if len(needToRemove) != 0 {
		removeUsers(parentResource, existedOp, needToRemove)
		return true
	}

	return false
}

func containsStr(list []string, element string) bool {
	for _, str := range list {
		if str == element {
			return true
		}
	}
	return false
}

func getAstOps(resource *astResource, childOp *astOperation) []*astOperation {
	var res []*astOperation
	for _, astOp := range resource.Operations {
		if astOp.IsGroupGrantee() == childOp.IsGroupGrantee() && astOp.Op == childOp.Op {
			res = append(res, astOp)
		}
	}
	return res
}

func removeAstOp(resource *astResource, group bool, op eacl.Operation, action eacl.Action) {
	for i, astOp := range resource.Operations {
		if astOp.IsGroupGrantee() == group && astOp.Op == op && astOp.Action == action {
			resource.Operations = append(resource.Operations[:i], resource.Operations[i+1:]...)
			return
		}
	}
}

func addUsers(resource *astResource, astO *astOperation, users []string) {
	for _, astOp := range resource.Operations {
		if astOp.IsGroupGrantee() == astO.IsGroupGrantee() && astOp.Op == astO.Op && astOp.Action == astO.Action {
			astOp.Users = append(astO.Users, users...)
			return
		}
	}
}

func removeUsers(resource *astResource, astOperation *astOperation, users []string) {
	for ind, astOp := range resource.Operations {
		if !astOp.IsGroupGrantee() && astOp.Op == astOperation.Op && astOp.Action == astOperation.Action {
			filteredUsers := astOp.Users[:0] // new slice without allocation
			for _, user := range astOp.Users {
				if !containsStr(users, user) {
					filteredUsers = append(filteredUsers, user)
				}
			}
			if len(filteredUsers) == 0 { // remove ast resource
				resource.Operations = append(resource.Operations[:ind], resource.Operations[ind+1:]...)
			} else {
				astOp.Users = filteredUsers
			}
			return
		}
	}
}

func getParentResource(parent *ast, resource *astResource) *astResource {
	for _, parentResource := range parent.Resources {
		if resource.Bucket == parentResource.Bucket && resource.Object == parentResource.Object &&
			resource.Version == parentResource.Version {
			return parentResource
		}
	}
	return nil
}

func astToTable(ast *ast) (*eacl.Table, error) {
	table := eacl.NewTable()

	for i := len(ast.Resources) - 1; i >= 0; i-- {
		records, err := formRecords(ast.Resources[i])
		if err != nil {
			return nil, fmt.Errorf("form records: %w", err)
		}

		for _, rec := range records {
			table.AddRecord(rec)
		}
	}

	return table, nil
}

func tryServiceRecord(record eacl.Record) *ServiceRecord {
	if record.Action() != eacl.ActionAllow || record.Operation() != eacl.OperationGet ||
		len(record.Targets()) != 1 || len(record.Filters()) != 2 {
		return nil
	}

	target := record.Targets()[0]
	if target.Role() != eacl.RoleSystem {
		return nil
	}

	resourceFilter := record.Filters()[0]
	recordsFilter := record.Filters()[1]
	if resourceFilter.From() != eacl.HeaderFromService || recordsFilter.From() != eacl.HeaderFromService ||
		resourceFilter.Matcher() != eacl.MatchUnknown || recordsFilter.Matcher() != eacl.MatchUnknown ||
		resourceFilter.Key() != serviceRecordResourceKey || recordsFilter.Key() != serviceRecordGroupLengthKey {
		return nil
	}

	groupLength, err := strconv.Atoi(recordsFilter.Value())
	if err != nil {
		return nil
	}

	return &ServiceRecord{
		Resource:           resourceFilter.Value(),
		GroupRecordsLength: groupLength,
	}
}

func formRecords(resource *astResource) ([]*eacl.Record, error) {
	var res []*eacl.Record

	for i := len(resource.Operations) - 1; i >= 0; i-- {
		astOp := resource.Operations[i]
		record := eacl.NewRecord()
		record.SetOperation(astOp.Op)
		record.SetAction(astOp.Action)
		if astOp.IsGroupGrantee() {
			eacl.AddFormedTarget(record, eacl.RoleOthers)
		} else {
			targetKeys := make([]ecdsa.PublicKey, 0, len(astOp.Users))
			for _, user := range astOp.Users {
				pk, err := keys.NewPublicKeyFromString(user)
				if err != nil {
					return nil, errInvalidPublicKey
				}
				targetKeys = append(targetKeys, (ecdsa.PublicKey)(*pk))
			}
			// Unknown role is used, because it is ignored when keys are set
			eacl.AddFormedTarget(record, eacl.RoleUnknown, targetKeys...)
		}
		if len(resource.Object) != 0 {
			record.AddObjectAttributeFilter(eacl.MatchStringEqual, object.AttributeFilePath, resource.Object)
		}

		if len(resource.Version) != 0 {
			var id oid.ID
			if err := id.DecodeString(resource.Version); err != nil {
				return nil, fmt.Errorf("parse object version (oid): %w", err)
			}
			record.AddObjectIDFilter(eacl.MatchStringEqual, id)
		}
		res = append(res, record)
	}

	return res, nil
}

func addToList(operations []*astOperation, rec eacl.Record, target eacl.Target) []*astOperation {
	var (
		found       *astOperation
		groupTarget = target.Role() == eacl.RoleOthers
	)

	for _, astOp := range operations {
		if astOp.Op == rec.Operation() && astOp.IsGroupGrantee() == groupTarget {
			found = astOp
		}
	}

	if found != nil {
		if !groupTarget {
			for _, key := range target.BinaryKeys() {
				pubKey := hex.EncodeToString(key)
				var exist bool

				for _, userPubKey := range found.Users {
					if userPubKey == pubKey {
						exist = true
						break
					}
				}

				if !exist {
					found.Users = append(found.Users, pubKey)
				}
			}
		}
	} else {
		astOperation := &astOperation{
			Op:     rec.Operation(),
			Action: rec.Action(),
		}
		if !groupTarget {
			for _, key := range target.BinaryKeys() {
				astOperation.Users = append(astOperation.Users, hex.EncodeToString(key))
			}
		}

		operations = append(operations, astOperation)
	}

	return operations
}

func policyToAst(bktPolicy *bucketPolicy) (*ast, error) {
	res := &ast{}

	rr := make(map[string]*astResource)

	for _, state := range bktPolicy.Statement {
		if state.Principal.AWS != "" && state.Principal.AWS != allUsersWildcard ||
			state.Principal.AWS == "" && state.Principal.CanonicalUser == "" {
			return nil, fmt.Errorf("unsupported principal: %v", state.Principal)
		}
		var groupGrantee bool
		if state.Principal.AWS == allUsersWildcard {
			groupGrantee = true
		}

		for _, resource := range state.Resource {
			trimmedResource := strings.TrimPrefix(resource, arnAwsPrefix)
			r, ok := rr[trimmedResource]
			if !ok {
				if !strings.HasPrefix(trimmedResource, bktPolicy.Bucket) {
					return nil, fmt.Errorf("resource '%s' must be in the same bucket '%s'", trimmedResource, bktPolicy.Bucket)
				}

				r = &astResource{
					resourceInfo: resourceInfoFromName(trimmedResource, bktPolicy.Bucket),
				}
			}
			for _, action := range state.Action {
				for _, op := range actionToOpMap[action] {
					toAction := effectToAction(state.Effect)
					r.Operations = addTo(r.Operations, state.Principal.CanonicalUser, op, groupGrantee, toAction)
				}
			}

			rr[trimmedResource] = r
		}
	}

	for _, val := range rr {
		res.Resources = append(res.Resources, val)
	}

	return res, nil
}

func resourceInfoFromName(name, bucketName string) resourceInfo {
	resInfo := resourceInfo{Bucket: bucketName}
	if name != bucketName {
		versionedObject := strings.TrimPrefix(name, bucketName+"/")
		objVersion := strings.Split(versionedObject, ":")
		if len(objVersion) <= 2 {
			resInfo.Object = objVersion[0]
			if len(objVersion) == 2 {
				resInfo.Version = objVersion[1]
			}
		} else {
			resInfo.Object = strings.Join(objVersion[:len(objVersion)-1], ":")
			resInfo.Version = objVersion[len(objVersion)-1]
		}
	}

	return resInfo
}

func astToPolicy(ast *ast) *bucketPolicy {
	bktPolicy := &bucketPolicy{}

	for _, resource := range ast.Resources {
		allowed, denied := triageOperations(resource.Operations)
		handleResourceOperations(bktPolicy, allowed, eacl.ActionAllow, resource.Name())
		handleResourceOperations(bktPolicy, denied, eacl.ActionDeny, resource.Name())
	}

	return bktPolicy
}

func handleResourceOperations(bktPolicy *bucketPolicy, list []*astOperation, eaclAction eacl.Action, resourceName string) {
	userOpsMap := make(map[string][]eacl.Operation)

	for _, op := range list {
		if !op.IsGroupGrantee() {
			for _, user := range op.Users {
				userOps := userOpsMap[user]
				userOps = append(userOps, op.Op)
				userOpsMap[user] = userOps
			}
		} else {
			userOps := userOpsMap[allUsersGroup]
			userOps = append(userOps, op.Op)
			userOpsMap[allUsersGroup] = userOps
		}
	}

	for user, userOps := range userOpsMap {
		var actions []string
	LOOP:
		for action, ops := range actionToOpMap {
			for _, op := range ops {
				if !contains(userOps, op) {
					continue LOOP
				}
			}
			actions = append(actions, action)
		}
		if len(actions) != 0 {
			state := statement{
				Effect:    actionToEffect(eaclAction),
				Principal: principal{CanonicalUser: user},
				Action:    actions,
				Resource:  []string{arnAwsPrefix + resourceName},
			}
			if user == allUsersGroup {
				state.Principal = principal{AWS: allUsersWildcard}
			}
			bktPolicy.Statement = append(bktPolicy.Statement, state)
		}
	}
}

func triageOperations(operations []*astOperation) ([]*astOperation, []*astOperation) {
	var allowed, denied []*astOperation
	for _, op := range operations {
		if op.Action == eacl.ActionAllow {
			allowed = append(allowed, op)
		} else {
			denied = append(denied, op)
		}
	}
	return allowed, denied
}

func addTo(list []*astOperation, userID string, op eacl.Operation, groupGrantee bool, action eacl.Action) []*astOperation {
	var found *astOperation
	for _, astop := range list {
		if astop.Op == op && astop.IsGroupGrantee() == groupGrantee {
			found = astop
		}
	}

	if found != nil {
		if !groupGrantee {
			found.Users = append(found.Users, userID)
		}
	} else {
		astoperation := &astOperation{
			Op:     op,
			Action: action,
		}
		if !groupGrantee {
			astoperation.Users = append(astoperation.Users, userID)
		}

		list = append(list, astoperation)
	}

	return list
}

func aclToAst(acl *AccessControlPolicy, resInfo *resourceInfo) (*ast, error) {
	res := &ast{}

	resource := &astResource{resourceInfo: *resInfo}

	ops := append(readOps, writeOps...)

	// Expect to have at least 1 full control grant for owner which is set in
	// parseACLHeaders(). If there is no other grants, then user sets private
	// canned ACL, which is processed in this branch.
	if len(acl.AccessControlList) < 2 {
		for _, op := range ops {
			operation := &astOperation{
				Op:     op,
				Action: eacl.ActionDeny,
			}
			resource.Operations = append(resource.Operations, operation)
		}
	}

	for _, op := range ops {
		operation := &astOperation{
			Users:  []string{acl.Owner.ID},
			Op:     op,
			Action: eacl.ActionAllow,
		}
		resource.Operations = append(resource.Operations, operation)
	}

	for _, grant := range acl.AccessControlList {
		if grant.Grantee.Type == granteeAmazonCustomerByEmail || (grant.Grantee.Type == granteeGroup && grant.Grantee.URI != allUsersGroup) {
			return nil, s3errors.GetAPIError(s3errors.ErrNotSupported)
		}

		var groupGrantee bool
		if grant.Grantee.Type == granteeGroup {
			groupGrantee = true
		} else if grant.Grantee.ID == acl.Owner.ID {
			continue
		}

		for _, action := range getActions(grant.Permission, resInfo.IsBucket()) {
			for _, op := range actionToOpMap[action] {
				resource.Operations = addTo(resource.Operations, grant.Grantee.ID, op, groupGrantee, eacl.ActionAllow)
			}
		}
	}

	res.Resources = []*astResource{resource}
	return res, nil
}

func aclToPolicy(acl *AccessControlPolicy, resInfo *resourceInfo) (*bucketPolicy, error) {
	if resInfo.Bucket == "" {
		return nil, fmt.Errorf("resource bucket must not be empty")
	}

	results := []statement{
		getAllowStatement(resInfo, acl.Owner.ID, awsPermFullControl),
	}

	// Expect to have at least 1 full control grant for owner which is set in
	// parseACLHeaders(). If there is no other grants, then user sets private
	// canned ACL, which is processed in this branch.
	if len(acl.AccessControlList) < 2 {
		results = append([]statement{getDenyStatement(resInfo, allUsersWildcard, awsPermFullControl)}, results...)
	}

	for _, grant := range acl.AccessControlList {
		if grant.Grantee.Type == granteeAmazonCustomerByEmail || (grant.Grantee.Type == granteeGroup && grant.Grantee.URI != allUsersGroup) {
			return nil, s3errors.GetAPIError(s3errors.ErrNotSupported)
		}

		user := grant.Grantee.ID
		if grant.Grantee.Type == granteeGroup {
			user = allUsersWildcard
		} else if user == acl.Owner.ID {
			continue
		}
		results = append(results, getAllowStatement(resInfo, user, grant.Permission))
	}

	return &bucketPolicy{
		Statement: results,
		Bucket:    resInfo.Bucket,
	}, nil
}

func getAllowStatement(resInfo *resourceInfo, id string, permission amazonS3Permission) statement {
	state := statement{
		Effect: "Allow",
		Principal: principal{
			CanonicalUser: id,
		},
		Action:   getActions(permission, resInfo.IsBucket()),
		Resource: []string{arnAwsPrefix + resInfo.Name()},
	}

	if id == allUsersWildcard {
		state.Principal = principal{AWS: allUsersWildcard}
	}

	return state
}

func getDenyStatement(resInfo *resourceInfo, id string, permission amazonS3Permission) statement {
	state := statement{
		Effect: "Deny",
		Principal: principal{
			CanonicalUser: id,
		},
		Action:   getActions(permission, resInfo.IsBucket()),
		Resource: []string{arnAwsPrefix + resInfo.Name()},
	}

	if id == allUsersWildcard {
		state.Principal = principal{AWS: allUsersWildcard}
	}

	return state
}

func getActions(permission amazonS3Permission, isBucket bool) []string {
	var res []string
	switch permission {
	case awsPermRead:
		if isBucket {
			res = []string{s3ListBucket, s3ListBucketVersions, s3ListBucketMultipartUploads}
		} else {
			res = []string{s3GetObject, s3GetObjectVersion}
		}
	case awsPermWrite:
		if isBucket {
			res = []string{s3PutObject, s3DeleteObject}
		}
	case awsPermFullControl:
		if isBucket {
			res = []string{s3ListBucket, s3ListBucketVersions, s3ListBucketMultipartUploads, s3PutObject, s3DeleteObject}
		} else {
			res = []string{s3GetObject, s3GetObjectVersion, s3PutObject, s3DeleteObject}
		}
	}

	return res
}

func effectToAction(effect string) eacl.Action {
	switch effect {
	case "Allow":
		return eacl.ActionAllow
	case "Deny":
		return eacl.ActionDeny
	}
	return eacl.ActionUnknown
}

func actionToEffect(action eacl.Action) string {
	switch action {
	case eacl.ActionAllow:
		return "Allow"
	case eacl.ActionDeny:
		return "Deny"
	default:
		return ""
	}
}

func permissionToOperations(permission amazonS3Permission) []eacl.Operation {
	switch permission {
	case awsPermFullControl:
		return fullOps
	case awsPermRead:
		return readOps
	case awsPermWrite:
		return writeOps
	}
	return nil
}

func encodeObjectACL(log *zap.Logger, bucketACL *layer.BucketACL, bucketName, objectVersion string) *AccessControlPolicy {
	ownerGrantee := NewGrantee(granteeCanonicalUser)
	ownerGrantee.ID = bucketACL.Info.PubKeyHex()
	ownerGrantee.DisplayName = bucketACL.Info.Owner.String()

	res := &AccessControlPolicy{
		Owner: Owner{
			ID:          bucketACL.Info.PubKeyHex(),
			DisplayName: bucketACL.Info.Owner.String(),
		},
		AccessControlList: []*Grant{
			{
				Grantee:    ownerGrantee,
				Permission: awsPermFullControl,
			},
		},
	}

	m := make(map[string][]eacl.Operation)

	astList := tableToAst(bucketACL.EACL, bucketName)

	for _, resource := range astList.Resources {
		if resource.Version != objectVersion {
			continue
		}

		for _, op := range resource.Operations {
			if op.Action != eacl.ActionAllow {
				continue
			}

			if len(op.Users) == 0 {
				list := append(m[allUsersGroup], op.Op)
				m[allUsersGroup] = list
			} else {
				for _, user := range op.Users {
					list := append(m[user], op.Op)
					m[user] = list
				}
			}
		}
	}

	for key, val := range m {
		if key == ownerGrantee.ID {
			// owner already processed.
			continue
		}

		var readOpAmount int
		var writeOpAmount int

		for _, op := range val {
			// valid operation.
			if op < eacl.OperationGet || op > eacl.OperationRangeHash {
				log.Warn("invalid eACL op", zap.Int("op", int(op)), zap.String("CID", bucketACL.Info.CID.String()))
				continue
			}

			_, ok := readOpsMap[op]
			if ok {
				readOpAmount++
			}

			_, ok = writeOpsMap[op]
			if ok {
				writeOpAmount++
			}
		}

		// all required set of operations was presented.
		isRead := readOpAmount == len(readOpsMap)
		isWrite := writeOpAmount == len(writeOpsMap)

		if isRead {
			grant := generateGrant(key, bucketACL, awsPermRead)
			res.AccessControlList = append(res.AccessControlList, grant)
		}

		if isWrite {
			grant := generateGrant(key, bucketACL, awsPermWrite)
			res.AccessControlList = append(res.AccessControlList, grant)
		}
	}

	return res
}

func generateGrant(key string, bucketACL *layer.BucketACL, permission amazonS3Permission) *Grant {
	var grantee *Grantee
	if key == allUsersGroup {
		grantee = NewGrantee(granteeGroup)
		grantee.URI = allUsersGroup
	} else {
		grantee = NewGrantee(granteeCanonicalUser)
		grantee.ID = key
		grantee.DisplayName = bucketACL.Info.Owner.String()
	}

	return &Grant{
		Grantee:    grantee,
		Permission: permission,
	}
}

func (h *handler) encodeBucketACL(bucketName string, bucketACL *layer.BucketACL) *AccessControlPolicy {
	return encodeObjectACL(h.log, bucketACL, bucketName, "")
}

func contains(list []eacl.Operation, op eacl.Operation) bool {
	for _, operation := range list {
		if operation == op {
			return true
		}
	}
	return false
}

func bucketACLToTable(acp *AccessControlPolicy) (*eacl.Table, error) {
	var found bool
	table := eacl.NewTable()

	ownerKey, err := keys.NewPublicKeyFromString(acp.Owner.ID)
	if err != nil {
		return nil, fmt.Errorf("public key from string: %w", err)
	}

	for _, grant := range acp.AccessControlList {
		if !isValidGrant(grant) {
			return nil, errors.New("unsupported grantee")
		}
		if grant.Grantee.ID == acp.Owner.ID {
			found = true
		}

		var recordFromOp func(eacl.Operation) *eacl.Record

		switch grant.Grantee.Type {
		default:
			return nil, fmt.Errorf("unknown grantee type: %s", grant.Grantee.Type)
		case granteeCanonicalUser:
			key, err := keys.NewPublicKeyFromString(grant.Grantee.ID)
			if err != nil {
				return nil, fmt.Errorf("grantee ID to public key (%s): %w", grant.Grantee.ID, err)
			}

			recordFromOp = func(op eacl.Operation) *eacl.Record { return getAllowRecord(op, key) }
		case granteeGroup:
			recordFromOp = func(op eacl.Operation) *eacl.Record { return getOthersRecord(op, eacl.ActionAllow) }
		}

		for _, op := range permissionToOperations(grant.Permission) {
			table.AddRecord(recordFromOp(op))
		}
	}

	if !found {
		for _, op := range fullOps {
			table.AddRecord(getAllowRecord(op, ownerKey))
		}
	}

	for _, op := range fullOps {
		table.AddRecord(getOthersRecord(op, eacl.ActionDeny))
	}

	return table, nil
}

func isValidGrant(grant *Grant) bool {
	return (grant.Permission == awsPermFullControl || grant.Permission == awsPermRead || grant.Permission == awsPermWrite) &&
		(grant.Grantee.Type == granteeCanonicalUser || (grant.Grantee.Type == granteeGroup && grant.Grantee.URI == allUsersGroup))
}

func getAllowRecord(op eacl.Operation, pk *keys.PublicKey) *eacl.Record {
	record := eacl.NewRecord()
	record.SetOperation(op)
	record.SetAction(eacl.ActionAllow)
	// Unknown role is used, because it is ignored when keys are set
	eacl.AddFormedTarget(record, eacl.RoleUnknown, (ecdsa.PublicKey)(*pk))
	return record
}

func getOthersRecord(op eacl.Operation, action eacl.Action) *eacl.Record {
	record := eacl.NewRecord()
	record.SetOperation(op)
	record.SetAction(action)
	eacl.AddFormedTarget(record, eacl.RoleOthers)
	return record
}
