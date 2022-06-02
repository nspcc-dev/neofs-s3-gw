package handler

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	v2acl "github.com/nspcc-dev/neofs-api-go/v2/acl"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/session"
)

var (
	writeOps = []eacl.Operation{eacl.OperationPut, eacl.OperationDelete}
	readOps  = []eacl.Operation{eacl.OperationGet, eacl.OperationHead,
		eacl.OperationSearch, eacl.OperationRange, eacl.OperationRangeHash}
	fullOps = []eacl.Operation{eacl.OperationGet, eacl.OperationHead, eacl.OperationPut,
		eacl.OperationDelete, eacl.OperationSearch, eacl.OperationRange, eacl.OperationRangeHash}
)

var actionToOpMap = map[string][]eacl.Operation{
	s3DeleteObject: {eacl.OperationDelete},
	s3GetObject:    readOps,
	s3PutObject:    {eacl.OperationPut},
	s3ListBucket:   readOps,
}

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

// AWSACL is aws permission constants.
type AWSACL string

const (
	aclFullControl AWSACL = "FULL_CONTROL"
	aclWrite       AWSACL = "WRITE"
	aclRead        AWSACL = "READ"
)

// GranteeType is aws grantee permission type constants.
type GranteeType string

const (
	acpCanonicalUser         GranteeType = "CanonicalUser"
	acpAmazonCustomerByEmail GranteeType = "AmazonCustomerByEmail"
	acpGroup                 GranteeType = "Group"
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
	Role   eacl.Role
	Op     eacl.Operation
	Action eacl.Action
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

	if err = api.EncodeToResponse(w, h.encodeBucketACL(bucketACL)); err != nil {
		h.logAndSendError(w, "something went wrong", reqInfo, err)
		return
	}
}

func (h *handler) bearerTokenIssuerKey(ctx context.Context) (*keys.PublicKey, error) {
	box, err := layer.GetBoxData(ctx)
	if err != nil {
		return nil, err
	}

	var btoken v2acl.BearerToken
	box.Gate.BearerToken.WriteToV2(&btoken)

	key, err := keys.NewPublicKeyFromBytes(btoken.GetSignature().GetKey(), elliptic.P256())
	if err != nil {
		return nil, err
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
	} else if err := xml.NewDecoder(r.Body).Decode(list); err != nil {
		h.logAndSendError(w, "could not parse bucket acl", reqInfo, errors.GetAPIError(errors.ErrMalformedXML))
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

	if err = h.updateBucketACL(r, astBucket, bktInfo, token); err != nil {
		h.logAndSendError(w, "could not update bucket acl", reqInfo, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *handler) updateBucketACL(r *http.Request, astChild *ast, bktInfo *data.BucketInfo, sessionToken *session.Container) error {
	bucketACL, err := h.obj.GetBucketACL(r.Context(), bktInfo)
	if err != nil {
		return fmt.Errorf("could not get bucket eacl: %w", err)
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
		return nil
	}

	table, err := astToTable(resAst)
	if err != nil {
		return fmt.Errorf("could not translate ast to table: %w", err)
	}

	table.SetSessionToken(sessionToken)

	p := &layer.PutBucketACLParams{
		BktInfo: bktInfo,
		EACL:    table,
	}

	if err = h.obj.PutBucketACL(r.Context(), p); err != nil {
		return fmt.Errorf("could not put bucket acl: %w", err)
	}

	return nil
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

	if err = api.EncodeToResponse(w, h.encodeObjectACL(bucketACL, reqInfo.ObjectName)); err != nil {
		h.logAndSendError(w, "something went wrong", reqInfo, err)
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

	list := &AccessControlPolicy{}
	if r.ContentLength == 0 {
		list, err = parseACLHeaders(r.Header, key)
		if err != nil {
			h.logAndSendError(w, "could not parse bucket acl", reqInfo, err)
			return
		}
	} else if err := xml.NewDecoder(r.Body).Decode(list); err != nil {
		h.logAndSendError(w, "could not parse bucket acl", reqInfo, errors.GetAPIError(errors.ErrMalformedXML))
		return
	}

	resInfo := &resourceInfo{
		Bucket:  reqInfo.BucketName,
		Object:  reqInfo.ObjectName,
		Version: versionID,
	}

	astObject, err := aclToAst(list, resInfo)
	if err != nil {
		h.logAndSendError(w, "could not translate acl to ast", reqInfo, err)
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

	if _, err = h.obj.GetObjectInfo(r.Context(), p); err != nil {
		h.logAndSendError(w, "could not get object info", reqInfo, err)
		return
	}

	if err = h.updateBucketACL(r, astObject, bktInfo, token); err != nil {
		h.logAndSendError(w, "could not update bucket acl", reqInfo, err)
		return
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
		return errors.GetAPIError(errors.ErrAccessDenied)
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
	if err := json.NewDecoder(r.Body).Decode(bktPolicy); err != nil {
		h.logAndSendError(w, "could not parse bucket policy", reqInfo, err)
		return
	}

	astPolicy, err := policyToAst(bktPolicy)
	if err != nil {
		h.logAndSendError(w, "could not translate policy to ast", reqInfo, err)
		return
	}

	if err = h.updateBucketACL(r, astPolicy, bktInfo, token); err != nil {
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
			Type:        acpCanonicalUser,
		},
		Permission: aclFullControl,
	}}

	cannedACL := header.Get(api.AmzACL)
	if cannedACL != "" {
		return addPredefinedACP(acp, cannedACL)
	}

	if acp.AccessControlList, err = addGrantees(acp.AccessControlList, header, api.AmzGrantFullControl); err != nil {
		return nil, err
	}
	if acp.AccessControlList, err = addGrantees(acp.AccessControlList, header, api.AmzGrantRead); err != nil {
		return nil, err
	}
	if acp.AccessControlList, err = addGrantees(acp.AccessControlList, header, api.AmzGrantWrite); err != nil {
		return nil, err
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
		return nil, err
	}

	grantees, err := parseGrantee(grant)
	if err != nil {
		return nil, err
	}

	for _, grantee := range grantees {
		if grantee.Type == acpAmazonCustomerByEmail || (grantee.Type == acpGroup && grantee.URI != allUsersGroup) {
			return nil, fmt.Errorf("unsupported grantee: %v", grantee)
		}

		list = append(list, &Grant{
			Grantee:    grantee,
			Permission: permission,
		})
	}
	return list, nil
}

func grantHdrToPermission(grant string) (AWSACL, error) {
	switch grant {
	case api.AmzGrantFullControl:
		return aclFullControl, nil
	case api.AmzGrantRead:
		return aclRead, nil
	case api.AmzGrantWrite:
		return aclWrite, nil
	}
	return "", fmt.Errorf("unsuppoted header: %s", grant)
}

func parseGrantee(grantees string) ([]*Grantee, error) {
	var result []*Grantee

	split := strings.Split(grantees, ", ")
	for _, pair := range split {
		split2 := strings.Split(pair, "=")
		if len(split2) != 2 {
			return nil, errors.GetAPIError(errors.ErrInvalidArgument)
		}

		grantee, err := formGrantee(split2[0], split2[1])
		if err != nil {
			return nil, err
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
			Type: acpCanonicalUser,
		}, nil
	case "uri":
		return &Grantee{
			URI:  value,
			Type: acpGroup,
		}, nil
	case "emailAddress":
		return &Grantee{
			EmailAddress: value,
			Type:         acpAmazonCustomerByEmail,
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
				Type: acpGroup,
			},
			Permission: aclFullControl,
		})
	case cannedACLAuthRead:
		fallthrough
	case basicACLReadOnly:
		acp.AccessControlList = append(acp.AccessControlList, &Grant{
			Grantee: &Grantee{
				URI:  allUsersGroup,
				Type: acpGroup,
			},
			Permission: aclRead,
		})
	default:
		return nil, errors.GetAPIError(errors.ErrInvalidArgument)
	}

	return acp, nil
}

func tableToAst(table *eacl.Table, bktName string) *ast {
	res := &ast{}
	rr := make(map[string]*astResource)

	for _, record := range table.Records() {
		resName := bktName
		var objectName string
		var version string
		for _, filter := range record.Filters() {
			if filter.Matcher() == eacl.MatchStringEqual {
				if filter.Key() == object.AttributeFileName {
					objectName = filter.Value()
					resName += "/" + objectName
				} else if filter.Key() == v2acl.FilterObjectID {
					version = filter.Value()
					resName += "/" + version
				}
			}
		}
		r, ok := rr[resName]
		if !ok {
			r = &astResource{resourceInfo: resourceInfo{
				Bucket:  bktName,
				Object:  objectName,
				Version: version,
			}}
		}
		for _, target := range record.Targets() {
			r.Operations = addToList(r.Operations, record, target)
		}
		rr[resName] = r
	}

	for _, val := range rr {
		res.Resources = append(res.Resources, val)
	}

	return res
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
			ops := getAstOps(parentResource, astOp)
			switch len(ops) {
			case 2:
				// potential inconsistency
				if astOp.Role == eacl.RoleOthers {
					// it is not likely (such state must be detected early)
					// inconsistency
					action := eacl.ActionAllow
					if astOp.Action == eacl.ActionAllow {
						action = eacl.ActionDeny
					}
					removeAstOp(parentResource, astOp.Role, astOp.Op, action)
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
				if opToDelete.Role == eacl.RoleUser && len(opToDelete.Users) == 0 {
					removeAstOp(parentResource, opToDelete.Role, opToDelete.Op, opToDelete.Action)
				}
			case 1:
				if astOp.Action != ops[0].Action {
					// potential inconsistency
					if astOp.Role == eacl.RoleOthers {
						// inconsistency
						removeAstOp(parentResource, astOp.Role, astOp.Op, ops[0].Action)
						parentResource.Operations = append(parentResource.Operations, astOp)
						updated = true
						continue
					}

					if handleRemoveOperations(parentResource, astOp, ops[0]) {
						updated = true
					}
					if ops[0].Role == eacl.RoleUser && len(ops[0].Users) == 0 {
						removeAstOp(parentResource, ops[0].Role, ops[0].Op, ops[0].Action)
					}
					parentResource.Operations = append(parentResource.Operations, astOp)
					continue
				}

				if handleAddOperations(parentResource, astOp, ops[0]) {
					updated = true
				}
			case 0:
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
		if astOp.Role == childOp.Role && astOp.Op == childOp.Op {
			res = append(res, astOp)
		}
	}
	return res
}

func removeAstOp(resource *astResource, role eacl.Role, op eacl.Operation, action eacl.Action) {
	for i, astOp := range resource.Operations {
		if astOp.Role == role && astOp.Op == op && astOp.Action == action {
			resource.Operations = append(resource.Operations[:i], resource.Operations[i+1:]...)
			return
		}
	}
}

func addUsers(resource *astResource, astO *astOperation, users []string) {
	for _, astOp := range resource.Operations {
		if astOp.Role == astO.Role && astOp.Op == astO.Op && astOp.Action == astO.Action {
			astOp.Users = append(astO.Users, users...)
			return
		}
	}
}

func removeUsers(resource *astResource, astOperation *astOperation, users []string) {
	for _, astOp := range resource.Operations {
		if astOp.Role == astOperation.Role && astOp.Op == astOperation.Op && astOp.Action == astOperation.Action {
			ind := 0
			for _, user := range astOp.Users {
				if containsStr(users, user) {
					astOp.Users = append(astOp.Users[:ind], astOp.Users[ind+1:]...)
				} else {
					ind++
				}
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

	for _, resource := range ast.Resources {
		records, err := formRecords(resource.Operations, resource)
		if err != nil {
			return nil, err
		}
		for _, rec := range records {
			table.AddRecord(rec)
		}
	}

	return table, nil
}

func formRecords(operations []*astOperation, resource *astResource) ([]*eacl.Record, error) {
	var res []*eacl.Record

	for _, astOp := range operations {
		record := eacl.NewRecord()
		record.SetOperation(astOp.Op)
		record.SetAction(astOp.Action)
		if astOp.Role == eacl.RoleOthers {
			eacl.AddFormedTarget(record, eacl.RoleOthers)
		} else {
			for _, user := range astOp.Users {
				pk, err := keys.NewPublicKeyFromString(user)
				if err != nil {
					return nil, err
				}
				eacl.AddFormedTarget(record, eacl.RoleUser, (ecdsa.PublicKey)(*pk))
			}
		}
		if len(resource.Object) != 0 {
			if len(resource.Version) != 0 {
				var id oid.ID
				if err := id.DecodeString(resource.Version); err != nil {
					return nil, err
				}
				record.AddObjectIDFilter(eacl.MatchStringEqual, id)
			}
			record.AddObjectAttributeFilter(eacl.MatchStringEqual, object.AttributeFileName, resource.Object)
		}
		res = append(res, record)
	}

	return res, nil
}

func addToList(operations []*astOperation, rec eacl.Record, target eacl.Target) []*astOperation {
	var found *astOperation
	for _, astOp := range operations {
		if astOp.Op == rec.Operation() && astOp.Role == target.Role() {
			found = astOp
		}
	}

	if found != nil {
		if target.Role() == eacl.RoleUser {
			for _, key := range target.BinaryKeys() {
				found.Users = append(found.Users, hex.EncodeToString(key))
			}
		}
	} else {
		astOperation := &astOperation{
			Role:   target.Role(),
			Op:     rec.Operation(),
			Action: rec.Action(),
		}
		if target.Role() == eacl.RoleUser {
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
		role := eacl.RoleUser
		if state.Principal.AWS == allUsersWildcard {
			role = eacl.RoleOthers
		}

		for _, resource := range state.Resource {
			trimmedResource := strings.TrimPrefix(resource, arnAwsPrefix)
			r, ok := rr[trimmedResource]
			if !ok {
				r = &astResource{resourceInfo: resourceInfo{Bucket: bktPolicy.Bucket}}
				if trimmedResource != bktPolicy.Bucket {
					r.Object = strings.TrimPrefix(trimmedResource, bktPolicy.Bucket+"/")
				}
			}
			for _, action := range state.Action {
				for _, op := range actionToOpMap[action] {
					toAction := effectToAction(state.Effect)
					r.Operations = addTo(r.Operations, state.Principal.CanonicalUser, op, role, toAction)
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

func astToPolicy(ast *ast) *bucketPolicy {
	bktPolicy := &bucketPolicy{}

	for _, resource := range ast.Resources {
		if len(resource.Version) == 0 {
			continue
		}
		allowed, denied := triageOperations(resource.Operations)
		handleResourceOperations(bktPolicy, allowed, eacl.ActionAllow, resource.Name())
		handleResourceOperations(bktPolicy, denied, eacl.ActionDeny, resource.Name())
	}

	return bktPolicy
}

func handleResourceOperations(bktPolicy *bucketPolicy, list []*astOperation, eaclAction eacl.Action, resourceName string) {
	userOpsMap := make(map[string][]eacl.Operation)

	for _, op := range list {
		if op.Role == eacl.RoleUser {
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
					break LOOP
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

func addTo(list []*astOperation, userID string, op eacl.Operation, role eacl.Role, action eacl.Action) []*astOperation {
	var found *astOperation
	for _, astop := range list {
		if astop.Op == op && astop.Role == role {
			found = astop
		}
	}

	if found != nil {
		if role == eacl.RoleUser {
			found.Users = append(found.Users, userID)
		}
	} else {
		astoperation := &astOperation{
			Role:   role,
			Op:     op,
			Action: action,
		}
		if role == eacl.RoleUser {
			astoperation.Users = append(astoperation.Users, userID)
		}

		list = append(list, astoperation)
	}

	return list
}

func aclToAst(acl *AccessControlPolicy, resInfo *resourceInfo) (*ast, error) {
	res := &ast{}

	resource := &astResource{resourceInfo: *resInfo}

	ops := readOps
	if resInfo.IsBucket() {
		ops = append(ops, writeOps...)
	}

	for _, op := range ops {
		operation := &astOperation{
			Users:  []string{acl.Owner.ID},
			Role:   eacl.RoleUser,
			Op:     op,
			Action: eacl.ActionAllow,
		}
		resource.Operations = append(resource.Operations, operation)
	}

	for _, grant := range acl.AccessControlList {
		if grant.Grantee.Type == acpAmazonCustomerByEmail || (grant.Grantee.Type == acpGroup && grant.Grantee.URI != allUsersGroup) {
			return nil, fmt.Errorf("unsupported grantee: %v", grant.Grantee)
		}

		role := eacl.RoleUser
		if grant.Grantee.Type == acpGroup {
			role = eacl.RoleOthers
		} else if grant.Grantee.ID == acl.Owner.ID {
			continue
		}

		for _, action := range getActions(grant.Permission, resInfo.IsBucket()) {
			for _, op := range actionToOpMap[action] {
				resource.Operations = addTo(resource.Operations, grant.Grantee.ID, op, role, eacl.ActionAllow)
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
		getAllowStatement(resInfo, acl.Owner.ID, aclFullControl),
	}

	for _, grant := range acl.AccessControlList {
		if grant.Grantee.Type == acpAmazonCustomerByEmail || (grant.Grantee.Type == acpGroup && grant.Grantee.URI != allUsersGroup) {
			return nil, fmt.Errorf("unsupported grantee: %v", grant.Grantee)
		}

		user := grant.Grantee.ID
		if grant.Grantee.Type == acpGroup {
			user = allUsersWildcard
		} else if user == acl.Owner.ID {
			continue
		}
		results = append(results, getAllowStatement(resInfo, user, grant.Permission))
	}

	return &bucketPolicy{
		Statement: results,
	}, nil
}

func getAllowStatement(resInfo *resourceInfo, id string, permission AWSACL) statement {
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

func getActions(permission AWSACL, isBucket bool) []string {
	var res []string
	switch permission {
	case aclRead:
		if isBucket {
			res = []string{s3ListBucket, s3ListBucketVersions, s3ListBucketMultipartUploads}
		} else {
			res = []string{s3GetObject, s3GetObjectVersion}
		}
	case aclWrite:
		if isBucket {
			res = []string{s3PutObject, s3DeleteObject}
		}
	case aclFullControl:
		if isBucket {
			res = []string{s3ListBucket, s3ListBucketVersions, s3ListBucketMultipartUploads, s3PutObject, s3DeleteObject}
		} else {
			res = []string{s3GetObject, s3GetObjectVersion}
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

func permissionToOperations(permission AWSACL) []eacl.Operation {
	switch permission {
	case aclFullControl:
		return fullOps
	case aclRead:
		return readOps
	case aclWrite:
		return writeOps
	}
	return nil
}

func isWriteOperation(op eacl.Operation) bool {
	return op == eacl.OperationDelete || op == eacl.OperationPut
}

func (h *handler) encodeObjectACL(bucketACL *layer.BucketACL, objectName string) *AccessControlPolicy {
	res := &AccessControlPolicy{
		Owner: Owner{
			ID:          bucketACL.Info.Owner.String(),
			DisplayName: bucketACL.Info.Owner.String(),
		},
	}

	m := make(map[string][]eacl.Operation)

	for _, record := range bucketACL.EACL.Records() {
		if len(record.Targets()) != 1 {
			h.log.Warn("some acl not fully mapped")
			continue
		}

		if objectName != "" {
			var found bool
			for _, filter := range record.Filters() {
				if filter.Matcher() == eacl.MatchStringEqual &&
					filter.Key() == object.AttributeFileName && filter.Key() == objectName {
					found = true
				}
			}
			if !found {
				continue
			}
		}

		target := record.Targets()[0]
		if target.Role() == eacl.RoleOthers {
			if record.Action() == eacl.ActionAllow {
				list := append(m[allUsersGroup], record.Operation())
				m[allUsersGroup] = list
			}
			continue
		}

		for _, key := range target.BinaryKeys() {
			id := hex.EncodeToString(key)
			list := append(m[id], record.Operation())
			m[id] = list
		}
	}

	for key, val := range m {
		permission := aclFullControl
		read, write := true, true
		for op := eacl.OperationGet; op <= eacl.OperationRangeHash; op++ {
			if !contains(val, op) {
				if isWriteOperation(op) {
					write = false
				} else {
					read = false
				}
			}
		}

		if !read && !write {
			h.log.Warn("some acl not fully mapped")
			continue
		}
		if !read {
			permission = aclWrite
		} else if !write {
			permission = aclRead
		}

		var grantee *Grantee
		if key == allUsersGroup {
			grantee = NewGrantee(acpGroup)
			grantee.URI = allUsersGroup
		} else {
			grantee = NewGrantee(acpCanonicalUser)
			grantee.ID = key
		}

		grant := &Grant{
			Grantee:    grantee,
			Permission: permission,
		}
		res.AccessControlList = append(res.AccessControlList, grant)
	}

	return res
}

func (h *handler) encodeBucketACL(bucketACL *layer.BucketACL) *AccessControlPolicy {
	return h.encodeObjectACL(bucketACL, "")
}

func contains(list []eacl.Operation, op eacl.Operation) bool {
	for _, operation := range list {
		if operation == op {
			return true
		}
	}
	return false
}

type getRecordFunc func(op eacl.Operation) *eacl.Record

func bucketACLToTable(acp *AccessControlPolicy, resInfo *resourceInfo) (*eacl.Table, error) {
	if !resInfo.IsBucket() {
		return nil, fmt.Errorf("allowed only bucket acl")
	}

	var found bool
	table := eacl.NewTable()

	ownerKey, err := keys.NewPublicKeyFromString(acp.Owner.ID)
	if err != nil {
		return nil, err
	}

	for _, grant := range acp.AccessControlList {
		if !isValidGrant(grant) {
			return nil, fmt.Errorf("unsupported grantee: %v", grant.Grantee)
		}
		if grant.Grantee.ID == acp.Owner.ID {
			found = true
		}

		getRecord, err := getRecordFunction(grant.Grantee)
		if err != nil {
			return nil, err
		}
		for _, op := range permissionToOperations(grant.Permission) {
			table.AddRecord(getRecord(op))
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

func getRecordFunction(grantee *Grantee) (getRecordFunc, error) {
	switch grantee.Type {
	case acpAmazonCustomerByEmail:
	case acpCanonicalUser:
		pk, err := keys.NewPublicKeyFromString(grantee.ID)
		if err != nil {
			return nil, fmt.Errorf("couldn't parse canonical ID %s: %w", grantee.ID, err)
		}
		return func(op eacl.Operation) *eacl.Record {
			return getAllowRecord(op, pk)
		}, nil
	case acpGroup:
		return func(op eacl.Operation) *eacl.Record {
			return getOthersRecord(op, eacl.ActionAllow)
		}, nil
	}
	return nil, fmt.Errorf("unknown type: %s", grantee.Type)
}

func isValidGrant(grant *Grant) bool {
	return (grant.Permission == aclFullControl || grant.Permission == aclRead || grant.Permission == aclWrite) &&
		(grant.Grantee.Type == acpCanonicalUser || (grant.Grantee.Type == acpGroup && grant.Grantee.URI == allUsersGroup))
}

func getAllowRecord(op eacl.Operation, pk *keys.PublicKey) *eacl.Record {
	record := eacl.NewRecord()
	record.SetOperation(op)
	record.SetAction(eacl.ActionAllow)
	eacl.AddFormedTarget(record, eacl.RoleUser, (ecdsa.PublicKey)(*pk))
	return record
}

func getOthersRecord(op eacl.Operation, action eacl.Action) *eacl.Record {
	record := eacl.NewRecord()
	record.SetOperation(op)
	record.SetAction(action)
	eacl.AddFormedTarget(record, eacl.RoleOthers)
	return record
}
