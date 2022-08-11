package handler

import (
	"context"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	stderrors "errors"
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
	"github.com/nspcc-dev/neofs-sdk-go/session"
	"go.uber.org/zap"
)

var (
	WriteOps = []eacl.Operation{eacl.OperationPut, eacl.OperationDelete}
	ReadOps  = []eacl.Operation{eacl.OperationGet, eacl.OperationHead,
		eacl.OperationSearch, eacl.OperationRange, eacl.OperationRangeHash}
	FullOps = []eacl.Operation{eacl.OperationGet, eacl.OperationHead, eacl.OperationPut,
		eacl.OperationDelete, eacl.OperationSearch, eacl.OperationRange, eacl.OperationRangeHash}
)

var actionToOpMap = map[string][]eacl.Operation{
	s3DeleteObject: {eacl.OperationDelete},
	s3GetObject:    ReadOps,
	s3PutObject:    {eacl.OperationPut},
	s3ListBucket:   ReadOps,
}

const (
	arnAwsPrefix     = "arn:aws:s3:::"
	allUsersWildcard = "*"
	AllUsersGroup    = "http://acs.amazonaws.com/groups/global/AllUsers"

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
	ACLFullControl AWSACL = "FULL_CONTROL"
	ACLWrite       AWSACL = "WRITE"
	ACLRead        AWSACL = "READ"
)

// GranteeType is aws grantee permission type constants.
type GranteeType string

const (
	AcpCanonicalUser         GranteeType = "CanonicalUser"
	AcpAmazonCustomerByEmail GranteeType = "AmazonCustomerByEmail"
	AcpGroup                 GranteeType = "Group"
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

type AstResource struct {
	ResourceInfo
	Operations []*AstOperation
}

type ResourceInfo struct {
	Bucket  string
	Object  string
	Version string
}

func (r *ResourceInfo) Name() string {
	if len(r.Object) == 0 {
		return r.Bucket
	}
	if len(r.Version) == 0 {
		return r.Bucket + "/" + r.Object
	}
	return r.Bucket + "/" + r.Object + ":" + r.Version
}

func (r *ResourceInfo) IsBucket() bool {
	return len(r.Object) == 0
}

type AstOperation struct {
	Users  []string
	Op     eacl.Operation
	Action eacl.Action
}

func (a AstOperation) IsGroupGrantee() bool {
	return len(a.Users) == 0
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

	var btoken v2acl.BearerToken
	box.Gate.BearerToken.WriteToV2(&btoken)

	key, err := keys.NewPublicKeyFromBytes(btoken.GetSignature().GetKey(), elliptic.P256())
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
		h.logAndSendError(w, "could not parse bucket acl", reqInfo, errors.GetAPIError(errors.ErrMalformedXML))
		return
	}

	resInfo := &ResourceInfo{Bucket: reqInfo.BucketName}
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

func (h *handler) updateBucketACL(r *http.Request, astChild *Ast, bktInfo *data.BucketInfo, sessionToken *session.Container) (bool, error) {
	bucketACL, err := h.obj.GetBucketACL(r.Context(), bktInfo)
	if err != nil {
		return false, fmt.Errorf("could not get bucket eacl: %w", err)
	}

	parentAst := h.NeoFS.TableToAst(bucketACL.EACL, bktInfo.Name)
	strCID := bucketACL.Info.CID.EncodeToString()

	for _, resource := range parentAst.Resources {
		if resource.Bucket == strCID {
			resource.Bucket = bktInfo.Name
		}
	}

	resAst, updated := MergeAst(parentAst, astChild)
	if !updated {
		return false, nil
	}

	table, err := h.NeoFS.AstToTable(resAst)
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

	if err = api.EncodeToResponse(w, h.encodeObjectACL(bucketACL, reqInfo.BucketName, objInfo.VersionID())); err != nil {
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

	list := &AccessControlPolicy{}
	if r.ContentLength == 0 {
		list, err = parseACLHeaders(r.Header, key)
		if err != nil {
			h.logAndSendError(w, "could not parse bucket acl", reqInfo, err)
			return
		}
	} else if err = xml.NewDecoder(r.Body).Decode(list); err != nil {
		h.logAndSendError(w, "could not parse bucket acl", reqInfo, errors.GetAPIError(errors.ErrMalformedXML))
		return
	}

	resInfo := &ResourceInfo{
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

	objInfo, err := h.obj.GetObjectInfo(r.Context(), p)
	if err != nil {
		h.logAndSendError(w, "could not get object info", reqInfo, err)
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

	ast := h.NeoFS.TableToAst(bucketACL.EACL, reqInfo.BucketName)
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
			Type:        AcpCanonicalUser,
		},
		Permission: ACLFullControl,
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
		if grantee.Type == AcpAmazonCustomerByEmail || (grantee.Type == AcpGroup && grantee.URI != AllUsersGroup) {
			return nil, stderrors.New("unsupported grantee type")
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
		return ACLFullControl, nil
	case api.AmzGrantRead:
		return ACLRead, nil
	case api.AmzGrantWrite:
		return ACLWrite, nil
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
			Type: AcpCanonicalUser,
		}, nil
	case "uri":
		return &Grantee{
			URI:  value,
			Type: AcpGroup,
		}, nil
	case "emailAddress":
		return &Grantee{
			EmailAddress: value,
			Type:         AcpAmazonCustomerByEmail,
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
				URI:  AllUsersGroup,
				Type: AcpGroup,
			},
			Permission: ACLFullControl,
		})
	case cannedACLAuthRead:
		fallthrough
	case basicACLReadOnly:
		acp.AccessControlList = append(acp.AccessControlList, &Grant{
			Grantee: &Grantee{
				URI:  AllUsersGroup,
				Type: AcpGroup,
			},
			Permission: ACLRead,
		})
	default:
		return nil, errors.GetAPIError(errors.ErrInvalidArgument)
	}

	return acp, nil
}

func MergeAst(parent, child *Ast) (*Ast, bool) {
	updated := false
	for _, resource := range child.Resources {
		parentResource := getParentResource(parent, resource)
		if parentResource == nil {
			parent.Resources = append(parent.Resources, resource)
			updated = true
			continue
		}

		var newOps []*AstOperation
		for _, astOp := range resource.Operations {
			ops := getAstOps(parentResource, astOp)
			switch len(ops) {
			case 2:
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
			case 1:
				if astOp.Action != ops[0].Action {
					// potential inconsistency
					if groupGrantee := astOp.IsGroupGrantee(); groupGrantee {
						// inconsistency
						removeAstOp(parentResource, groupGrantee, astOp.Op, ops[0].Action)
						parentResource.Operations = append(parentResource.Operations, astOp)
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

func handleAddOperations(parentResource *AstResource, astOp, existedOp *AstOperation) bool {
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

func handleRemoveOperations(parentResource *AstResource, astOp, existedOp *AstOperation) bool {
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

func getAstOps(resource *AstResource, childOp *AstOperation) []*AstOperation {
	var res []*AstOperation
	for _, astOp := range resource.Operations {
		if astOp.IsGroupGrantee() == childOp.IsGroupGrantee() && astOp.Op == childOp.Op {
			res = append(res, astOp)
		}
	}
	return res
}

func removeAstOp(resource *AstResource, group bool, op eacl.Operation, action eacl.Action) {
	for i, astOp := range resource.Operations {
		if astOp.IsGroupGrantee() == group && astOp.Op == op && astOp.Action == action {
			resource.Operations = append(resource.Operations[:i], resource.Operations[i+1:]...)
			return
		}
	}
}

func addUsers(resource *AstResource, astO *AstOperation, users []string) {
	for _, astOp := range resource.Operations {
		if astOp.IsGroupGrantee() == astO.IsGroupGrantee() && astOp.Op == astO.Op && astOp.Action == astO.Action {
			astOp.Users = append(astO.Users, users...)
			return
		}
	}
}

func removeUsers(resource *AstResource, AstOperation *AstOperation, users []string) {
	for ind, astOp := range resource.Operations {
		if !astOp.IsGroupGrantee() && astOp.Op == AstOperation.Op && astOp.Action == AstOperation.Action {
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

func getParentResource(parent *Ast, resource *AstResource) *AstResource {
	for _, parentResource := range parent.Resources {
		if resource.Bucket == parentResource.Bucket && resource.Object == parentResource.Object &&
			resource.Version == parentResource.Version {
			return parentResource
		}
	}
	return nil
}

func policyToAst(bktPolicy *bucketPolicy) (*Ast, error) {
	res := &Ast{}

	rr := make(map[string]*AstResource)

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
				r = &AstResource{
					ResourceInfo: ResourceInfoFromName(trimmedResource, bktPolicy.Bucket),
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

func ResourceInfoFromName(name, bucketName string) ResourceInfo {
	resInfo := ResourceInfo{Bucket: bucketName}
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

func astToPolicy(ast *Ast) *bucketPolicy {
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

func handleResourceOperations(bktPolicy *bucketPolicy, list []*AstOperation, eaclAction eacl.Action, resourceName string) {
	userOpsMap := make(map[string][]eacl.Operation)

	for _, op := range list {
		if !op.IsGroupGrantee() {
			for _, user := range op.Users {
				userOps := userOpsMap[user]
				userOps = append(userOps, op.Op)
				userOpsMap[user] = userOps
			}
		} else {
			userOps := userOpsMap[AllUsersGroup]
			userOps = append(userOps, op.Op)
			userOpsMap[AllUsersGroup] = userOps
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
			if user == AllUsersGroup {
				state.Principal = principal{AWS: allUsersWildcard}
			}
			bktPolicy.Statement = append(bktPolicy.Statement, state)
		}
	}
}

func triageOperations(operations []*AstOperation) ([]*AstOperation, []*AstOperation) {
	var allowed, denied []*AstOperation
	for _, op := range operations {
		if op.Action == eacl.ActionAllow {
			allowed = append(allowed, op)
		} else {
			denied = append(denied, op)
		}
	}
	return allowed, denied
}

func addTo(list []*AstOperation, userID string, op eacl.Operation, groupGrantee bool, action eacl.Action) []*AstOperation {
	var found *AstOperation
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
		AstOperation := &AstOperation{
			Op:     op,
			Action: action,
		}
		if !groupGrantee {
			AstOperation.Users = append(AstOperation.Users, userID)
		}

		list = append(list, AstOperation)
	}

	return list
}

func aclToAst(acl *AccessControlPolicy, resInfo *ResourceInfo) (*Ast, error) {
	res := &Ast{}

	resource := &AstResource{ResourceInfo: *resInfo}

	ops := ReadOps
	if resInfo.IsBucket() {
		ops = append(ops, WriteOps...)
	}

	// Expect to have at least 1 full control grant for owner which is set in
	// parseACLHeaders(). If there is no other grants, then user sets private
	// canned ACL, which is processed in this branch.
	if len(acl.AccessControlList) < 2 {
		for _, op := range ops {
			operation := &AstOperation{
				Op:     op,
				Action: eacl.ActionDeny,
			}
			resource.Operations = append(resource.Operations, operation)
		}
	}

	for _, op := range ops {
		operation := &AstOperation{
			Users:  []string{acl.Owner.ID},
			Op:     op,
			Action: eacl.ActionAllow,
		}
		resource.Operations = append(resource.Operations, operation)
	}

	for _, grant := range acl.AccessControlList {
		if grant.Grantee.Type == AcpAmazonCustomerByEmail || (grant.Grantee.Type == AcpGroup && grant.Grantee.URI != AllUsersGroup) {
			return nil, stderrors.New("unsupported grantee type")
		}

		var groupGrantee bool
		if grant.Grantee.Type == AcpGroup {
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

	res.Resources = []*AstResource{resource}
	return res, nil
}

func aclToPolicy(acl *AccessControlPolicy, resInfo *ResourceInfo) (*bucketPolicy, error) {
	if resInfo.Bucket == "" {
		return nil, fmt.Errorf("resource bucket must not be empty")
	}

	results := []statement{
		getAllowStatement(resInfo, acl.Owner.ID, ACLFullControl),
	}

	// Expect to have at least 1 full control grant for owner which is set in
	// parseACLHeaders(). If there is no other grants, then user sets private
	// canned ACL, which is processed in this branch.
	if len(acl.AccessControlList) < 2 {
		results = append([]statement{getDenyStatement(resInfo, allUsersWildcard, ACLFullControl)}, results...)
	}

	for _, grant := range acl.AccessControlList {
		if grant.Grantee.Type == AcpAmazonCustomerByEmail || (grant.Grantee.Type == AcpGroup && grant.Grantee.URI != AllUsersGroup) {
			return nil, stderrors.New("unsupported grantee type")
		}

		user := grant.Grantee.ID
		if grant.Grantee.Type == AcpGroup {
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

func getAllowStatement(resInfo *ResourceInfo, id string, permission AWSACL) statement {
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

func getDenyStatement(resInfo *ResourceInfo, id string, permission AWSACL) statement {
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

func getActions(permission AWSACL, isBucket bool) []string {
	var res []string
	switch permission {
	case ACLRead:
		if isBucket {
			res = []string{s3ListBucket, s3ListBucketVersions, s3ListBucketMultipartUploads}
		} else {
			res = []string{s3GetObject, s3GetObjectVersion}
		}
	case ACLWrite:
		if isBucket {
			res = []string{s3PutObject, s3DeleteObject}
		}
	case ACLFullControl:
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

func isWriteOperation(op eacl.Operation) bool {
	return op == eacl.OperationDelete || op == eacl.OperationPut
}

func (h *handler) encodeObjectACL(bucketACL *layer.BucketACL, bucketName, objectVersion string) *AccessControlPolicy {
	res := &AccessControlPolicy{
		Owner: Owner{
			ID:          bucketACL.Info.Owner.String(),
			DisplayName: bucketACL.Info.Owner.String(),
		},
	}

	m := make(map[string][]eacl.Operation)

	astList := h.NeoFS.TableToAst(bucketACL.EACL, bucketName)

	for _, resource := range astList.Resources {
		if resource.Version != objectVersion {
			continue
		}

		for _, op := range resource.Operations {
			if op.Action != eacl.ActionAllow {
				continue
			}

			if len(op.Users) == 0 {
				list := append(m[AllUsersGroup], op.Op)
				m[AllUsersGroup] = list
			} else {
				for _, user := range op.Users {
					list := append(m[user], op.Op)
					m[user] = list
				}
			}
		}
	}

	for key, val := range m {
		permission := ACLFullControl
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
			permission = ACLWrite
		} else if !write {
			permission = ACLRead
		}

		var grantee *Grantee
		if key == AllUsersGroup {
			grantee = NewGrantee(AcpGroup)
			grantee.URI = AllUsersGroup
		} else {
			grantee = NewGrantee(AcpCanonicalUser)
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

func (h *handler) encodeBucketACL(bucketName string, bucketACL *layer.BucketACL) *AccessControlPolicy {
	return h.encodeObjectACL(bucketACL, bucketName, "")
}

func contains(list []eacl.Operation, op eacl.Operation) bool {
	for _, operation := range list {
		if operation == op {
			return true
		}
	}
	return false
}
