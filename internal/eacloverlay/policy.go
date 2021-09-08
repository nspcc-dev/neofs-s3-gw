package eacloverlay

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/minio/minio-go/v7/pkg/policy"
	"github.com/nspcc-dev/neofs-api-go/pkg/acl/eacl"
	cid "github.com/nspcc-dev/neofs-api-go/pkg/container/id"
	v2acl "github.com/nspcc-dev/neofs-api-go/v2/acl"
)

const (
	// FilterAWSSid contains statement identifier from the bucket policy.
	FilterAWSSid = FilterAWSPrefix + "sid"
	// FilterAWSOperations contains list of operations from ACP ('s3:PutObject' etc.).
	// Currently unused because we need custom unmarshaler for ACL (see s3.GetBucketPolicyOutput field).
	FilterAWSOperations = FilterAWSPrefix + "operations"

	eaclOperationsSep = ","
)

// operationMap maps s3 operation to the corresponding eacl.Operation
// to be used by NeoFS nodes. If the operation is missing, the actual access
// logic is performed on the gateway.
var operationMap = map[string]eacl.Operation{
	//"s3:AbortMultipartUpload":             eacl.OperationPut,
	//"s3:BypassGovernanceRetention":        eacl.OperationPut,
	"s3:DeleteObject": eacl.OperationDelete,
	//"s3:DeleteObjectTagging":              eacl.OperationPut,
	//"s3:DeleteObjectVersion":              eacl.OperationPut,
	//"s3:DeleteObjectVersionTagging":       eacl.OperationPut,
	"s3:GetObject": eacl.OperationGet,
	//"s3:GetObjectAcl":                     eacl.OperationGet,
	//"s3:GetObjectLegalHold":               eacl.OperationGet,
	//"s3:GetObjectRetention":               eacl.OperationGet,
	//"s3:GetObjectTagging":                 eacl.OperationGet,
	//"s3:GetObjectVersion":                 eacl.OperationGet,
	//"s3:GetObjectVersionAcl":              eacl.OperationGet,
	//"s3:GetObjectVersionForReplication":   eacl.OperationGet,
	//"s3:GetObjectVersionTagging":          eacl.OperationGet,
	//"s3:ListMultipartUploadParts":         eacl.OperationGet,
	//"s3:ObjectOwnerOverrideToBucketOwner": eacl.OperationPut,
	"s3:PutObject": eacl.OperationPut,
	//"s3:PutObjectAcl":                     eacl.OperationPut,
	//"s3:PutObjectLegalHold":               eacl.OperationPut,
	//"s3:PutObjectRetention":               eacl.OperationPut,
	//"s3:PutObjectTagging":                 eacl.OperationPut,
	//"s3:PutObjectVersionAcl":              eacl.OperationPut,
	//"s3:PutObjectVersionTagging":          eacl.OperationPut,
	//"s3:ReplicateDelete":                  eacl.OperationPut,
	//"s3:ReplicateObject":                  eacl.OperationPut,
	//"s3:ReplicateTags":                    eacl.OperationPut,
	//"s3:RestoreObject":                    eacl.OperationPut,
	"s3:ListBucket": eacl.OperationSearch,
}

// s3StatementToRecord converts S3 bucket policy to a list of EACL records.
// If possible, eacl records without service headers will be created for common operations.
func s3StatementToRecord(s *policy.Statement) ([]*eacl.Record, error) {
	var eaclAction eacl.Action
	switch s.Effect {
	case "Allow":
		eaclAction = eacl.ActionAllow
	case "Deny":
		eaclAction = eacl.ActionDeny
	default:
		return nil, fmt.Errorf("unknown Effect: %s", s.Effect)
	}

	var rs []*eacl.Record
	actions := s.Actions.ToSlice()
	tgt, err := s3CanonicalIDToTarget(s.Principal.CanonicalUser.ToSlice()...)
	if err != nil {
		return nil, err
	}

	cntID, objIDs, err := s3ResourceToIDList(s.Resources)
	if err != nil {
		return nil, err
	}

	if cntID != nil {
		for _, a := range actions {
			if op, ok := operationMap[a]; ok {
				r := eacl.NewRecord()
				r.SetAction(eaclAction)
				r.SetOperation(op)
				r.SetTargets(tgt)
				rs = append(rs, r)
			}
		}

		r := eacl.NewRecord()
		r.SetAction(eaclAction)
		r.SetOperation(eacl.OperationPut)
		r.SetTargets(tgt)
		r.AddObjectContainerIDFilter(eacl.MatchStringEqual, cntID)
		r.AddFilter(HeaderFromService, eacl.MatchStringEqual, FilterAWSOperations, strings.Join(actions, eaclOperationsSep))
		r.AddFilter(HeaderFromService, eacl.MatchStringEqual, FilterAWSSid, s.Sid)
		rs = append(rs, r)
	}

	// Add NeoFS rules without service header, if possible.
	for _, oid := range objIDs {
		for _, a := range actions {
			if op, ok := operationMap[a]; ok {
				r := eacl.NewRecord()
				r.SetAction(eaclAction)
				r.SetOperation(op)
				r.SetTargets(tgt)
				r.AddObjectIDFilter(eacl.MatchStringEqual, oid)
				rs = append(rs, r)
			}
		}

		r := eacl.NewRecord()
		r.SetAction(eaclAction)
		r.SetOperation(eacl.OperationPut)
		r.SetTargets(tgt)
		r.AddObjectIDFilter(eacl.MatchStringEqual, oid)
		r.AddFilter(HeaderFromService, eacl.MatchStringEqual, FilterAWSOperations, strings.Join(actions, eaclOperationsSep))
		r.AddFilter(HeaderFromService, eacl.MatchStringEqual, FilterAWSSid, s.Sid)
		rs = append(rs, r)
	}

	return rs, nil
}

// recordToS3Statement appends fields of r to the S3 bucket policy statement.
// If onlyOp is true, targets are not processed.
func recordToS3Statement(cntID *cid.ID, r *eacl.Record, s *policy.Statement, onlyOp bool) {
	f := getFilter(r.Filters(), FilterAWSOperations)
	if f != nil {
		ops := strings.Split(f.Value(), eaclOperationsSep)
		for _, op := range ops {
			s.Actions.Add(op)
		}
	}

	f = getFilter(r.Filters(), v2acl.FilterObjectContainerID)
	if f != nil {
		s.Resources.Add(f.Value())
	} else {
		f = getFilter(r.Filters(), v2acl.FilterObjectID)
		s.Resources.Add(cntID.String() + "/" + f.Value())
	}

	if onlyOp {
		return
	}

	for _, tgt := range r.Targets() {
		for _, p := range tgt.BinaryKeys() {
			s.Principal.CanonicalUser.Add(hex.EncodeToString(p))
		}
	}
}
