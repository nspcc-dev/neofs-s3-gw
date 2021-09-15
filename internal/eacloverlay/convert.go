package eacloverlay

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/minio/minio-go/v7/pkg/policy"
	"github.com/minio/minio-go/v7/pkg/set"
	"github.com/nspcc-dev/neofs-api-go/pkg/acl/eacl"
	cid "github.com/nspcc-dev/neofs-api-go/pkg/container/id"
	"github.com/nspcc-dev/neofs-api-go/pkg/object"
	v2acl "github.com/nspcc-dev/neofs-api-go/v2/acl"
)

const HeaderFromService eacl.FilterHeaderType = 3

const (
	FilterAWSPrefix = "$AWS:"
	// FilterAWSPermission contains real S3 ACL permission.
	FilterAWSPermission = FilterAWSPrefix + "permission"
	// FilterAWSOwner is present if object/container owner.
	FilterAWSOwner = FilterAWSPrefix + "owner"
	// FilterAWSGroup is present if grantee is a group.
	FilterAWSGroup = FilterAWSPrefix + "group"
)

const (
	s3GroupAllURI = "http://acs.amazonaws.com/groups/global/AllUsers"
)

type (
	// AccessControl combines S3 ACP and ACL in one structure.
	AccessControl struct {
		BucketID  *cid.ID
		Policy    policy.BucketAccessPolicy
		ObjectACL []ObjectACL
	}

	// ObjectACL contains pair of ID and related ACL.
	ObjectACL struct {
		ID  *object.ID
		ACL s3.AccessControlPolicy
	}
)

var (
	// ErrInvalidCanonicalID is returned if canonical user ID can't be parsed.
	ErrInvalidCanonicalID = errors.New("invalid canonical ID")
	// ErrInvalidGranteeType is returned if Grantee type is invalid.
	ErrInvalidGranteeType = errors.New("invalid grantee type")
)

// S3ToEACL converts S3 ACP to NeoFS EACL assuming it has canonical IDs for all grantees.
func S3ToEACL(ac *AccessControl) (*eacl.Table, error) {
	tb := eacl.NewTable()
	for _, stmt := range ac.Policy.Statements {
		rs, err := s3StatementToRecord(&stmt)
		if err != nil {
			return nil, fmt.Errorf("can't convert bucket policy: %w", err)
		}
		for _, r := range rs {
			tb.AddRecord(r)
		}
	}

	for i := range ac.ObjectACL {
		owner := ac.ObjectACL[i].ACL.Owner.ID
		for _, g := range ac.ObjectACL[i].ACL.Grants {
			r, err := S3GrantToRecord(g)
			if err != nil {
				return nil, err
			}

			r.AddObjectIDFilter(eacl.MatchStringEqual, ac.ObjectACL[i].ID)
			r.AddFilter(HeaderFromService, eacl.MatchStringEqual, FilterAWSPermission, *g.Permission)
			if owner != nil && g.Grantee.ID != nil && *g.Grantee.ID == *owner {
				r.AddFilter(HeaderFromService, eacl.MatchStringEqual, FilterAWSOwner, "")
			}
			if g.Grantee.Type != nil && *g.Grantee.Type == s3.TypeGroup {
				r.AddFilter(HeaderFromService, eacl.MatchStringEqual, FilterAWSGroup, *g.Grantee.URI)
			}
			tb.AddRecord(r)
		}
	}

	r := eacl.NewRecord()
	tgt := eacl.NewTarget()
	tgt.SetRole(eacl.RoleOthers)
	r.SetTargets(tgt)
	r.SetOperation(eacl.OperationGet)
	r.SetAction(eacl.ActionDeny)
	tb.AddRecord(r)

	tb.SetCID(ac.BucketID)
	return tb, nil
}

// EACLToS3 converts NeoFS EACL to S3 ACP.
func EACLToS3(tb *eacl.Table) (*AccessControl, error) {
	var (
		ac    AccessControl
		gMap  = make(map[string]s3.AccessControlPolicy)
		stmts = make(map[string]*policy.Statement)
	)

	for _, r := range tb.Records() {
		var effect string
		switch r.Action() {
		case eacl.ActionAllow:
			effect = "Allow"
		case eacl.ActionDeny:
			effect = "Deny"
		default:
			continue
		}
		fs := r.Filters()
		if f := getFilter(fs, FilterAWSSid); f != nil {
			sid := f.Value()
			s, ok := stmts[sid]
			if !ok {
				i := len(ac.Policy.Statements)
				ac.Policy.Statements = append(ac.Policy.Statements, policy.Statement{
					Actions:   set.NewStringSet(),
					Effect:    effect,
					Resources: set.NewStringSet(),
					Principal: policy.User{
						CanonicalUser: set.NewStringSet(),
					},
					Sid: sid,
				})
				s = &ac.Policy.Statements[i]
				stmts[sid] = s
			}
			recordToS3Statement(tb.CID(), r, s, ok)
		}

		var isOwner bool
		var permission, group string

		for _, f := range fs {
			switch f.Key() {
			case FilterAWSPermission:
				permission = f.Value()
			case FilterAWSOwner:
				isOwner = true
			case FilterAWSGroup:
				group = f.Value()
			}
		}

		if permission == "" {
			continue
		}

		f := getFilter(fs, v2acl.FilterObjectID)
		if f == nil {
			continue
		}
		objID := f.Value()

		for _, tgt := range r.Targets() {
			gs := EACLTargetToGrantee(tgt, group)
			for _, g := range gs {
				acp := gMap[objID]
				acp.Grants = append(acp.Grants, &s3.Grant{
					Grantee:    g,
					Permission: aws.String(permission),
				})
				if isOwner {
					acp.Owner = &s3.Owner{ID: g.ID}
				}
				gMap[objID] = acp
			}
		}
	}

	for objID, g := range gMap {
		oid := object.NewID()
		err := oid.Parse(objID)
		if err != nil {
			return nil, err
		}

		ac.ObjectACL = append(ac.ObjectACL, ObjectACL{
			ID:  oid,
			ACL: g,
		})
	}

	// Store in canonical form.
	sort.Slice(ac.ObjectACL, func(i, j int) bool {
		return ac.ObjectACL[i].ID.String() < ac.ObjectACL[j].ID.String()
	})

	ac.BucketID = tb.CID()
	return &ac, nil
}

// S3GrantToRecord converts p to a single ACL record.
func S3GrantToRecord(p *s3.Grant) (*eacl.Record, error) {
	var op eacl.Operation
	switch *p.Permission {
	case s3.PermissionRead, s3.PermissionReadAcp:
		op = eacl.OperationGet
	case s3.PermissionFullControl, s3.PermissionWrite, s3.PermissionWriteAcp:
		op = eacl.OperationPut
	}

	r := eacl.NewRecord()
	tgt, err := S3GranteeToTarget(p.Grantee)
	if err != nil {
		return nil, err
	}

	r.SetTargets(tgt)
	r.SetAction(eacl.ActionAllow)
	r.SetOperation(op)
	return r, nil
}

// S3GranteeToTarget converts g to EACL target.
func S3GranteeToTarget(g *s3.Grantee) (*eacl.Target, error) {
	tgt := eacl.NewTarget()

	if g.Type == nil {
		return nil, fmt.Errorf("%w: nil", ErrInvalidGranteeType)
	}

	switch *g.Type {
	case s3.TypeGroup:
		// Set others and skip group for now, as we don't distinguish between
		// AllUsers and AuthorizedUsers.
		tgt.SetRole(eacl.RoleOthers)
	case s3.TypeCanonicalUser:
		pub, err := hex.DecodeString(*g.ID) // currently canonical user ID is hex-encoded public key
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrInvalidCanonicalID, *g.ID)
		}
		tgt.SetBinaryKeys([][]byte{pub})
	default:
		return nil, fmt.Errorf("%w: %s", ErrInvalidGranteeType, *g.Type)
	}
	return tgt, nil
}

// EACLTargetToGrantee converts tgt to the list of ACL grantees.
func EACLTargetToGrantee(tgt *eacl.Target, group string) []*s3.Grantee {
	var res []*s3.Grantee
	switch tgt.Role() {
	case eacl.RoleOthers:
		res = []*s3.Grantee{{
			Type: aws.String(s3.TypeGroup),
			URI:  aws.String(group),
		}}
	case eacl.RoleUnknown:
		pubs := tgt.BinaryKeys()
		res = make([]*s3.Grantee, len(pubs))
		for i, pub := range pubs {
			res[i] = &s3.Grantee{
				ID:   aws.String(hex.EncodeToString(pub)),
				Type: aws.String(s3.TypeCanonicalUser),
			}
		}
	}
	return res
}
