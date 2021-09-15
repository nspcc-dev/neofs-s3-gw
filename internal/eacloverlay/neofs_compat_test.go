package eacloverlay

import (
	"testing"

	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/minio/minio-go/v7/pkg/policy"
	"github.com/minio/minio-go/v7/pkg/set"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-api-go/pkg/acl/eacl"
	cid "github.com/nspcc-dev/neofs-api-go/pkg/container/id"
	v2acl "github.com/nspcc-dev/neofs-api-go/v2/acl"
	srveacl "github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestACPDenyGetObject(t *testing.T) {
	users := makeUsers(t, 4)
	cntID, objAddrs := makeOIDs(2)

	var ac AccessControl
	ac.BucketID = cntID
	ac.Policy.Statements = []policy.Statement{
		{
			Sid:       "1",
			Effect:    "Deny",
			Principal: newPrincipal(users[1]),
			Actions:   set.CreateStringSet("s3:GetObject"),
			Resources: set.CreateStringSet(objAddrs[0].String()),
		},
		{
			Sid:       "2",
			Effect:    "Allow",
			Principal: newPrincipal(users[0]),
			Actions:   set.CreateStringSet("s3:GetObject"),
			Resources: set.CreateStringSet(objAddrs[0].String()),
		},
	}

	tb := testConversion(t, &ac)
	v := newValidator(t, tb)
	hdrs := []srveacl.Header{
		hdr{v2acl.FilterObjectID, objAddrs[0].ObjectID().String()},
		hdr{v2acl.FilterObjectContainerID, cntID.String()},
	}

	vu := newValidationUnit(cntID, users[0], eacl.OperationGet, hdrs...)
	require.Equal(t, eacl.ActionAllow, v.CalculateAction(vu))

	vu = newValidationUnit(cntID, users[1], eacl.OperationGet, hdrs...)
	require.Equal(t, eacl.ActionDeny, v.CalculateAction(vu))
}

func TestACLAllowAll(t *testing.T) {
	users := makeUsers(t, 4)
	cntID, objAddrs := makeOIDs(2)

	var ac AccessControl
	ac.BucketID = cntID
	ac.ObjectACL = []ObjectACL{
		{
			ID: objAddrs[0].ObjectID(),
			ACL: s3.AccessControlPolicy{
				Owner: newOwner(users[0]),
				Grants: []*s3.Grant{
					newGrant(users[0], s3.PermissionFullControl),
					newGroupGrant(s3.PermissionRead),
				},
			},
		},
		{
			ID: objAddrs[1].ObjectID(),
			ACL: s3.AccessControlPolicy{
				Owner: newOwner(users[0]),
				Grants: []*s3.Grant{
					newGrant(users[0], s3.PermissionFullControl),
				},
			},
		},
	}

	tb := testConversion(t, &ac)
	v := newValidator(t, tb)

	t.Run("allowed for all", func(t *testing.T) {
		hdrs0 := []srveacl.Header{
			hdr{v2acl.FilterObjectID, objAddrs[0].ObjectID().String()},
			hdr{v2acl.FilterObjectContainerID, cntID.String()},
		}

		vu := newValidationUnit(cntID, users[0], eacl.OperationGet, hdrs0...)
		require.Equal(t, eacl.ActionAllow, v.CalculateAction(vu))

		//vu = newValidationUnit(cntID, users[1], eacl.OperationGet, hdrs0...)
		//require.Equal(t, eacl.ActionAllow, v.CalculateAction(vu))
	})

	t.Run("allowed for owner", func(t *testing.T) {
		hdrs1 := []srveacl.Header{
			hdr{v2acl.FilterObjectID, objAddrs[1].ObjectID().String()},
			hdr{v2acl.FilterObjectContainerID, cntID.String()},
		}

		vu := newValidationUnit(cntID, users[0], eacl.OperationPut, hdrs1...)
		require.Equal(t, eacl.ActionAllow, v.CalculateAction(vu))

		vu = newValidationUnit(cntID, users[1], eacl.OperationGet, hdrs1...)
		require.Equal(t, eacl.ActionDeny, v.CalculateAction(vu))
	})
}

// Helpers

type dummyEACLSource struct {
	tb *eacl.Table
}

func (s dummyEACLSource) GetEACL(*cid.ID) (*eacl.Table, error) {
	return s.tb, nil
}

func newValidator(t *testing.T, tb *eacl.Table) *srveacl.Validator {
	return srveacl.NewValidator(
		srveacl.WithEACLSource(dummyEACLSource{tb}),
		srveacl.WithLogger(zaptest.NewLogger(t)))
}

type (
	hdr struct {
		key, value string
	}
	hdrSource struct {
		req []srveacl.Header
		obj []srveacl.Header
	}
)

func (h hdr) Key() string   { return h.key }
func (h hdr) Value() string { return h.value }
func (s hdrSource) HeadersOfType(f eacl.FilterHeaderType) ([]srveacl.Header, bool) {
	switch f {
	case eacl.HeaderFromObject:
		return s.obj, true
	case eacl.HeaderFromRequest:
		return s.req, true
	default:
		return nil, false
	}
}

func newValidationUnit(cntID *cid.ID, user *keys.PublicKey, op eacl.Operation, obj ...srveacl.Header) *srveacl.ValidationUnit {
	return new(srveacl.ValidationUnit).
		WithContainerID(cntID).
		WithSenderKey(user.UncompressedBytes()).
		WithOperation(op).
		WithRole(eacl.RoleOthers).
		WithHeaderSource(hdrSource{obj: obj})
}
