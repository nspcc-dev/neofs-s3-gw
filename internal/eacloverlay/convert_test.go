package eacloverlay

import (
	"encoding/hex"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/minio/minio-go/v7/pkg/policy"
	"github.com/minio/minio-go/v7/pkg/set"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-api-go/pkg/acl/eacl"
	cid "github.com/nspcc-dev/neofs-api-go/pkg/container/id"
	"github.com/nspcc-dev/neofs-api-go/pkg/object"
	"github.com/stretchr/testify/require"
)

// This tests checks that S3 <-> EACL conversion is lossless.
func TestS3ToEACL(t *testing.T) {
	users := makeUsers(t, 4)
	cntID, objectIDs := makeOIDs(3)

	var ac AccessControl
	ac.BucketID = cntID
	//ac.Policy.Statements = []policy.Statement{
	//	{
	//		Sid:       "1",
	//		Effect:    "Allow",
	//		Principal: newPrincipal(users[1], users[2]),
	//		Actions:   set.CreateStringSet("s3:GetObject"),
	//		Resources: set.CreateStringSet(objectIDs[1].String()),
	//	},
	//	{
	//		Sid:       "2",
	//		Effect:    "Deny",
	//		Principal: newPrincipal(users[3]),
	//		Actions:   set.CreateStringSet("s3:PutObject", "s3:PutObjectAcl"),
	//		Resources: set.CreateStringSet(
	//			objectIDs[1].String(),
	//			objectIDs[2].String(),
	//		),
	//	},
	//}
	ac.ObjectACL = []ObjectACL{
		{
			ID: objectIDs[0].ObjectID(),
			ACL: s3.AccessControlPolicy{
				Grants: []*s3.Grant{
					newGrant(users[0], s3.PermissionFullControl),
					newGrant(users[3], s3.PermissionRead),
				},
				Owner: newOwner(users[0]),
			},
		},
	}

	testConversion(t, &ac)
}

func TestSimpleACL(t *testing.T) {
	users := makeUsers(t, 3)
	cntID, objectIDs := makeOIDs(2)

	var ac AccessControl
	ac.BucketID = cntID
	ac.ObjectACL = []ObjectACL{
		{
			ID: objectIDs[0].ObjectID(),
			ACL: s3.AccessControlPolicy{
				Grants: []*s3.Grant{
					newGrant(users[0], s3.PermissionFullControl),
					newGrant(users[1], s3.PermissionWrite),
					newGrant(users[2], s3.PermissionRead),
				},
				Owner: newOwner(users[0]),
			},
		},
		{
			ID: objectIDs[1].ObjectID(),
			ACL: s3.AccessControlPolicy{
				Grants: []*s3.Grant{
					newGrant(users[0], s3.PermissionRead),
					newGrant(users[1], s3.PermissionRead),
					newGrant(users[2], s3.PermissionFullControl),
				},
				Owner: newOwner(users[2]),
			},
		},
	}

	testConversion(t, &ac)
}

func TestACPListBucket(t *testing.T) {
	users := makeUsers(t, 4)
	cntID, _ := makeOIDs(2)

	var ac AccessControl
	ac.BucketID = cntID
	ac.Policy.Statements = []policy.Statement{
		{
			Sid:    "1",
			Effect: "Allow",
			Principal: policy.User{
				CanonicalUser: set.CreateStringSet(
					users[1].String(),
					users[2].String(),
				)},
			Actions:   set.CreateStringSet("s3:ListBucket"),
			Resources: set.CreateStringSet(cntID.String()),
		},
	}

	testConversion(t, &ac)
}

func testConversion(t *testing.T, ac *AccessControl) *eacl.Table {
	tb, err := S3ToEACL(ac)
	require.NoError(t, err)

	actualAc, err := EACLToS3(tb)
	require.NoError(t, err)
	require.Equal(t, ac, actualAc)

	return tb
}

func makeUsers(t *testing.T, n int) keys.PublicKeys {
	users := make(keys.PublicKeys, n)
	for i := range users {
		p, err := keys.NewPrivateKey()
		require.NoError(t, err)
		users[i] = p.PublicKey()
	}
	return users
}

func makeOIDs(n int) (*cid.ID, []*object.Address) {
	bucketID := cid.New()
	bucketID.SetSHA256([32]byte{1, 2, 3})

	addrs := make([]*object.Address, n)
	for i := range addrs {
		objID := object.NewID()
		objID.SetSHA256([32]byte{byte(i), byte(i + 1), byte(i + 2)})

		addrs[i] = object.NewAddress()
		addrs[i].SetContainerID(bucketID)
		addrs[i].SetObjectID(objID)
	}
	return bucketID, addrs
}

func newOwner(pub *keys.PublicKey) *s3.Owner {
	return &s3.Owner{ID: aws.String(pub.String())}
}

func newPrincipal(pubs ...*keys.PublicKey) policy.User {
	s := set.CreateStringSet()
	for _, p := range pubs {
		s.Add(hex.EncodeToString(p.UncompressedBytes()))
	}
	return policy.User{CanonicalUser: s}
}

func newGrant(pub *keys.PublicKey, permission string) *s3.Grant {
	return &s3.Grant{
		Grantee:    newGrantee(pub),
		Permission: aws.String(permission),
	}
}

func newGroupGrant(permission string) *s3.Grant {
	return &s3.Grant{
		Grantee: &s3.Grantee{
			Type: aws.String(s3.TypeGroup),
			URI:  aws.String(s3GroupAllURI),
		},
		Permission: aws.String(permission),
	}
}

func newGrantee(pub *keys.PublicKey) *s3.Grantee {
	return &s3.Grantee{
		ID:   aws.String(pub.String()),
		Type: aws.String(s3.TypeCanonicalUser),
	}
}
