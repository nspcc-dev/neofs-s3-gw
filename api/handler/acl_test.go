package handler

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/nspcc-dev/neofs-s3-gw/creds/accessbox"
	"github.com/nspcc-dev/neofs-sdk-go/bearer"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	neofscryptotest "github.com/nspcc-dev/neofs-sdk-go/crypto/test"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/session"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	usertest "github.com/nspcc-dev/neofs-sdk-go/user/test"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestTableToAst(t *testing.T) {
	b := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, b)
	require.NoError(t, err)
	id := oid.NewFromObjectHeaderBinary(b)

	key, err := keys.NewPrivateKey()
	require.NoError(t, err)
	key2, err := keys.NewPrivateKey()
	require.NoError(t, err)

	table := new(eacl.Table)
	var records []eacl.Record
	records = append(records, eacl.ConstructRecord(eacl.ActionAllow, eacl.OperationGet,
		[]eacl.Target{eacl.NewTargetByRole(eacl.RoleOthers)},
	))

	records = append(records, eacl.ConstructRecord(eacl.ActionDeny, eacl.OperationPut,
		[]eacl.Target{eacl.NewTargetByAccounts([]user.ID{
			user.NewFromScriptHash(key.PublicKey().GetScriptHash()),
			user.NewFromScriptHash(key2.PublicKey().GetScriptHash()),
		})},
		[]eacl.Filter{
			eacl.NewObjectPropertyFilter(object.AttributeFilePath, eacl.MatchStringEqual, "objectName"),
			eacl.NewFilterObjectWithID(id),
		}...,
	))

	table.SetRecords(records)

	expectedAst := &ast{
		Resources: []*astResource{
			{
				resourceInfo: resourceInfo{Bucket: "bucketName"},
				Operations: []*astOperation{{
					Op:     eacl.OperationGet,
					Action: eacl.ActionAllow,
				}}},
			{
				resourceInfo: resourceInfo{
					Bucket:  "bucketName",
					Object:  "objectName",
					Version: id.EncodeToString(),
				},
				Operations: []*astOperation{{
					Users: []user.ID{
						user.NewFromScriptHash(key.PublicKey().GetScriptHash()),
						user.NewFromScriptHash(key2.PublicKey().GetScriptHash()),
					},
					Op:     eacl.OperationPut,
					Action: eacl.ActionDeny,
				}}},
		},
	}

	actualAst := tableToAst(table, expectedAst.Resources[0].Bucket)

	if actualAst.Resources[0].Name() == expectedAst.Resources[0].Name() {
		require.Equal(t, expectedAst, actualAst)
	} else {
		require.Equal(t, len(expectedAst.Resources), len(actualAst.Resources))
		require.Equal(t, expectedAst.Resources[0], actualAst.Resources[1])
		require.Equal(t, expectedAst.Resources[1], actualAst.Resources[0])
	}
}

func TestPolicyToAst(t *testing.T) {
	key, err := keys.NewPrivateKey()
	require.NoError(t, err)

	policy := &bucketPolicy{
		Statement: []statement{
			{
				Effect:    "Allow",
				Principal: principal{AWS: allUsersWildcard},
				Action:    stringOrSlice{values: []string{"s3:PutObject"}},
				Resource:  stringOrSlice{values: []string{"arn:aws:s3:::bucketName"}},
			},
			{
				Effect: "Deny",
				Principal: principal{
					CanonicalUser: user.NewFromScriptHash(key.GetScriptHash()).String(),
				},
				Action:   stringOrSlice{values: []string{"s3:GetObject"}},
				Resource: stringOrSlice{values: []string{"arn:aws:s3:::bucketName/object"}},
			}},
	}
	policy.Bucket = "bucketName"

	expectedAst := &ast{
		Resources: []*astResource{
			{
				resourceInfo: resourceInfo{
					Bucket: "bucketName",
				},
				Operations: []*astOperation{{
					Op:     eacl.OperationPut,
					Action: eacl.ActionAllow,
				}},
			},
			{
				resourceInfo: resourceInfo{
					Bucket: "bucketName",
					Object: "object",
				},
				Operations: getReadOps(key, false, eacl.ActionDeny),
			},
		},
	}

	actualAst, err := policyToAst(policy)
	require.NoError(t, err)

	if actualAst.Resources[0].Name() == expectedAst.Resources[0].Name() {
		require.Equal(t, expectedAst, actualAst)
	} else {
		require.Equal(t, len(expectedAst.Resources), len(actualAst.Resources))
		require.Equal(t, expectedAst.Resources[0], actualAst.Resources[1])
		require.Equal(t, expectedAst.Resources[1], actualAst.Resources[0])
	}
}

func getReadOps(key *keys.PrivateKey, groupGrantee bool, action eacl.Action) []*astOperation {
	var (
		result []*astOperation
		users  []user.ID
	)
	if !groupGrantee {
		users = append(users, user.NewFromScriptHash(key.GetScriptHash()))
	}

	for _, op := range readOps {
		result = append(result, &astOperation{
			Users:  users,
			Op:     op,
			Action: action,
		})
	}

	return result
}

func TestMergeAstUnModified(t *testing.T) {
	key, err := keys.NewPrivateKey()
	require.NoError(t, err)

	child := &ast{
		Resources: []*astResource{
			{
				resourceInfo: resourceInfo{
					Bucket: "bucket",
					Object: "objectName",
				},
				Operations: []*astOperation{{
					Users:  []user.ID{user.NewFromScriptHash(key.GetScriptHash())},
					Op:     eacl.OperationPut,
					Action: eacl.ActionDeny,
				}},
			},
		},
	}

	parent := &ast{
		Resources: []*astResource{
			{
				resourceInfo: resourceInfo{
					Bucket: "bucket",
				},
				Operations: []*astOperation{{
					Op:     eacl.OperationGet,
					Action: eacl.ActionAllow,
				}},
			},
			child.Resources[0],
		},
	}

	result, updated := mergeAst(parent, child)
	require.False(t, updated)
	require.Equal(t, parent, result)
}

func TestMergeAstModified(t *testing.T) {
	user1 := usertest.ID()
	user2 := usertest.ID()

	child := &ast{
		Resources: []*astResource{
			{
				resourceInfo: resourceInfo{
					Bucket: "bucket",
					Object: "objectName",
				},
				Operations: []*astOperation{{
					Op:     eacl.OperationPut,
					Action: eacl.ActionDeny,
				}, {
					Users:  []user.ID{user2},
					Op:     eacl.OperationGet,
					Action: eacl.ActionDeny,
				}},
			},
		},
	}

	parent := &ast{
		Resources: []*astResource{
			{
				resourceInfo: resourceInfo{
					Bucket: "bucket",
					Object: "objectName",
				},
				Operations: []*astOperation{{
					Users:  []user.ID{user1},
					Op:     eacl.OperationGet,
					Action: eacl.ActionDeny,
				}},
			},
		},
	}

	expected := &ast{
		Resources: []*astResource{
			{
				resourceInfo: resourceInfo{
					Bucket: "bucket",
					Object: "objectName",
				},
				Operations: []*astOperation{
					child.Resources[0].Operations[0],
					{
						Users:  []user.ID{user1, user2},
						Op:     eacl.OperationGet,
						Action: eacl.ActionDeny,
					},
				},
			},
		},
	}

	actual, updated := mergeAst(parent, child)
	require.True(t, updated)
	require.Equal(t, expected, actual)
}

func TestMergeAppended(t *testing.T) {
	key, err := keys.NewPrivateKey()
	require.NoError(t, err)
	users := []user.ID{user.NewFromScriptHash(key.GetScriptHash())}

	parent := &ast{
		Resources: []*astResource{
			{
				resourceInfo: resourceInfo{
					Bucket: "bucket",
				},
				Operations: []*astOperation{
					{
						Users:  users,
						Op:     eacl.OperationGet,
						Action: eacl.ActionAllow,
					},
					{
						Users:  users,
						Op:     eacl.OperationPut,
						Action: eacl.ActionAllow,
					},
					{
						Users:  users,
						Op:     eacl.OperationDelete,
						Action: eacl.ActionAllow,
					},
					{
						Op:     eacl.OperationGet,
						Action: eacl.ActionDeny,
					},
					{
						Op:     eacl.OperationPut,
						Action: eacl.ActionDeny,
					},
					{
						Op:     eacl.OperationDelete,
						Action: eacl.ActionDeny,
					},
				},
			},
		},
	}

	child := &ast{
		Resources: []*astResource{
			{
				resourceInfo: resourceInfo{
					Bucket: "bucket",
					Object: "objectName",
				},
				Operations: []*astOperation{
					{
						Users:  users,
						Op:     eacl.OperationGet,
						Action: eacl.ActionAllow,
					},
					{
						Users:  users,
						Op:     eacl.OperationPut,
						Action: eacl.ActionAllow,
					},
					{
						Users:  users,
						Op:     eacl.OperationDelete,
						Action: eacl.ActionAllow,
					},
					{
						Op:     eacl.OperationGet,
						Action: eacl.ActionAllow,
					},
					{
						Op:     eacl.OperationPut,
						Action: eacl.ActionAllow,
					},
					{
						Op:     eacl.OperationDelete,
						Action: eacl.ActionAllow,
					},
				},
			},
		},
	}

	expected := &ast{
		Resources: []*astResource{
			{
				resourceInfo: resourceInfo{
					Bucket: "bucket",
				},
				Operations: []*astOperation{
					{
						Users:  users,
						Op:     eacl.OperationGet,
						Action: eacl.ActionAllow,
					},
					{
						Users:  users,
						Op:     eacl.OperationPut,
						Action: eacl.ActionAllow,
					},
					{
						Users:  users,
						Op:     eacl.OperationDelete,
						Action: eacl.ActionAllow,
					},
					{
						Op:     eacl.OperationGet,
						Action: eacl.ActionDeny,
					},
					{
						Op:     eacl.OperationPut,
						Action: eacl.ActionDeny,
					},
					{
						Op:     eacl.OperationDelete,
						Action: eacl.ActionDeny,
					},
				},
			},
			{
				resourceInfo: resourceInfo{
					Bucket: "bucket",
					Object: "objectName",
				},
				Operations: []*astOperation{
					{
						Users:  users,
						Op:     eacl.OperationGet,
						Action: eacl.ActionAllow,
					},
					{
						Users:  users,
						Op:     eacl.OperationPut,
						Action: eacl.ActionAllow,
					},
					{
						Users:  users,
						Op:     eacl.OperationDelete,
						Action: eacl.ActionAllow,
					},
					{
						Op:     eacl.OperationGet,
						Action: eacl.ActionAllow,
					},
					{
						Op:     eacl.OperationPut,
						Action: eacl.ActionAllow,
					},
					{
						Op:     eacl.OperationDelete,
						Action: eacl.ActionAllow,
					},
				},
			},
		},
	}
	actual, updated := mergeAst(parent, child)
	require.True(t, updated)
	require.Equal(t, expected, actual)
}

func TestOrder(t *testing.T) {
	key, err := keys.NewPrivateKey()
	require.NoError(t, err)
	users := []user.ID{user.NewFromScriptHash(key.GetScriptHash())}
	bucketName := "bucket"
	objectName := "objectName"

	expectedAst := &ast{
		Resources: []*astResource{
			{
				resourceInfo: resourceInfo{
					Bucket: bucketName,
				},
				Operations: []*astOperation{
					{
						Users:  users,
						Op:     eacl.OperationGet,
						Action: eacl.ActionAllow,
					},
					{
						Op:     eacl.OperationGet,
						Action: eacl.ActionDeny,
					},
				},
			},
			{
				resourceInfo: resourceInfo{
					Bucket: bucketName,
					Object: objectName,
				},
				Operations: []*astOperation{
					{
						Users:  users,
						Op:     eacl.OperationPut,
						Action: eacl.ActionAllow,
					},
					{
						Op:     eacl.OperationPut,
						Action: eacl.ActionDeny,
					},
				},
			},
		},
	}

	var records = []eacl.Record{
		eacl.ConstructRecord(eacl.ActionDeny, eacl.OperationPut,
			[]eacl.Target{
				eacl.NewTargetByRole(eacl.RoleOthers),
			},
			[]eacl.Filter{
				eacl.NewObjectPropertyFilter(object.AttributeFilePath, eacl.MatchStringEqual, objectName),
			}...,
		),
		eacl.ConstructRecord(eacl.ActionAllow, eacl.OperationPut,
			[]eacl.Target{
				eacl.NewTargetByAccounts(users),
			},
			[]eacl.Filter{
				eacl.NewObjectPropertyFilter(object.AttributeFilePath, eacl.MatchStringEqual, objectName),
			}...,
		),
		eacl.ConstructRecord(eacl.ActionDeny, eacl.OperationGet,
			[]eacl.Target{
				eacl.NewTargetByRole(eacl.RoleOthers),
			}),
		eacl.ConstructRecord(eacl.ActionAllow, eacl.OperationGet,
			[]eacl.Target{
				eacl.NewTargetByAccounts(users),
			}),
	}

	expectedEacl := eacl.ConstructTable(records)

	t.Run("astToTable order and vice versa", func(t *testing.T) {
		actualEacl, err := astToTable(expectedAst)
		require.NoError(t, err)
		require.Equal(t, &expectedEacl, actualEacl)

		actualAst := tableToAst(actualEacl, bucketName)
		require.Equal(t, expectedAst, actualAst)
	})

	t.Run("tableToAst order and vice versa", func(t *testing.T) {
		actualAst := tableToAst(&expectedEacl, bucketName)
		require.Equal(t, expectedAst, actualAst)

		actualEacl, err := astToTable(actualAst)
		require.NoError(t, err)
		require.Equal(t, &expectedEacl, actualEacl)
	})

	t.Run("append a resource", func(t *testing.T) {
		childName := "child"
		child := &ast{Resources: []*astResource{{
			resourceInfo: resourceInfo{
				Bucket: bucketName,
				Object: childName,
			},
			Operations: []*astOperation{{Op: eacl.OperationDelete, Action: eacl.ActionDeny}}}},
		}

		childRecord := eacl.ConstructRecord(eacl.ActionDeny, eacl.OperationDelete,
			[]eacl.Target{
				eacl.NewTargetByRole(eacl.RoleOthers),
			},
			[]eacl.Filter{
				eacl.NewObjectPropertyFilter(object.AttributeFilePath, eacl.MatchStringEqual, childName),
			}...,
		)

		mergedAst, updated := mergeAst(expectedAst, child)
		require.True(t, updated)

		mergedEacl, err := astToTable(mergedAst)
		require.NoError(t, err)

		require.Equal(t, childRecord, mergedEacl.Records()[0])
	})
}

func TestMergeAstModifiedConflict(t *testing.T) {
	user1 := usertest.ID()
	user2 := usertest.ID()
	user3 := usertest.ID()

	child := &ast{
		Resources: []*astResource{
			{
				resourceInfo: resourceInfo{
					Bucket: "bucket",
					Object: "objectName",
				},
				Operations: []*astOperation{{
					Users:  []user.ID{user1},
					Op:     eacl.OperationPut,
					Action: eacl.ActionDeny,
				}, {
					Users:  []user.ID{user3},
					Op:     eacl.OperationGet,
					Action: eacl.ActionAllow,
				}},
			},
		},
	}

	parent := &ast{
		Resources: []*astResource{
			{
				resourceInfo: resourceInfo{
					Bucket: "bucket",
					Object: "objectName",
				},
				Operations: []*astOperation{{
					Users:  []user.ID{user1},
					Op:     eacl.OperationPut,
					Action: eacl.ActionAllow,
				}, {
					Users:  []user.ID{user2},
					Op:     eacl.OperationPut,
					Action: eacl.ActionDeny,
				}, {
					Users:  []user.ID{user3},
					Op:     eacl.OperationGet,
					Action: eacl.ActionDeny,
				}},
			},
		},
	}

	expected := &ast{
		Resources: []*astResource{
			{
				resourceInfo: resourceInfo{
					Bucket: "bucket",
					Object: "objectName",
				},
				Operations: []*astOperation{
					{
						Users:  []user.ID{user2, user1},
						Op:     eacl.OperationPut,
						Action: eacl.ActionDeny,
					}, {
						Users:  []user.ID{user3},
						Op:     eacl.OperationGet,
						Action: eacl.ActionAllow,
					},
				},
			},
		},
	}

	actual, updated := mergeAst(parent, child)
	require.True(t, updated)
	require.Equal(t, expected, actual)
}

func TestAstToTable(t *testing.T) {
	key, err := keys.NewPrivateKey()
	require.NoError(t, err)

	ast := &ast{
		Resources: []*astResource{
			{
				resourceInfo: resourceInfo{
					Bucket: "bucketName",
				},
				Operations: []*astOperation{{
					Users:  []user.ID{user.NewFromScriptHash(key.GetScriptHash())},
					Op:     eacl.OperationPut,
					Action: eacl.ActionAllow,
				}},
			},
			{
				resourceInfo: resourceInfo{
					Bucket: "bucketName",
					Object: "objectName",
				},
				Operations: []*astOperation{{
					Op:     eacl.OperationGet,
					Action: eacl.ActionDeny,
				}},
			},
		},
	}

	records := []eacl.Record{
		eacl.ConstructRecord(eacl.ActionDeny, eacl.OperationGet,
			[]eacl.Target{eacl.NewTargetByRole(eacl.RoleOthers)},
			[]eacl.Filter{
				eacl.NewObjectPropertyFilter(object.AttributeFilePath, eacl.MatchStringEqual, "objectName"),
			}...,
		),
		eacl.ConstructRecord(eacl.ActionAllow, eacl.OperationPut,
			[]eacl.Target{eacl.NewTargetByAccounts([]user.ID{user.NewFromScriptHash(key.PublicKey().GetScriptHash())})},
		),
	}

	expectedTable := eacl.ConstructTable(records)

	actualTable, err := astToTable(ast)
	require.NoError(t, err)
	require.Equal(t, &expectedTable, actualTable)
}

func TestRemoveUsers(t *testing.T) {
	user1 := usertest.ID()
	user2 := usertest.ID()
	user3 := usertest.ID()
	user4 := usertest.ID()
	user5 := usertest.ID()

	resource := &astResource{
		resourceInfo: resourceInfo{
			Bucket: "bucket",
		},
		Operations: []*astOperation{{
			Users:  []user.ID{user1, user3, user4},
			Op:     eacl.OperationPut,
			Action: eacl.ActionAllow,
		},
			{
				Users:  []user.ID{user5},
				Op:     eacl.OperationGet,
				Action: eacl.ActionDeny,
			},
		},
	}

	op1 := &astOperation{
		Op:     eacl.OperationPut,
		Action: eacl.ActionAllow,
	}
	op2 := &astOperation{
		Op:     eacl.OperationGet,
		Action: eacl.ActionDeny,
	}

	removeUsers(resource, op1, []user.ID{user1, user2, user4}) // modify astOperation
	removeUsers(resource, op2, []user.ID{user5})               // remove astOperation

	require.Equal(t, len(resource.Operations), 1)
	require.Equal(t, []user.ID{user3}, resource.Operations[0].Users)
}

func TestBucketAclToPolicy(t *testing.T) {
	key, err := keys.NewPrivateKey()
	require.NoError(t, err)
	key2, err := keys.NewPrivateKey()
	require.NoError(t, err)

	id := user.NewFromScriptHash(key.GetScriptHash())
	id2 := hex.EncodeToString(key2.PublicKey().Bytes())

	acl := &AccessControlPolicy{
		Owner: Owner{
			ID:          id.String(),
			DisplayName: "user1",
		},
		AccessControlList: []*Grant{{
			Grantee: &Grantee{
				URI:  allUsersGroup,
				Type: granteeGroup,
			},
			Permission: awsPermRead,
		}, {
			Grantee: &Grantee{
				ID:   id2,
				Type: granteeCanonicalUser,
			},
			Permission: awsPermWrite,
		}},
	}

	resInfo := &resourceInfo{
		Bucket: "bucketName",
	}

	expectedPolicy := &bucketPolicy{
		Bucket: resInfo.Bucket,
		Statement: []statement{
			{
				Effect: "Allow",
				Principal: principal{
					CanonicalUser: id.String(),
				},
				Action:   stringOrSlice{values: []string{"s3:ListBucket", "s3:ListBucketVersions", "s3:ListBucketMultipartUploads", "s3:PutObject", "s3:DeleteObject"}},
				Resource: stringOrSlice{values: []string{arnAwsPrefix + resInfo.Name()}},
			},
			{
				Effect:    "Allow",
				Principal: principal{AWS: allUsersWildcard},
				Action:    stringOrSlice{values: []string{"s3:ListBucket", "s3:ListBucketVersions", "s3:ListBucketMultipartUploads"}},
				Resource:  stringOrSlice{values: []string{arnAwsPrefix + resInfo.Name()}},
			},
			{
				Effect: "Allow",
				Principal: principal{
					CanonicalUser: id2,
				},
				Action:   stringOrSlice{values: []string{"s3:PutObject", "s3:DeleteObject"}},
				Resource: stringOrSlice{values: []string{arnAwsPrefix + resInfo.Name()}},
			},
		},
	}

	actualPolicy, err := aclToPolicy(acl, resInfo)
	require.NoError(t, err)
	require.Equal(t, expectedPolicy, actualPolicy)
}

func TestObjectAclToPolicy(t *testing.T) {
	key, err := keys.NewPrivateKey()
	require.NoError(t, err)
	key2, err := keys.NewPrivateKey()
	require.NoError(t, err)

	id := user.NewFromScriptHash(key.GetScriptHash())
	id2 := hex.EncodeToString(key2.PublicKey().Bytes())

	acl := &AccessControlPolicy{
		Owner: Owner{
			ID:          id.String(),
			DisplayName: "user1",
		},
		AccessControlList: []*Grant{{
			Grantee: &Grantee{
				ID:   id.String(),
				Type: granteeCanonicalUser,
			},
			Permission: awsPermFullControl,
		}, {
			Grantee: &Grantee{
				ID:   id2,
				Type: granteeCanonicalUser,
			},
			Permission: awsPermFullControl,
		}, {
			Grantee: &Grantee{
				URI:  allUsersGroup,
				Type: granteeGroup,
			},
			Permission: awsPermRead,
		}},
	}

	resInfo := &resourceInfo{
		Bucket: "bucketName",
		Object: "object",
	}

	expectedPolicy := &bucketPolicy{
		Bucket: resInfo.Bucket,
		Statement: []statement{
			{
				Effect: "Allow",
				Principal: principal{
					CanonicalUser: id.String(),
				},
				Action:   stringOrSlice{values: []string{s3GetObject, s3GetObjectVersion, s3PutObject, s3DeleteObject}},
				Resource: stringOrSlice{values: []string{arnAwsPrefix + resInfo.Name()}},
			},
			{
				Effect: "Allow",
				Principal: principal{
					CanonicalUser: id2,
				},
				Action:   stringOrSlice{values: []string{s3GetObject, s3GetObjectVersion, s3PutObject, s3DeleteObject}},
				Resource: stringOrSlice{values: []string{arnAwsPrefix + resInfo.Name()}},
			},
			{
				Effect:    "Allow",
				Principal: principal{AWS: allUsersWildcard},
				Action:    stringOrSlice{values: []string{s3GetObject, s3GetObjectVersion}},
				Resource:  stringOrSlice{values: []string{arnAwsPrefix + resInfo.Name()}},
			},
		},
	}

	actualPolicy, err := aclToPolicy(acl, resInfo)
	require.NoError(t, err)
	require.Equal(t, expectedPolicy, actualPolicy)
}

func TestObjectWithVersionAclToTable(t *testing.T) {
	key, err := keys.NewPrivateKey()
	require.NoError(t, err)
	id := user.NewFromScriptHash(key.GetScriptHash())

	acl := &AccessControlPolicy{
		Owner: Owner{
			ID:          id.String(),
			DisplayName: "user1",
		},
		AccessControlList: []*Grant{{
			Grantee: &Grantee{
				ID:   id.String(),
				Type: granteeCanonicalUser,
			},
			Permission: awsPermFullControl,
		}},
	}

	resInfoObject := &resourceInfo{
		Bucket: "bucketName",
		Object: "object",
	}
	expectedTable := allowedTableForPrivateObject(t, key, resInfoObject)
	actualTable := tableFromACL(t, acl, resInfoObject)
	checkTables(t, expectedTable, actualTable)

	resInfoObjectVersion := &resourceInfo{
		Bucket:  "bucketName",
		Object:  "objectVersion",
		Version: "Gfrct4Afhio8pCGCCKVNTf1kyexQjMBeaUfvDtQCkAvg",
	}
	expectedTable = allowedTableForPrivateObject(t, key, resInfoObjectVersion)
	actualTable = tableFromACL(t, acl, resInfoObjectVersion)
	checkTables(t, expectedTable, actualTable)
}

func allowedTableForPrivateObject(t *testing.T, key *keys.PrivateKey, resInfo *resourceInfo) *eacl.Table {
	var objID oid.ID

	if resInfo.Version != "" {
		err := objID.DecodeString(resInfo.Version)
		require.NoError(t, err)
	}

	var records []eacl.Record

	applyFilters := func(r *eacl.Record) {
		var filters []eacl.Filter

		if resInfo.Object != "" {
			filters = append(filters, eacl.NewObjectPropertyFilter(object.AttributeFilePath, eacl.MatchStringEqual, resInfo.Object))
		}
		if !objID.IsZero() {
			filters = append(filters, eacl.NewFilterObjectWithID(objID))
		}

		r.SetFilters(filters)
	}

	// Order of these loops is important for test.
	for i := len(writeOps) - 1; i >= 0; i-- {
		op := writeOps[i]
		record := getAllowRecordWithUser(op, user.NewFromScriptHash(key.GetScriptHash()))

		applyFilters(record)
		records = append(records, *record)
	}
	for i := len(readOps) - 1; i >= 0; i-- {
		op := readOps[i]
		record := getAllowRecordWithUser(op, user.NewFromScriptHash(key.GetScriptHash()))

		applyFilters(record)
		records = append(records, *record)
	}

	for i := len(writeOps) - 1; i >= 0; i-- {
		op := writeOps[i]
		record := getOthersRecord(op, eacl.ActionDeny)

		applyFilters(record)
		records = append(records, *record)
	}
	for i := len(readOps) - 1; i >= 0; i-- {
		op := readOps[i]
		record := getOthersRecord(op, eacl.ActionDeny)

		applyFilters(record)
		records = append(records, *record)
	}

	expectedTable := eacl.ConstructTable(records)

	return &expectedTable
}

func tableFromACL(t *testing.T, acl *AccessControlPolicy, resInfo *resourceInfo) *eacl.Table {
	actualPolicy, err := aclToPolicy(acl, resInfo)
	require.NoError(t, err)
	actualAst, err := policyToAst(actualPolicy)
	require.NoError(t, err)
	actualTable, err := astToTable(actualAst)
	require.NoError(t, err)
	return actualTable
}

func checkTables(t *testing.T, expectedTable, actualTable *eacl.Table) {
	require.Equal(t, len(expectedTable.Records()), len(actualTable.Records()), "different number of records")
	for i, record := range expectedTable.Records() {
		actRecord := actualTable.Records()[i]

		require.Equal(t, len(record.Targets()), len(actRecord.Targets()), "different number of targets")
		for j, target := range record.Targets() {
			actTarget := actRecord.Targets()[j]

			expected := fmt.Sprintf("%s %v", target.Role().String(), target.Accounts())
			actual := fmt.Sprintf("%s %v", actTarget.Role().String(), actTarget.Accounts())
			require.Equalf(t, target, actTarget, "want: '%s'\ngot: '%s'", expected, actual)
		}

		require.Equal(t, len(record.Filters()), len(actRecord.Filters()), "different number of filters")
		for j, filter := range record.Filters() {
			actFilter := actRecord.Filters()[j]

			expected := fmt.Sprintf("%s:%s %s %s", filter.From().String(), filter.Key(), filter.Matcher().String(), filter.Value())
			actual := fmt.Sprintf("%s:%s %s %s", actFilter.From().String(), actFilter.Key(), actFilter.Matcher().String(), actFilter.Value())
			require.Equalf(t, filter, actFilter, "want: '%s'\ngot: '%s'", expected, actual)
		}

		require.Equal(t, record.Action().String(), actRecord.Action().String())
		require.Equal(t, record.Operation().String(), actRecord.Operation().String())
	}
}

func TestParseCannedACLHeaders(t *testing.T) {
	key, err := keys.NewPrivateKey()
	require.NoError(t, err)

	id := user.NewFromScriptHash(key.GetScriptHash())
	address := key.PublicKey().Address()

	req := &http.Request{
		Header: map[string][]string{
			api.AmzACL: {basicACLReadOnly},
		},
	}

	expectedACL := &AccessControlPolicy{
		Owner: Owner{
			ID:          id.String(),
			DisplayName: address,
		},
		AccessControlList: []*Grant{{
			Grantee: &Grantee{
				ID:          id.String(),
				DisplayName: address,
				Type:        granteeCanonicalUser,
			},
			Permission: awsPermFullControl,
		}, {
			Grantee: &Grantee{
				URI:  allUsersGroup,
				Type: granteeGroup,
			},
			Permission: awsPermRead,
		}},
	}

	actualACL, err := parseACLHeaders(req.Header, user.NewFromScriptHash(key.GetScriptHash()))
	require.NoError(t, err)
	require.Equal(t, expectedACL, actualACL)
}

func TestParseACLHeaders(t *testing.T) {
	key, err := keys.NewPrivateKey()
	require.NoError(t, err)

	id := user.NewFromScriptHash(key.GetScriptHash())
	address := key.PublicKey().Address()

	user1 := usertest.ID()
	user2 := usertest.ID()
	user3 := usertest.ID()

	req := &http.Request{
		Header: map[string][]string{
			api.AmzGrantFullControl: {fmt.Sprintf("id=\"%s\"", user1.String())},
			api.AmzGrantRead:        {"uri=\"" + allUsersGroup + fmt.Sprintf("\", id=\"%s\"", user2.String())},
			api.AmzGrantWrite:       {fmt.Sprintf("id=\"%s\", id=\"%s\"", user2.String(), user3.String())},
		},
	}

	expectedACL := &AccessControlPolicy{
		Owner: Owner{
			ID:          id.String(),
			DisplayName: address,
		},
		AccessControlList: []*Grant{{
			Grantee: &Grantee{
				ID:          id.String(),
				DisplayName: address,
				Type:        granteeCanonicalUser,
			},
			Permission: awsPermFullControl,
		}, {
			Grantee: &Grantee{
				ID:   user1.String(),
				Type: granteeCanonicalUser,
			},
			Permission: awsPermFullControl,
		}, {
			Grantee: &Grantee{
				URI:  allUsersGroup,
				Type: granteeGroup,
			},
			Permission: awsPermRead,
		}, {
			Grantee: &Grantee{
				ID:   user2.String(),
				Type: granteeCanonicalUser,
			},
			Permission: awsPermRead,
		}, {
			Grantee: &Grantee{
				ID:   user2.String(),
				Type: granteeCanonicalUser,
			},
			Permission: awsPermWrite,
		}, {
			Grantee: &Grantee{
				ID:   user3.String(),
				Type: granteeCanonicalUser,
			},
			Permission: awsPermWrite,
		}},
	}

	actualACL, err := parseACLHeaders(req.Header, user.NewFromScriptHash(key.GetScriptHash()))
	require.NoError(t, err)
	require.Equal(t, expectedACL, actualACL)
}

func TestAddGranteeError(t *testing.T) {
	headers := map[string][]string{
		api.AmzGrantFullControl: {"i=\"user1\""},
		api.AmzGrantRead:        {"uri, id=\"user2\""},
		api.AmzGrantWrite:       {"emailAddress=\"user2\""},
		"unknown header":        {"something"},
	}

	expectedList := []*Grant{{
		Permission: "predefined",
	}}

	actualList, err := addGrantees(expectedList, headers, "unknown header1")
	require.NoError(t, err)
	require.Equal(t, expectedList, actualList)

	actualList, err = addGrantees(expectedList, headers, "unknown header")
	require.Error(t, err)
	require.Nil(t, actualList)

	actualList, err = addGrantees(expectedList, headers, api.AmzGrantFullControl)
	require.Error(t, err)
	require.Nil(t, actualList)

	actualList, err = addGrantees(expectedList, headers, api.AmzGrantRead)
	require.Error(t, err)
	require.Nil(t, actualList)

	actualList, err = addGrantees(expectedList, headers, api.AmzGrantWrite)
	require.Error(t, err)
	require.Nil(t, actualList)
}

func TestBucketAclToTable(t *testing.T) {
	key, err := keys.NewPrivateKey()
	require.NoError(t, err)
	key2, err := keys.NewPrivateKey()
	require.NoError(t, err)

	id := user.NewFromScriptHash(key.GetScriptHash())
	id2 := user.NewFromScriptHash(key2.GetScriptHash())

	acl := &AccessControlPolicy{
		Owner: Owner{
			ID:          id.String(),
			DisplayName: "user1",
		},
		AccessControlList: []*Grant{{
			Grantee: &Grantee{
				URI:  allUsersGroup,
				Type: granteeGroup,
			},
			Permission: awsPermRead,
		}, {
			Grantee: &Grantee{
				ID:   id2.String(),
				Type: granteeCanonicalUser,
			},
			Permission: awsPermWrite,
		}},
	}

	var records []eacl.Record
	for _, op := range readOps {
		records = append(records, *getOthersRecord(op, eacl.ActionAllow))
	}
	for _, op := range writeOps {
		records = append(records, *getAllowRecordWithUser(op, user.NewFromScriptHash(key2.GetScriptHash())))
	}
	for _, op := range fullOps {
		records = append(records, *getAllowRecordWithUser(op, user.NewFromScriptHash(key.GetScriptHash())))
	}
	records = append(records, getAllowRecordForBucketSettings())
	for _, op := range fullOps {
		records = append(records, *getOthersRecord(op, eacl.ActionDeny))
	}

	actualTable, err := bucketACLToTable(acl)
	require.NoError(t, err)
	require.Equal(t, records, actualTable.Records())
}

func TestObjectAclToAst(t *testing.T) {
	b := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, b)
	require.NoError(t, err)
	var objID oid.ID = sha256.Sum256(b)

	key, err := keys.NewPrivateKey()
	require.NoError(t, err)
	key2, err := keys.NewPrivateKey()
	require.NoError(t, err)

	id := user.NewFromScriptHash(key.GetScriptHash())
	id2 := user.NewFromScriptHash(key2.GetScriptHash())

	acl := &AccessControlPolicy{
		Owner: Owner{
			ID:          id.String(),
			DisplayName: "user1",
		},
		AccessControlList: []*Grant{{
			Grantee: &Grantee{
				ID:   id.String(),
				Type: granteeCanonicalUser,
			},
			Permission: awsPermFullControl,
		}, {
			Grantee: &Grantee{
				ID:   id2.String(),
				Type: granteeCanonicalUser,
			},
			Permission: awsPermRead,
		},
		},
	}

	resInfo := &resourceInfo{
		Bucket:  "bucketName",
		Object:  "object",
		Version: objID.EncodeToString(),
	}

	var operations []*astOperation
	for _, op := range readOps {
		astOp := &astOperation{Users: []user.ID{
			user.NewFromScriptHash(key.GetScriptHash()),
			user.NewFromScriptHash(key2.GetScriptHash()),
		},
			Op:     op,
			Action: eacl.ActionAllow,
		}
		operations = append(operations, astOp)
	}

	for _, op := range writeOps {
		astOp := &astOperation{Users: []user.ID{
			user.NewFromScriptHash(key.GetScriptHash()),
		},
			Op:     op,
			Action: eacl.ActionAllow,
		}
		operations = append(operations, astOp)
	}

	expectedAst := &ast{
		Resources: []*astResource{
			{
				resourceInfo: *resInfo,
				Operations:   operations,
			},
		},
	}

	actualAst, err := aclToAst(acl, resInfo)
	require.NoError(t, err)
	require.Equal(t, expectedAst, actualAst)
}

func TestBucketAclToAst(t *testing.T) {
	b := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, b)
	require.NoError(t, err)

	key, err := keys.NewPrivateKey()
	require.NoError(t, err)
	key2, err := keys.NewPrivateKey()
	require.NoError(t, err)

	id := user.NewFromScriptHash(key.GetScriptHash())
	id2 := user.NewFromScriptHash(key2.GetScriptHash())

	acl := &AccessControlPolicy{
		Owner: Owner{
			ID:          id.String(),
			DisplayName: "user1",
		},
		AccessControlList: []*Grant{
			{
				Grantee: &Grantee{
					ID:   id2.String(),
					Type: granteeCanonicalUser,
				},
				Permission: awsPermWrite,
			}, {
				Grantee: &Grantee{
					URI:  allUsersGroup,
					Type: granteeGroup,
				},
				Permission: awsPermRead,
			},
		},
	}

	var operations []*astOperation
	for _, op := range readOps {
		astOp := &astOperation{Users: []user.ID{
			user.NewFromScriptHash(key.GetScriptHash()),
		},
			Op:     op,
			Action: eacl.ActionAllow,
		}
		operations = append(operations, astOp)
	}
	for _, op := range writeOps {
		astOp := &astOperation{Users: []user.ID{
			user.NewFromScriptHash(key.GetScriptHash()),
			user.NewFromScriptHash(key2.GetScriptHash()),
		},
			Op:     op,
			Action: eacl.ActionAllow,
		}
		operations = append(operations, astOp)
	}
	for _, op := range readOps {
		astOp := &astOperation{
			Op:     op,
			Action: eacl.ActionAllow,
		}
		operations = append(operations, astOp)
	}

	resInfo := &resourceInfo{Bucket: "bucketName"}

	expectedAst := &ast{
		Resources: []*astResource{
			{
				resourceInfo: *resInfo,
				Operations:   operations,
			},
		},
	}

	actualAst, err := aclToAst(acl, resInfo)
	require.NoError(t, err)
	require.Equal(t, expectedAst, actualAst)
}

func TestPutBucketACL(t *testing.T) {
	tc := prepareHandlerContext(t)
	bktName := "bucket-for-acl"

	box, _ := createAccessBox(t)
	bktInfo := createBucket(t, tc, bktName, box)

	header := map[string]string{api.AmzACL: "public-read"}
	// ACLs disabled.
	putBucketACL(t, tc, bktName, box, header, http.StatusBadRequest)

	putBucketOwnership(tc, bktName, box, amzBucketOwnerObjectWriter, http.StatusOK)

	// ACLs enabled.
	putBucketACL(t, tc, bktName, box, header, http.StatusOK)
	header = map[string]string{api.AmzACL: "private"}
	putBucketACL(t, tc, bktName, box, header, http.StatusOK)
	checkLastRecords(t, tc, bktInfo, eacl.ActionDeny, ownerObjectWriterUserID)
}

func TestBucketPolicy(t *testing.T) {
	hc := prepareHandlerContext(t)
	bktName := "bucket-for-policy"

	box, key := createAccessBox(t)
	createBucket(t, hc, bktName, box)

	bktPolicy := getBucketPolicy(hc, bktName)
	for _, st := range bktPolicy.Statement {
		if st.Effect == "Allow" {
			require.Equal(t, user.NewFromScriptHash(key.GetScriptHash()).String(), st.Principal.CanonicalUser)
			require.Equal(t, []string{arnAwsPrefix + bktName}, st.Resource.values)
		} else {
			if st.Principal.AWS != "" {
				require.Equal(t, allUsersWildcard, st.Principal.AWS)
			} else {
				// special marker record for ownership.
				require.Equal(t, ownerEnforcedUserID.String(), st.Principal.CanonicalUser)
			}

			require.Equal(t, "Deny", st.Effect)
			require.Equal(t, []string{arnAwsPrefix + bktName}, st.Resource.values)
		}
	}

	newPolicy := &bucketPolicy{
		Statement: []statement{{
			Effect:    "Allow",
			Principal: principal{AWS: allUsersWildcard},
			Action:    stringOrSlice{values: []string{s3GetObject}},
			Resource:  stringOrSlice{values: []string{arnAwsPrefix + "dummy"}},
		}},
	}

	putBucketPolicy(hc, bktName, newPolicy, box, http.StatusInternalServerError)

	newPolicy.Statement[0].Resource.values[0] = arnAwsPrefix + bktName
	putBucketPolicy(hc, bktName, newPolicy, box, http.StatusOK)

	bktPolicy = getBucketPolicy(hc, bktName)
	for _, st := range bktPolicy.Statement {
		if st.Effect == "Allow" && st.Principal.AWS == allUsersWildcard {
			require.Equal(t, []string{arnAwsPrefix + bktName}, st.Resource.values)
			require.ElementsMatch(t, []string{s3GetObject, s3ListBucket}, st.Action.values)
		}
	}
}

func getBucketPolicy(hc *handlerContext, bktName string) *bucketPolicy {
	w, r := prepareTestRequest(hc, bktName, "", nil)
	hc.Handler().GetBucketPolicyHandler(w, r)

	assertStatus(hc.t, w, http.StatusOK)
	policy := &bucketPolicy{}
	body := w.Result().Body
	err := json.NewDecoder(body).Decode(policy)
	body.Close()
	require.NoError(hc.t, err)
	return policy
}

func putBucketPolicy(hc *handlerContext, bktName string, bktPolicy *bucketPolicy, box *accessbox.Box, status int) {
	body, err := json.Marshal(bktPolicy)
	require.NoError(hc.t, err)

	w, r := prepareTestPayloadRequest(hc, bktName, "", bytes.NewReader(body))
	ctx := context.WithValue(r.Context(), api.BoxData, box)
	r = r.WithContext(ctx)
	hc.Handler().PutBucketPolicyHandler(w, r)
	assertStatus(hc.t, w, status)
}

func putBucketOwnership(hc *handlerContext, bktName string, box *accessbox.Box, ownership string, status int) {
	p := putBucketOwnershipControlsParams{
		Rules: []objectOwnershipRules{
			{
				ObjectOwnership: ownership,
			},
		},
	}

	var b bytes.Buffer
	err := xml.NewEncoder(&b).Encode(p)
	require.NoError(hc.t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, defaultURL, &b)

	reqInfo := api.NewReqInfo(w, r, api.ObjectRequest{Bucket: bktName})
	r = r.WithContext(api.SetReqInfo(hc.Context(), reqInfo))
	ctx := context.WithValue(r.Context(), api.BoxData, box)
	r = r.WithContext(ctx)
	hc.Handler().PutBucketOwnershipControlsHandler(w, r)

	assertStatus(hc.t, w, status)
}

func checkLastRecords(t *testing.T, tc *handlerContext, bktInfo *data.BucketInfo, action eacl.Action, markerUserID user.ID) {
	bktACL, err := tc.Layer().GetBucketACL(tc.Context(), bktInfo)
	require.NoError(t, err)

	length := len(bktACL.EACL.Records())

	if length < 7 {
		t.Fatalf("length of records is less than 7: '%d'", length)
	}

	for _, rec := range bktACL.EACL.Records()[length-7:] {
		if rec.Targets()[0].Role() == eacl.RoleOthers {
			require.Equal(t, action, rec.Action())
		} else {
			// special ownership marker rule.
			require.Equal(t, markerUserID, rec.Targets()[0].Accounts()[0])
		}
	}
}

func createAccessBox(t *testing.T) (*accessbox.Box, *keys.PrivateKey) {
	key, err := keys.NewPrivateKey()
	require.NoError(t, err)

	var bearerToken bearer.Token
	err = bearerToken.Sign(user.NewAutoIDSignerRFC6979(key.PrivateKey))
	require.NoError(t, err)

	tok := new(session.Container)
	tok.ForVerb(session.VerbContainerSetEACL)

	tok2 := new(session.Container)
	tok2.ForVerb(session.VerbContainerPut)
	box := &accessbox.Box{
		Gate: &accessbox.GateData{
			SessionTokens: []*session.Container{tok, tok2},
			BearerToken:   &bearerToken,
		},
	}

	return box, key
}

func createBucket(t *testing.T, tc *handlerContext, bktName string, box *accessbox.Box) *data.BucketInfo {
	w, r := prepareTestRequest(tc, bktName, "", nil)
	ctx := context.WithValue(r.Context(), api.BoxData, box)
	r = r.WithContext(ctx)
	tc.Handler().CreateBucketHandler(w, r)
	assertStatus(t, w, http.StatusOK)

	bktInfo, err := tc.Layer().GetBucketInfo(tc.Context(), bktName)
	require.NoError(t, err)
	return bktInfo
}

func putBucketACL(t *testing.T, tc *handlerContext, bktName string, box *accessbox.Box, header map[string]string, status int) {
	w, r := prepareTestRequest(tc, bktName, "", nil)
	for key, val := range header {
		r.Header.Set(key, val)
	}
	ctx := context.WithValue(r.Context(), api.BoxData, box)
	r = r.WithContext(ctx)
	tc.Handler().PutBucketACLHandler(w, r)
	assertStatus(t, w, status)
}

func generateRecord(action eacl.Action, op eacl.Operation, targets []eacl.Target) *eacl.Record {
	var r eacl.Record
	r.SetAction(action)
	r.SetOperation(op)
	r.SetTargets(targets...)

	return &r
}

func TestEACLEncode(t *testing.T) {
	s := user.NewAutoIDSigner(neofscryptotest.ECDSAPrivateKey())

	b := make([]byte, s.Public().MaxEncodedSize())
	s.Public().Encode(b)

	pubKey, err := keys.NewPublicKeyFromBytes(b, elliptic.P256())
	require.NoError(t, err)
	owner := user.NewFromScriptHash(pubKey.GetScriptHash())

	acl := layer.BucketACL{
		Info: &data.BucketInfo{
			OwnerPublicKey: *pubKey,
		},
		EACL: &eacl.Table{},
	}
	acl.Info.Owner = s.UserID()

	var containerID cid.ID
	acl.EACL.SetCID(containerID)

	var userTarget eacl.Target
	userTarget.SetAccounts([]user.ID{s.UserID()})

	var othersTarget eacl.Target
	othersTarget.SetRole(eacl.RoleOthers)

	var records []eacl.Record

	records = append(records, *generateRecord(eacl.ActionAllow, eacl.OperationGet, []eacl.Target{userTarget}))
	records = append(records, *generateRecord(eacl.ActionAllow, eacl.OperationHead, []eacl.Target{userTarget}))
	records = append(records, *generateRecord(eacl.ActionAllow, eacl.OperationPut, []eacl.Target{userTarget}))
	records = append(records, *generateRecord(eacl.ActionAllow, eacl.OperationDelete, []eacl.Target{userTarget}))
	records = append(records, *generateRecord(eacl.ActionAllow, eacl.OperationSearch, []eacl.Target{userTarget}))
	records = append(records, *generateRecord(eacl.ActionAllow, eacl.OperationRange, []eacl.Target{userTarget}))
	records = append(records, *generateRecord(eacl.ActionAllow, eacl.OperationRangeHash, []eacl.Target{userTarget}))

	records = append(records, *generateRecord(eacl.ActionAllow, eacl.OperationGet, []eacl.Target{othersTarget}))
	records = append(records, *generateRecord(eacl.ActionAllow, eacl.OperationHead, []eacl.Target{othersTarget}))
	records = append(records, *generateRecord(eacl.ActionAllow, eacl.OperationSearch, []eacl.Target{othersTarget}))
	records = append(records, *generateRecord(eacl.ActionAllow, eacl.OperationRange, []eacl.Target{othersTarget}))
	records = append(records, *generateRecord(eacl.ActionAllow, eacl.OperationRangeHash, []eacl.Target{othersTarget}))

	records = append(records, *generateRecord(eacl.ActionDeny, eacl.OperationGet, []eacl.Target{othersTarget}))
	records = append(records, *generateRecord(eacl.ActionDeny, eacl.OperationHead, []eacl.Target{othersTarget}))
	records = append(records, *generateRecord(eacl.ActionDeny, eacl.OperationPut, []eacl.Target{othersTarget}))
	records = append(records, *generateRecord(eacl.ActionDeny, eacl.OperationDelete, []eacl.Target{othersTarget}))
	records = append(records, *generateRecord(eacl.ActionDeny, eacl.OperationSearch, []eacl.Target{othersTarget}))
	records = append(records, *generateRecord(eacl.ActionDeny, eacl.OperationRange, []eacl.Target{othersTarget}))
	records = append(records, *generateRecord(eacl.ActionDeny, eacl.OperationRangeHash, []eacl.Target{othersTarget}))

	acl.EACL.SetRecords(records)

	logger, err := zap.NewProduction()
	require.NoError(t, err)

	acp := encodeObjectACL(logger, &acl, "bucket-name", "")
	require.NotNil(t, acp)

	require.Len(t, acp.AccessControlList, 2)

	required := []*Grant{
		{
			Grantee: &Grantee{
				Type: granteeGroup,
				URI:  allUsersGroup,
			},
			Permission: awsPermRead,
		},
		{
			Grantee: &Grantee{
				ID:          owner.String(),
				Type:        granteeCanonicalUser,
				DisplayName: s.UserID().String(),
			},
			Permission: awsPermFullControl,
		},
	}

	for _, g := range required {
		require.Contains(t, acp.AccessControlList, g)
	}
}

func TestPrincipal(t *testing.T) {
	type testCase struct {
		Principal principal `json:"p"`
	}

	t.Run("wildcard", func(t *testing.T) {
		payload := []byte(`{"p":"*"}`)

		var testObj testCase
		require.NoError(t, json.Unmarshal(payload, &testObj))
		require.Equal(t, allUsersWildcard, testObj.Principal.AWS)

		bts, err := json.Marshal(testObj)
		require.NoError(t, err)

		// we should be able to unmarshal string and structs, but marshals always a struct.
		payload = []byte(`{"p":{"AWS":"*"}}`)
		require.Equal(t, payload, bts)
	})

	t.Run("wildcard in struct", func(t *testing.T) {
		payload := []byte(`{"p":{"AWS":"*"}}`)

		var testObj testCase
		require.NoError(t, json.Unmarshal(payload, &testObj))
		require.Equal(t, allUsersWildcard, testObj.Principal.AWS)

		bts, err := json.Marshal(testObj)
		require.NoError(t, err)
		require.Equal(t, payload, bts)
	})
}
