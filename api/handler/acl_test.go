package handler

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"testing"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/stretchr/testify/require"
)

func TestTableToAst(t *testing.T) {
	b := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, b)
	require.NoError(t, err)
	var id oid.ID
	id.SetSHA256(sha256.Sum256(b))

	key, err := keys.NewPrivateKey()
	require.NoError(t, err)
	key2, err := keys.NewPrivateKey()
	require.NoError(t, err)

	table := new(eacl.Table)
	record := eacl.NewRecord()
	record.SetAction(eacl.ActionAllow)
	record.SetOperation(eacl.OperationGet)
	eacl.AddFormedTarget(record, eacl.RoleOthers)
	table.AddRecord(record)
	record2 := eacl.NewRecord()
	record2.SetAction(eacl.ActionDeny)
	record2.SetOperation(eacl.OperationPut)
	eacl.AddFormedTarget(record2, eacl.RoleUser, *(*ecdsa.PublicKey)(key.PublicKey()))
	eacl.AddFormedTarget(record2, eacl.RoleUser, *(*ecdsa.PublicKey)(key2.PublicKey()))
	record2.AddObjectAttributeFilter(eacl.MatchStringEqual, object.AttributeFileName, "objectName")
	record2.AddObjectIDFilter(eacl.MatchStringEqual, id)
	table.AddRecord(record2)

	expectedAst := &ast{
		Resources: []*astResource{
			{
				resourceInfo: resourceInfo{Bucket: "bucketName"},
				Operations: []*astOperation{{
					Role:   eacl.RoleOthers,
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
					Users: []string{
						hex.EncodeToString(key.PublicKey().Bytes()),
						hex.EncodeToString(key2.PublicKey().Bytes()),
					},
					Role:   eacl.RoleUser,
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
				Action:    []string{"s3:PutObject"},
				Resource:  []string{"arn:aws:s3:::bucketName"},
			},
			{
				Effect: "Deny",
				Principal: principal{
					CanonicalUser: hex.EncodeToString(key.PublicKey().Bytes()),
				},
				Action:   []string{"s3:GetObject"},
				Resource: []string{"arn:aws:s3:::bucketName/object"},
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
					Role:   eacl.RoleOthers,
					Op:     eacl.OperationPut,
					Action: eacl.ActionAllow,
				}},
			},
			{
				resourceInfo: resourceInfo{
					Bucket: "bucketName",
					Object: "object",
				},
				Operations: getReadOps(key, eacl.RoleUser, eacl.ActionDeny),
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

func getReadOps(key *keys.PrivateKey, role eacl.Role, action eacl.Action) []*astOperation {
	var result []*astOperation

	for _, op := range readOps {
		result = append(result, &astOperation{
			Users:  []string{hex.EncodeToString(key.PublicKey().Bytes())},
			Role:   role,
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
					Users:  []string{hex.EncodeToString(key.PublicKey().Bytes())},
					Role:   eacl.RoleUser,
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
					Role:   eacl.RoleOthers,
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
	child := &ast{
		Resources: []*astResource{
			{
				resourceInfo: resourceInfo{
					Bucket: "bucket",
					Object: "objectName",
				},
				Operations: []*astOperation{{
					Role:   eacl.RoleOthers,
					Op:     eacl.OperationPut,
					Action: eacl.ActionDeny,
				}, {
					Users:  []string{"user2"},
					Role:   eacl.RoleUser,
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
					Users:  []string{"user1"},
					Role:   eacl.RoleUser,
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
						Users:  []string{"user1", "user2"},
						Role:   eacl.RoleUser,
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

func TestMergeAstModifiedConflict(t *testing.T) {
	child := &ast{
		Resources: []*astResource{
			{
				resourceInfo: resourceInfo{
					Bucket: "bucket",
					Object: "objectName",
				},
				Operations: []*astOperation{{
					Users:  []string{"user1"},
					Role:   eacl.RoleUser,
					Op:     eacl.OperationPut,
					Action: eacl.ActionDeny,
				}, {
					Users:  []string{"user3"},
					Role:   eacl.RoleUser,
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
					Users:  []string{"user1"},
					Role:   eacl.RoleUser,
					Op:     eacl.OperationPut,
					Action: eacl.ActionAllow,
				}, {
					Users:  []string{"user2"},
					Role:   eacl.RoleUser,
					Op:     eacl.OperationPut,
					Action: eacl.ActionDeny,
				}, {
					Users:  []string{"user3"},
					Role:   eacl.RoleUser,
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
						Users:  []string{"user2", "user1"},
						Role:   eacl.RoleUser,
						Op:     eacl.OperationPut,
						Action: eacl.ActionDeny,
					}, {
						Users:  []string{"user3"},
						Role:   eacl.RoleUser,
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
					Users:  []string{hex.EncodeToString(key.PublicKey().Bytes())},
					Role:   eacl.RoleUser,
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
					Role:   eacl.RoleOthers,
					Op:     eacl.OperationGet,
					Action: eacl.ActionDeny,
				}},
			},
		},
	}

	expectedTable := eacl.NewTable()
	record := eacl.NewRecord()
	record.SetAction(eacl.ActionAllow)
	record.SetOperation(eacl.OperationPut)
	eacl.AddFormedTarget(record, eacl.RoleUser, *(*ecdsa.PublicKey)(key.PublicKey()))
	expectedTable.AddRecord(record)
	record2 := eacl.NewRecord()
	record2.SetAction(eacl.ActionDeny)
	record2.SetOperation(eacl.OperationGet)
	eacl.AddFormedTarget(record2, eacl.RoleOthers)
	record2.AddObjectAttributeFilter(eacl.MatchStringEqual, object.AttributeFileName, "objectName")
	expectedTable.AddRecord(record2)

	actualTable, err := astToTable(ast)
	require.NoError(t, err)
	require.Equal(t, expectedTable, actualTable)
}

func TestRemoveUsers(t *testing.T) {
	resource := &astResource{
		resourceInfo: resourceInfo{
			Bucket: "bucket",
		},
		Operations: []*astOperation{{
			Users:  []string{"user1", "user3"},
			Role:   eacl.RoleUser,
			Op:     eacl.OperationPut,
			Action: eacl.ActionAllow,
		}},
	}

	op := &astOperation{
		Role:   eacl.RoleUser,
		Op:     eacl.OperationPut,
		Action: eacl.ActionAllow,
	}

	removeUsers(resource, op, []string{"user1", "user2"})

	require.Equal(t, len(resource.Operations), 1)
	require.Equal(t, resource.Name(), resource.Name())
	require.Equal(t, resource.Operations[0].Users, []string{"user3"})
}

func TestBucketAclToPolicy(t *testing.T) {
	key, err := keys.NewPrivateKey()
	require.NoError(t, err)
	key2, err := keys.NewPrivateKey()
	require.NoError(t, err)

	id := hex.EncodeToString(key.PublicKey().Bytes())
	id2 := hex.EncodeToString(key2.PublicKey().Bytes())

	acl := &AccessControlPolicy{
		Owner: Owner{
			ID:          id,
			DisplayName: "user1",
		},
		AccessControlList: []*Grant{{
			Grantee: &Grantee{
				URI:  allUsersGroup,
				Type: acpGroup,
			},
			Permission: aclRead,
		}, {
			Grantee: &Grantee{
				ID:   id2,
				Type: acpCanonicalUser,
			},
			Permission: aclWrite,
		}},
	}

	resInfo := &resourceInfo{
		Bucket: "bucketName",
	}

	expectedPolicy := &bucketPolicy{
		Statement: []statement{
			{
				Effect: "Allow",
				Principal: principal{
					CanonicalUser: id,
				},
				Action:   []string{"s3:ListBucket", "s3:ListBucketVersions", "s3:ListBucketMultipartUploads", "s3:PutObject", "s3:DeleteObject"},
				Resource: []string{arnAwsPrefix + resInfo.Name()},
			}, {
				Effect:    "Allow",
				Principal: principal{AWS: allUsersWildcard},
				Action:    []string{"s3:ListBucket", "s3:ListBucketVersions", "s3:ListBucketMultipartUploads"},
				Resource:  []string{arnAwsPrefix + resInfo.Name()},
			}, {
				Effect: "Allow",
				Principal: principal{
					CanonicalUser: id2,
				},
				Action:   []string{"s3:PutObject", "s3:DeleteObject"},
				Resource: []string{arnAwsPrefix + resInfo.Name()},
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

	id := hex.EncodeToString(key.PublicKey().Bytes())
	id2 := hex.EncodeToString(key2.PublicKey().Bytes())

	acl := &AccessControlPolicy{
		Owner: Owner{
			ID:          id,
			DisplayName: "user1",
		},
		AccessControlList: []*Grant{{
			Grantee: &Grantee{
				ID:   id,
				Type: acpCanonicalUser,
			},
			Permission: aclFullControl,
		}, {
			Grantee: &Grantee{
				ID:   id2,
				Type: acpCanonicalUser,
			},
			Permission: aclFullControl,
		}, {
			Grantee: &Grantee{
				URI:  allUsersGroup,
				Type: acpGroup,
			},
			Permission: aclRead,
		}},
	}

	resInfo := &resourceInfo{
		Bucket: "bucketName",
		Object: "object",
	}

	expectedPolicy := &bucketPolicy{
		Statement: []statement{
			{
				Effect: "Allow",
				Principal: principal{
					CanonicalUser: id,
				},
				Action:   []string{"s3:GetObject", "s3:GetObjectVersion"},
				Resource: []string{arnAwsPrefix + resInfo.Name()},
			},
			{
				Effect: "Allow",
				Principal: principal{
					CanonicalUser: id2,
				},
				Action:   []string{"s3:GetObject", "s3:GetObjectVersion"},
				Resource: []string{arnAwsPrefix + resInfo.Name()},
			}, {
				Effect:    "Allow",
				Principal: principal{AWS: allUsersWildcard},
				Action:    []string{"s3:GetObject", "s3:GetObjectVersion"},
				Resource:  []string{arnAwsPrefix + resInfo.Name()},
			},
		},
	}

	actualPolicy, err := aclToPolicy(acl, resInfo)
	require.NoError(t, err)
	require.Equal(t, expectedPolicy, actualPolicy)
}

func TestParseCannedACLHeaders(t *testing.T) {
	key, err := keys.NewPrivateKey()
	require.NoError(t, err)

	id := hex.EncodeToString(key.PublicKey().Bytes())
	address := key.PublicKey().Address()

	req := &http.Request{
		Header: map[string][]string{
			api.AmzACL: {basicACLReadOnly},
		},
	}

	expectedACL := &AccessControlPolicy{
		Owner: Owner{
			ID:          id,
			DisplayName: address,
		},
		AccessControlList: []*Grant{{
			Grantee: &Grantee{
				ID:          id,
				DisplayName: address,
				Type:        acpCanonicalUser,
			},
			Permission: aclFullControl,
		}, {
			Grantee: &Grantee{
				URI:  allUsersGroup,
				Type: acpGroup,
			},
			Permission: aclRead,
		}},
	}

	actualACL, err := parseACLHeaders(req.Header, key.PublicKey())
	require.NoError(t, err)
	require.Equal(t, expectedACL, actualACL)
}

func TestParseACLHeaders(t *testing.T) {
	key, err := keys.NewPrivateKey()
	require.NoError(t, err)

	id := hex.EncodeToString(key.PublicKey().Bytes())
	address := key.PublicKey().Address()

	req := &http.Request{
		Header: map[string][]string{
			api.AmzGrantFullControl: {"id=\"user1\""},
			api.AmzGrantRead:        {"uri=\"" + allUsersGroup + "\", id=\"user2\""},
			api.AmzGrantWrite:       {"id=\"user2\", id=\"user3\""},
		},
	}

	expectedACL := &AccessControlPolicy{
		Owner: Owner{
			ID:          id,
			DisplayName: address,
		},
		AccessControlList: []*Grant{{
			Grantee: &Grantee{
				ID:          id,
				DisplayName: address,
				Type:        acpCanonicalUser,
			},
			Permission: aclFullControl,
		}, {
			Grantee: &Grantee{
				ID:   "user1",
				Type: acpCanonicalUser,
			},
			Permission: aclFullControl,
		}, {
			Grantee: &Grantee{
				URI:  allUsersGroup,
				Type: acpGroup,
			},
			Permission: aclRead,
		}, {
			Grantee: &Grantee{
				ID:   "user2",
				Type: acpCanonicalUser,
			},
			Permission: aclRead,
		}, {
			Grantee: &Grantee{
				ID:   "user2",
				Type: acpCanonicalUser,
			},
			Permission: aclWrite,
		}, {
			Grantee: &Grantee{
				ID:   "user3",
				Type: acpCanonicalUser,
			},
			Permission: aclWrite,
		}},
	}

	actualACL, err := parseACLHeaders(req.Header, key.PublicKey())
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

	id := hex.EncodeToString(key.PublicKey().Bytes())
	id2 := hex.EncodeToString(key2.PublicKey().Bytes())

	acl := &AccessControlPolicy{
		Owner: Owner{
			ID:          id,
			DisplayName: "user1",
		},
		AccessControlList: []*Grant{{
			Grantee: &Grantee{
				URI:  allUsersGroup,
				Type: acpGroup,
			},
			Permission: aclRead,
		}, {
			Grantee: &Grantee{
				ID:   id2,
				Type: acpCanonicalUser,
			},
			Permission: aclWrite,
		}},
	}

	expectedTable := new(eacl.Table)
	for _, op := range readOps {
		expectedTable.AddRecord(getOthersRecord(op, eacl.ActionAllow))
	}
	for _, op := range writeOps {
		expectedTable.AddRecord(getAllowRecord(op, key2.PublicKey()))
	}
	for _, op := range fullOps {
		expectedTable.AddRecord(getAllowRecord(op, key.PublicKey()))
	}
	for _, op := range fullOps {
		expectedTable.AddRecord(getOthersRecord(op, eacl.ActionDeny))
	}
	resInfo := &resourceInfo{
		Bucket: "bucketName",
	}

	actualTable, err := bucketACLToTable(acl, resInfo)
	require.NoError(t, err)
	require.Equal(t, expectedTable.Records(), actualTable.Records())
}

func TestObjectAclToAst(t *testing.T) {
	b := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, b)
	require.NoError(t, err)
	var objID oid.ID
	objID.SetSHA256(sha256.Sum256(b))

	key, err := keys.NewPrivateKey()
	require.NoError(t, err)
	key2, err := keys.NewPrivateKey()
	require.NoError(t, err)

	id := hex.EncodeToString(key.PublicKey().Bytes())
	id2 := hex.EncodeToString(key2.PublicKey().Bytes())

	acl := &AccessControlPolicy{
		Owner: Owner{
			ID:          id,
			DisplayName: "user1",
		},
		AccessControlList: []*Grant{{
			Grantee: &Grantee{
				ID:   id,
				Type: acpCanonicalUser,
			},
			Permission: aclFullControl,
		}, {
			Grantee: &Grantee{
				ID:   id2,
				Type: acpCanonicalUser,
			},
			Permission: aclRead,
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
		astOp := &astOperation{Users: []string{
			hex.EncodeToString(key.PublicKey().Bytes()),
			hex.EncodeToString(key2.PublicKey().Bytes()),
		},
			Role:   eacl.RoleUser,
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
	var objID oid.ID
	objID.SetSHA256(sha256.Sum256(b))

	key, err := keys.NewPrivateKey()
	require.NoError(t, err)
	key2, err := keys.NewPrivateKey()
	require.NoError(t, err)

	id := hex.EncodeToString(key.PublicKey().Bytes())
	id2 := hex.EncodeToString(key2.PublicKey().Bytes())

	acl := &AccessControlPolicy{
		Owner: Owner{
			ID:          id,
			DisplayName: "user1",
		},
		AccessControlList: []*Grant{
			{
				Grantee: &Grantee{
					ID:   id2,
					Type: acpCanonicalUser,
				},
				Permission: aclWrite,
			}, {
				Grantee: &Grantee{
					URI:  allUsersGroup,
					Type: acpGroup,
				},
				Permission: aclRead,
			},
		},
	}

	var operations []*astOperation
	for _, op := range readOps {
		astOp := &astOperation{Users: []string{
			hex.EncodeToString(key.PublicKey().Bytes()),
		},
			Role:   eacl.RoleUser,
			Op:     op,
			Action: eacl.ActionAllow,
		}
		operations = append(operations, astOp)
	}
	for _, op := range writeOps {
		astOp := &astOperation{Users: []string{
			hex.EncodeToString(key.PublicKey().Bytes()),
			hex.EncodeToString(key2.PublicKey().Bytes()),
		},
			Role:   eacl.RoleUser,
			Op:     op,
			Action: eacl.ActionAllow,
		}
		operations = append(operations, astOp)
	}
	for _, op := range readOps {
		astOp := &astOperation{
			Role:   eacl.RoleOthers,
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
