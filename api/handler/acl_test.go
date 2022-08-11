package handler

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"testing"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/stretchr/testify/require"
)

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

	expectedAst := &Ast{
		Resources: []*AstResource{
			{
				ResourceInfo: ResourceInfo{
					Bucket: "bucketName",
				},
				Operations: []*AstOperation{{
					Op:     eacl.OperationPut,
					Action: eacl.ActionAllow,
				}},
			},
			{
				ResourceInfo: ResourceInfo{
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

func getReadOps(key *keys.PrivateKey, groupGrantee bool, action eacl.Action) []*AstOperation {
	var (
		result []*AstOperation
		users  []string
	)
	if !groupGrantee {
		users = append(users, hex.EncodeToString(key.PublicKey().Bytes()))
	}

	for _, op := range ReadOps {
		result = append(result, &AstOperation{
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

	child := &Ast{
		Resources: []*AstResource{
			{
				ResourceInfo: ResourceInfo{
					Bucket: "bucket",
					Object: "objectName",
				},
				Operations: []*AstOperation{{
					Users:  []string{hex.EncodeToString(key.PublicKey().Bytes())},
					Op:     eacl.OperationPut,
					Action: eacl.ActionDeny,
				}},
			},
		},
	}

	parent := &Ast{
		Resources: []*AstResource{
			{
				ResourceInfo: ResourceInfo{
					Bucket: "bucket",
				},
				Operations: []*AstOperation{{
					Op:     eacl.OperationGet,
					Action: eacl.ActionAllow,
				}},
			},
			child.Resources[0],
		},
	}

	result, updated := MergeAst(parent, child)
	require.False(t, updated)
	require.Equal(t, parent, result)
}

func TestMergeAstModified(t *testing.T) {
	child := &Ast{
		Resources: []*AstResource{
			{
				ResourceInfo: ResourceInfo{
					Bucket: "bucket",
					Object: "objectName",
				},
				Operations: []*AstOperation{{
					Op:     eacl.OperationPut,
					Action: eacl.ActionDeny,
				}, {
					Users:  []string{"user2"},
					Op:     eacl.OperationGet,
					Action: eacl.ActionDeny,
				}},
			},
		},
	}

	parent := &Ast{
		Resources: []*AstResource{
			{
				ResourceInfo: ResourceInfo{
					Bucket: "bucket",
					Object: "objectName",
				},
				Operations: []*AstOperation{{
					Users:  []string{"user1"},
					Op:     eacl.OperationGet,
					Action: eacl.ActionDeny,
				}},
			},
		},
	}

	expected := &Ast{
		Resources: []*AstResource{
			{
				ResourceInfo: ResourceInfo{
					Bucket: "bucket",
					Object: "objectName",
				},
				Operations: []*AstOperation{
					child.Resources[0].Operations[0],
					{
						Users:  []string{"user1", "user2"},
						Op:     eacl.OperationGet,
						Action: eacl.ActionDeny,
					},
				},
			},
		},
	}

	actual, updated := MergeAst(parent, child)
	require.True(t, updated)
	require.Equal(t, expected, actual)
}

func TestMergeAppended(t *testing.T) {
	key, err := keys.NewPrivateKey()
	require.NoError(t, err)
	users := []string{hex.EncodeToString(key.PublicKey().Bytes())}

	parent := &Ast{
		Resources: []*AstResource{
			{
				ResourceInfo: ResourceInfo{
					Bucket: "bucket",
				},
				Operations: []*AstOperation{
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

	child := &Ast{
		Resources: []*AstResource{
			{
				ResourceInfo: ResourceInfo{
					Bucket: "bucket",
					Object: "objectName",
				},
				Operations: []*AstOperation{
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

	expected := &Ast{
		Resources: []*AstResource{
			{
				ResourceInfo: ResourceInfo{
					Bucket: "bucket",
				},
				Operations: []*AstOperation{
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
				ResourceInfo: ResourceInfo{
					Bucket: "bucket",
					Object: "objectName",
				},
				Operations: []*AstOperation{
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
	actual, updated := MergeAst(parent, child)
	require.True(t, updated)
	require.Equal(t, expected, actual)
}

func TestMergeAstModifiedConflict(t *testing.T) {
	child := &Ast{
		Resources: []*AstResource{
			{
				ResourceInfo: ResourceInfo{
					Bucket: "bucket",
					Object: "objectName",
				},
				Operations: []*AstOperation{{
					Users:  []string{"user1"},
					Op:     eacl.OperationPut,
					Action: eacl.ActionDeny,
				}, {
					Users:  []string{"user3"},
					Op:     eacl.OperationGet,
					Action: eacl.ActionAllow,
				}},
			},
		},
	}

	parent := &Ast{
		Resources: []*AstResource{
			{
				ResourceInfo: ResourceInfo{
					Bucket: "bucket",
					Object: "objectName",
				},
				Operations: []*AstOperation{{
					Users:  []string{"user1"},
					Op:     eacl.OperationPut,
					Action: eacl.ActionAllow,
				}, {
					Users:  []string{"user2"},
					Op:     eacl.OperationPut,
					Action: eacl.ActionDeny,
				}, {
					Users:  []string{"user3"},
					Op:     eacl.OperationGet,
					Action: eacl.ActionDeny,
				}},
			},
		},
	}

	expected := &Ast{
		Resources: []*AstResource{
			{
				ResourceInfo: ResourceInfo{
					Bucket: "bucket",
					Object: "objectName",
				},
				Operations: []*AstOperation{
					{
						Users:  []string{"user2", "user1"},
						Op:     eacl.OperationPut,
						Action: eacl.ActionDeny,
					}, {
						Users:  []string{"user3"},
						Op:     eacl.OperationGet,
						Action: eacl.ActionAllow,
					},
				},
			},
		},
	}

	actual, updated := MergeAst(parent, child)
	require.True(t, updated)
	require.Equal(t, expected, actual)
}

func TestRemoveUsers(t *testing.T) {
	resource := &AstResource{
		ResourceInfo: ResourceInfo{
			Bucket: "bucket",
		},
		Operations: []*AstOperation{{
			Users:  []string{"user1", "user3", "user4"},
			Op:     eacl.OperationPut,
			Action: eacl.ActionAllow,
		},
			{
				Users:  []string{"user5"},
				Op:     eacl.OperationGet,
				Action: eacl.ActionDeny,
			},
		},
	}

	op1 := &AstOperation{
		Op:     eacl.OperationPut,
		Action: eacl.ActionAllow,
	}
	op2 := &AstOperation{
		Op:     eacl.OperationGet,
		Action: eacl.ActionDeny,
	}

	removeUsers(resource, op1, []string{"user1", "user2", "user4"}) // modify AstOperation
	removeUsers(resource, op2, []string{"user5"})                   // remove AstOperation

	require.Equal(t, len(resource.Operations), 1)
	require.Equal(t, []string{"user3"}, resource.Operations[0].Users)
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
				URI:  AllUsersGroup,
				Type: AcpGroup,
			},
			Permission: ACLRead,
		}, {
			Grantee: &Grantee{
				ID:   id2,
				Type: AcpCanonicalUser,
			},
			Permission: ACLWrite,
		}},
	}

	resInfo := &ResourceInfo{
		Bucket: "bucketName",
	}

	expectedPolicy := &bucketPolicy{
		Bucket: resInfo.Bucket,
		Statement: []statement{
			{
				Effect: "Allow",
				Principal: principal{
					CanonicalUser: id,
				},
				Action:   []string{"s3:ListBucket", "s3:ListBucketVersions", "s3:ListBucketMultipartUploads", "s3:PutObject", "s3:DeleteObject"},
				Resource: []string{arnAwsPrefix + resInfo.Name()},
			},
			{
				Effect:    "Allow",
				Principal: principal{AWS: allUsersWildcard},
				Action:    []string{"s3:ListBucket", "s3:ListBucketVersions", "s3:ListBucketMultipartUploads"},
				Resource:  []string{arnAwsPrefix + resInfo.Name()},
			},
			{
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
				Type: AcpCanonicalUser,
			},
			Permission: ACLFullControl,
		}, {
			Grantee: &Grantee{
				ID:   id2,
				Type: AcpCanonicalUser,
			},
			Permission: ACLFullControl,
		}, {
			Grantee: &Grantee{
				URI:  AllUsersGroup,
				Type: AcpGroup,
			},
			Permission: ACLRead,
		}},
	}

	resInfo := &ResourceInfo{
		Bucket: "bucketName",
		Object: "object",
	}

	expectedPolicy := &bucketPolicy{
		Bucket: resInfo.Bucket,
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
			},
			{
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
				Type:        AcpCanonicalUser,
			},
			Permission: ACLFullControl,
		}, {
			Grantee: &Grantee{
				URI:  AllUsersGroup,
				Type: AcpGroup,
			},
			Permission: ACLRead,
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
			api.AmzGrantRead:        {"uri=\"" + AllUsersGroup + "\", id=\"user2\""},
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
				Type:        AcpCanonicalUser,
			},
			Permission: ACLFullControl,
		}, {
			Grantee: &Grantee{
				ID:   "user1",
				Type: AcpCanonicalUser,
			},
			Permission: ACLFullControl,
		}, {
			Grantee: &Grantee{
				URI:  AllUsersGroup,
				Type: AcpGroup,
			},
			Permission: ACLRead,
		}, {
			Grantee: &Grantee{
				ID:   "user2",
				Type: AcpCanonicalUser,
			},
			Permission: ACLRead,
		}, {
			Grantee: &Grantee{
				ID:   "user2",
				Type: AcpCanonicalUser,
			},
			Permission: ACLWrite,
		}, {
			Grantee: &Grantee{
				ID:   "user3",
				Type: AcpCanonicalUser,
			},
			Permission: ACLWrite,
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
				Type: AcpCanonicalUser,
			},
			Permission: ACLFullControl,
		}, {
			Grantee: &Grantee{
				ID:   id2,
				Type: AcpCanonicalUser,
			},
			Permission: ACLRead,
		},
		},
	}

	resInfo := &ResourceInfo{
		Bucket:  "bucketName",
		Object:  "object",
		Version: objID.EncodeToString(),
	}

	var operations []*AstOperation
	for _, op := range ReadOps {
		astOp := &AstOperation{Users: []string{
			hex.EncodeToString(key.PublicKey().Bytes()),
			hex.EncodeToString(key2.PublicKey().Bytes()),
		},
			Op:     op,
			Action: eacl.ActionAllow,
		}
		operations = append(operations, astOp)
	}

	expectedAst := &Ast{
		Resources: []*AstResource{
			{
				ResourceInfo: *resInfo,
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
					Type: AcpCanonicalUser,
				},
				Permission: ACLWrite,
			}, {
				Grantee: &Grantee{
					URI:  AllUsersGroup,
					Type: AcpGroup,
				},
				Permission: ACLRead,
			},
		},
	}

	var operations []*AstOperation
	for _, op := range ReadOps {
		astOp := &AstOperation{Users: []string{
			hex.EncodeToString(key.PublicKey().Bytes()),
		},
			Op:     op,
			Action: eacl.ActionAllow,
		}
		operations = append(operations, astOp)
	}
	for _, op := range WriteOps {
		astOp := &AstOperation{Users: []string{
			hex.EncodeToString(key.PublicKey().Bytes()),
			hex.EncodeToString(key2.PublicKey().Bytes()),
		},
			Op:     op,
			Action: eacl.ActionAllow,
		}
		operations = append(operations, astOp)
	}
	for _, op := range ReadOps {
		astOp := &AstOperation{
			Op:     op,
			Action: eacl.ActionAllow,
		}
		operations = append(operations, astOp)
	}

	resInfo := &ResourceInfo{Bucket: "bucketName"}

	expectedAst := &Ast{
		Resources: []*AstResource{
			{
				ResourceInfo: *resInfo,
				Operations:   operations,
			},
		},
	}

	actualAst, err := aclToAst(acl, resInfo)
	require.NoError(t, err)
	require.Equal(t, expectedAst, actualAst)
}
