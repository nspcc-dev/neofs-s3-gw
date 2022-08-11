package neofs

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/api/handler"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/stretchr/testify/require"
)

func TestTableToAst(t *testing.T) {
	neofs := NewNeoFS(nil)
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
	// Unknown role is used, because it is ignored when keys are set
	eacl.AddFormedTarget(record2, eacl.RoleUnknown, *(*ecdsa.PublicKey)(key.PublicKey()), *((*ecdsa.PublicKey)(key2.PublicKey())))
	record2.AddObjectAttributeFilter(eacl.MatchStringEqual, object.AttributeFileName, "objectName")
	record2.AddObjectIDFilter(eacl.MatchStringEqual, id)
	table.AddRecord(record2)

	expectedAst := &handler.Ast{
		Resources: []*handler.AstResource{
			{
				ResourceInfo: handler.ResourceInfo{Bucket: "bucketName"},
				Operations: []*handler.AstOperation{{
					Op:     eacl.OperationGet,
					Action: eacl.ActionAllow,
				}}},
			{
				ResourceInfo: handler.ResourceInfo{
					Bucket:  "bucketName",
					Object:  "objectName",
					Version: id.EncodeToString(),
				},
				Operations: []*handler.AstOperation{{
					Users: []string{
						hex.EncodeToString(key.PublicKey().Bytes()),
						hex.EncodeToString(key2.PublicKey().Bytes()),
					},
					Op:     eacl.OperationPut,
					Action: eacl.ActionDeny,
				}}},
		},
	}

	actualAst := neofs.TableToAst(table, expectedAst.Resources[0].Bucket)

	if actualAst.Resources[0].Name() == expectedAst.Resources[0].Name() {
		require.Equal(t, expectedAst, actualAst)
	} else {
		require.Equal(t, len(expectedAst.Resources), len(actualAst.Resources))
		require.Equal(t, expectedAst.Resources[0], actualAst.Resources[1])
		require.Equal(t, expectedAst.Resources[1], actualAst.Resources[0])
	}
}

func TestAstToTable(t *testing.T) {
	neofs := NewNeoFS(nil)
	key, err := keys.NewPrivateKey()
	require.NoError(t, err)

	ast := &handler.Ast{
		Resources: []*handler.AstResource{
			{
				ResourceInfo: handler.ResourceInfo{
					Bucket: "bucketName",
				},
				Operations: []*handler.AstOperation{{
					Users:  []string{hex.EncodeToString(key.PublicKey().Bytes())},
					Op:     eacl.OperationPut,
					Action: eacl.ActionAllow,
				}},
			},
			{
				ResourceInfo: handler.ResourceInfo{
					Bucket: "bucketName",
					Object: "objectName",
				},
				Operations: []*handler.AstOperation{{
					Op:     eacl.OperationGet,
					Action: eacl.ActionDeny,
				}},
			},
		},
	}

	expectedTable := eacl.NewTable()
	serviceRec1 := &serviceRecord{Resource: ast.Resources[0].Name(), GroupRecordsLength: 1}
	record1 := eacl.NewRecord()
	record1.SetAction(eacl.ActionAllow)
	record1.SetOperation(eacl.OperationPut)
	// Unknown role is used, because it is ignored when keys are set
	eacl.AddFormedTarget(record1, eacl.RoleUnknown, *(*ecdsa.PublicKey)(key.PublicKey()))

	serviceRec2 := &serviceRecord{Resource: ast.Resources[1].Name(), GroupRecordsLength: 1}
	record2 := eacl.NewRecord()
	record2.SetAction(eacl.ActionDeny)
	record2.SetOperation(eacl.OperationGet)
	eacl.AddFormedTarget(record2, eacl.RoleOthers)
	record2.AddObjectAttributeFilter(eacl.MatchStringEqual, object.AttributeFileName, "objectName")

	expectedTable.AddRecord(serviceRec2.ToEACLRecord())
	expectedTable.AddRecord(record2)
	expectedTable.AddRecord(serviceRec1.ToEACLRecord())
	expectedTable.AddRecord(record1)

	actualTable, err := neofs.AstToTable(ast)
	require.NoError(t, err)
	require.Equal(t, expectedTable, actualTable)
}

func TestOrder(t *testing.T) {
	neofs := NewNeoFS(nil)
	key, err := keys.NewPrivateKey()
	require.NoError(t, err)
	users := []string{hex.EncodeToString(key.PublicKey().Bytes())}
	targetUser := eacl.NewTarget()
	targetUser.SetBinaryKeys([][]byte{key.PublicKey().Bytes()})
	targetOther := eacl.NewTarget()
	targetOther.SetRole(eacl.RoleOthers)
	bucketName := "bucket"
	objectName := "objectName"

	expectedAst := &handler.Ast{
		Resources: []*handler.AstResource{
			{
				ResourceInfo: handler.ResourceInfo{
					Bucket: bucketName,
				},
				Operations: []*handler.AstOperation{
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
				ResourceInfo: handler.ResourceInfo{
					Bucket: bucketName,
					Object: objectName,
				},
				Operations: []*handler.AstOperation{
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
	bucketServiceRec := &serviceRecord{Resource: expectedAst.Resources[0].Name(), GroupRecordsLength: 2}
	bucketUsersGetRec := eacl.NewRecord()
	bucketUsersGetRec.SetOperation(eacl.OperationGet)
	bucketUsersGetRec.SetAction(eacl.ActionAllow)
	bucketUsersGetRec.SetTargets(*targetUser)
	bucketOtherGetRec := eacl.NewRecord()
	bucketOtherGetRec.SetOperation(eacl.OperationGet)
	bucketOtherGetRec.SetAction(eacl.ActionDeny)
	bucketOtherGetRec.SetTargets(*targetOther)
	objectServiceRec := &serviceRecord{Resource: expectedAst.Resources[1].Name(), GroupRecordsLength: 2}
	objectUsersPutRec := eacl.NewRecord()
	objectUsersPutRec.SetOperation(eacl.OperationPut)
	objectUsersPutRec.SetAction(eacl.ActionAllow)
	objectUsersPutRec.AddObjectAttributeFilter(eacl.MatchStringEqual, object.AttributeFileName, objectName)
	objectUsersPutRec.SetTargets(*targetUser)
	objectOtherPutRec := eacl.NewRecord()
	objectOtherPutRec.SetOperation(eacl.OperationPut)
	objectOtherPutRec.SetAction(eacl.ActionDeny)
	objectOtherPutRec.AddObjectAttributeFilter(eacl.MatchStringEqual, object.AttributeFileName, objectName)
	objectOtherPutRec.SetTargets(*targetOther)

	expectedEacl := eacl.NewTable()
	expectedEacl.AddRecord(objectServiceRec.ToEACLRecord())
	expectedEacl.AddRecord(objectOtherPutRec)
	expectedEacl.AddRecord(objectUsersPutRec)
	expectedEacl.AddRecord(bucketServiceRec.ToEACLRecord())
	expectedEacl.AddRecord(bucketOtherGetRec)
	expectedEacl.AddRecord(bucketUsersGetRec)

	t.Run("astToTable order and vice versa", func(t *testing.T) {
		actualEacl, err := neofs.AstToTable(expectedAst)
		require.NoError(t, err)
		require.Equal(t, expectedEacl, actualEacl)

		actualAst := neofs.TableToAst(actualEacl, bucketName)
		require.Equal(t, expectedAst, actualAst)
	})

	t.Run("tableToAst order and vice versa", func(t *testing.T) {
		actualAst := neofs.TableToAst(expectedEacl, bucketName)
		require.Equal(t, expectedAst, actualAst)

		actualEacl, err := neofs.AstToTable(actualAst)
		require.NoError(t, err)
		require.Equal(t, expectedEacl, actualEacl)
	})

	t.Run("append a resource", func(t *testing.T) {
		childName := "child"
		child := &handler.Ast{Resources: []*handler.AstResource{{
			ResourceInfo: handler.ResourceInfo{
				Bucket: bucketName,
				Object: childName,
			},
			Operations: []*handler.AstOperation{{Op: eacl.OperationDelete, Action: eacl.ActionDeny}}}},
		}

		childRecord := eacl.NewRecord()
		childRecord.SetOperation(eacl.OperationDelete)
		childRecord.SetAction(eacl.ActionDeny)
		childRecord.SetTargets(*targetOther)
		childRecord.AddObjectAttributeFilter(eacl.MatchStringEqual, object.AttributeFileName, childName)

		mergedAst, updated := handler.MergeAst(expectedAst, child)
		require.True(t, updated)

		mergedEacl, err := neofs.AstToTable(mergedAst)
		require.NoError(t, err)

		require.Equal(t, *childRecord, mergedEacl.Records()[1])
	})
}

func TestBucketAclToTable(t *testing.T) {
	neofs := NewNeoFS(nil)
	key, err := keys.NewPrivateKey()
	require.NoError(t, err)
	key2, err := keys.NewPrivateKey()
	require.NoError(t, err)

	id := hex.EncodeToString(key.PublicKey().Bytes())
	id2 := hex.EncodeToString(key2.PublicKey().Bytes())

	acl := &handler.AccessControlPolicy{
		Owner: handler.Owner{
			ID:          id,
			DisplayName: "user1",
		},
		AccessControlList: []*handler.Grant{{
			Grantee: &handler.Grantee{
				URI:  handler.AllUsersGroup,
				Type: handler.AcpGroup,
			},
			Permission: handler.ACLRead,
		}, {
			Grantee: &handler.Grantee{
				ID:   id2,
				Type: handler.AcpCanonicalUser,
			},
			Permission: handler.ACLWrite,
		}},
	}

	expectedTable := new(eacl.Table)
	for _, op := range handler.ReadOps {
		expectedTable.AddRecord(getOthersRecord(op, eacl.ActionAllow))
	}
	for _, op := range handler.WriteOps {
		expectedTable.AddRecord(getAllowRecord(op, key2.PublicKey()))
	}
	for _, op := range handler.FullOps {
		expectedTable.AddRecord(getAllowRecord(op, key.PublicKey()))
	}
	for _, op := range handler.FullOps {
		expectedTable.AddRecord(getOthersRecord(op, eacl.ActionDeny))
	}
	resInfo := &handler.ResourceInfo{
		Bucket: "bucketName",
	}

	actualTable, err := neofs.BucketACLToTable(acl, resInfo)
	require.NoError(t, err)
	require.Equal(t, expectedTable.Records(), actualTable.Records())
}
