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
	"slices"
	"strings"
	"testing"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3errors"
	"github.com/nspcc-dev/neofs-s3-gw/creds/accessbox"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	neofscryptotest "github.com/nspcc-dev/neofs-sdk-go/crypto/test"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	usertest "github.com/nspcc-dev/neofs-sdk-go/user/test"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestTableToAst(t *testing.T) {
	b := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, b)
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
					Op:      eacl.OperationGet,
					Action:  eacl.ActionAllow,
					Grantee: astGranteeRoleOthers,
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
					Op:      eacl.OperationPut,
					Action:  eacl.ActionAllow,
					Grantee: astGranteeRoleOthers,
				}},
			},
			{
				resourceInfo: resourceInfo{
					Bucket: "bucketName",
					Object: "object",
				},
				Operations: getReadOps(key, astGranteeAccount, eacl.ActionDeny),
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

func TestTaggingPolicyToAst(t *testing.T) {
	for _, tc := range []struct {
		action string
		ops    []eacl.Operation
	}{
		{action: s3GetObjectTagging, ops: readOps},
		{action: s3PutObjectTagging, ops: []eacl.Operation{eacl.OperationPut, eacl.OperationSearch}},
	} {
		t.Run(tc.action, func(t *testing.T) {
			policy := &bucketPolicy{
				Bucket: "bucketName",
				Statement: []statement{{
					Effect:    "Allow",
					Principal: principal{AWS: allUsersWildcard},
					Action:    stringOrSlice{values: []string{tc.action}},
					Resource:  stringOrSlice{values: []string{"arn:aws:s3:::bucketName/object"}},
				}},
			}

			actualAst, err := policyToAst(policy)
			require.NoError(t, err)
			require.Len(t, actualAst.Resources, 1)
			require.Equal(t, resourceInfo{Bucket: "bucketName", Object: "object"}, actualAst.Resources[0].resourceInfo)

			var ops []eacl.Operation
			for _, op := range actualAst.Resources[0].Operations {
				require.Equal(t, eacl.ActionAllow, op.Action)
				require.Equal(t, astGranteeRoleOthers, op.Grantee)
				ops = append(ops, op.Op)
			}
			require.Equal(t, tc.ops, ops)
		})
	}
}

func TestPolicyToAstUnsupportedElements(t *testing.T) {
	const ownerFullControl = `"Effect":"Allow","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::bucketName/*",` +
		`"Condition":{"StringEquals":{"s3:x-amz-acl":"bucket-owner-full-control"`

	for name, state := range map[string]string{
		"condition":                              `"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucketName/obj","Condition":{"StringEquals":{"s3:x-amz-acl":"public-read"}}`,
		"not resource":                           `"Effect":"Deny","Principal":"*","Action":"s3:GetObject","NotResource":"arn:aws:s3:::bucketName/obj"`,
		"not action":                             `"Effect":"Allow","Principal":"*","NotAction":"s3:DeleteObject","Resource":"arn:aws:s3:::bucketName/obj"`,
		"not principal":                          `"Effect":"Deny","NotPrincipal":{"AWS":"*"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::bucketName/obj"`,
		"owner full control with extra key":      ownerFullControl + `,"s3:prefix":"public/"}}`,
		"owner full control with extra operator": ownerFullControl + `},"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}`,
		"owner full control with not resource":   ownerFullControl + `}},"NotResource":"arn:aws:s3:::bucketName/secret"`,
	} {
		t.Run(name, func(t *testing.T) {
			policy := &bucketPolicy{Bucket: "bucketName"}
			require.NoError(t, json.Unmarshal([]byte(`{"Statement":[{`+state+`}]}`), policy))

			_, err := policyToAst(policy)
			require.True(t, s3errors.IsS3Error(err, s3errors.ErrUnsupportedPolicy), err)
		})
	}

	t.Run("owner full control", func(t *testing.T) {
		policy := &bucketPolicy{Bucket: "bucketName"}
		require.NoError(t, json.Unmarshal([]byte(`{"Statement":[{`+ownerFullControl+`}}}]}`), policy))

		actualAst, err := policyToAst(policy)
		require.NoError(t, err)
		require.Len(t, actualAst.Resources, 1)
		require.Equal(t, s3ConditionXAmzACL, actualAst.Resources[0].Object)
	})
}

func TestPolicyToAstActions(t *testing.T) {
	policyWith := func(t *testing.T, effect, action string) *bucketPolicy {
		policy := &bucketPolicy{Bucket: "bucketName"}
		require.NoError(t, json.Unmarshal([]byte(`{"Statement":[{"Effect":"`+effect+`","Principal":"*","Action":`+action+
			`,"Resource":"arn:aws:s3:::bucketName/*"}]}`), policy))
		return policy
	}

	for _, effect := range []string{"Allow", "Deny"} {
		for name, tc := range map[string]struct {
			action string
			ops    []eacl.Operation
		}{
			"s3 wildcard":       {action: `"s3:*"`, ops: fullOps},
			"wildcard":          {action: `"*"`, ops: fullOps},
			"wildcard in list":  {action: `["s3:GetObject","s3:*"]`, ops: fullOps},
			"supported actions": {action: `["s3:PutObject","s3:DeleteObject"]`, ops: writeOps},
		} {
			t.Run(effect+" "+name, func(t *testing.T) {
				actualAst, err := policyToAst(policyWith(t, effect, tc.action))
				require.NoError(t, err)
				require.Len(t, actualAst.Resources, 1)

				var ops []eacl.Operation
				for _, op := range actualAst.Resources[0].Operations {
					require.Equal(t, effectToAction(effect), op.Action)
					require.Equal(t, astGranteeRoleOthers, op.Grantee)
					ops = append(ops, op.Op)
				}
				require.ElementsMatch(t, tc.ops, ops)
			})
		}
	}

	for name, action := range map[string]string{
		"unknown":           `"s3:GetBucketLocation"`,
		"object version":    `"s3:GetObjectVersion"`,
		"multipart uploads": `["s3:ListBucket","s3:ListBucketMultipartUploads"]`,
		"prefix wildcard":   `"s3:Get*"`,
		"unknown in list":   `["s3:GetObject","s3:Bogus"]`,
		"wildcard and list": `["s3:*","s3:Bogus"]`,
	} {
		t.Run("Deny "+name, func(t *testing.T) {
			_, err := policyToAst(policyWith(t, "Deny", action))
			require.True(t, s3errors.IsS3Error(err, s3errors.ErrUnsupportedPolicy), err)
		})

		t.Run("Allow "+name, func(t *testing.T) {
			_, err := policyToAst(policyWith(t, "Allow", action))
			require.NoError(t, err)
		})
	}
}

func TestPolicyToAstInvalidEffect(t *testing.T) {
	for _, effect := range []string{"", "deny", "allow", "Reject"} {
		t.Run(effect, func(t *testing.T) {
			policy := &bucketPolicy{Bucket: "bucketName"}
			require.NoError(t, json.Unmarshal([]byte(`{"Statement":[{"Effect":"`+effect+
				`","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::bucketName"}]}`), policy))

			_, err := policyToAst(policy)
			require.True(t, s3errors.IsS3Error(err, s3errors.ErrMalformedPolicy), err)
		})
	}
}

func TestPolicyToAstDenyWins(t *testing.T) {
	const (
		userA = "NiskPF9pfRMzg7V7PeB4d6ogLzu74a1L2Q"
		userB = "NbUgTSFvPmsRxmGeWpuuGeJUoRoi6PErcM"
	)

	statement := func(effect, principal, action string) string {
		return `{"Effect":"` + effect + `","Principal":` + principal + `,"Action":"` + action + `","Resource":"arn:aws:s3:::bucketName"}`
	}
	canonical := func(id string) string { return `{"CanonicalUser":"` + id + `"}` }

	idA, err := user.DecodeString(userA)
	require.NoError(t, err)
	idB, err := user.DecodeString(userB)
	require.NoError(t, err)

	type opKey struct {
		op     eacl.Operation
		action eacl.Action
	}

	for name, tc := range map[string]struct {
		statements []string
		grantee    astGrantee
		expected   map[opKey][]user.ID
	}{
		"different users": {
			statements: []string{statement("Allow", canonical(userA), "s3:GetObject"), statement("Deny", canonical(userB), "s3:*")},
			expected: map[opKey][]user.ID{
				{eacl.OperationGet, eacl.ActionAllow}:    {idA},
				{eacl.OperationHead, eacl.ActionAllow}:   {idA},
				{eacl.OperationSearch, eacl.ActionAllow}: {idA},
				{eacl.OperationGet, eacl.ActionDeny}:     {idB},
				{eacl.OperationHead, eacl.ActionDeny}:    {idB},
				{eacl.OperationSearch, eacl.ActionDeny}:  {idB},
				{eacl.OperationPut, eacl.ActionDeny}:     {idB},
				{eacl.OperationDelete, eacl.ActionDeny}:  {idB},
			},
		},
		"same user, deny last": {
			statements: []string{statement("Allow", canonical(userA), "s3:*"), statement("Deny", canonical(userA), "s3:PutObject")},
			expected: map[opKey][]user.ID{
				{eacl.OperationGet, eacl.ActionAllow}:    {idA},
				{eacl.OperationHead, eacl.ActionAllow}:   {idA},
				{eacl.OperationSearch, eacl.ActionAllow}: {idA},
				{eacl.OperationDelete, eacl.ActionAllow}: {idA},
				{eacl.OperationPut, eacl.ActionDeny}:     {idA},
			},
		},
		"same user, deny first": {
			statements: []string{statement("Deny", canonical(userA), "s3:PutObject"), statement("Allow", canonical(userA), "s3:*")},
			expected: map[opKey][]user.ID{
				{eacl.OperationGet, eacl.ActionAllow}:    {idA},
				{eacl.OperationHead, eacl.ActionAllow}:   {idA},
				{eacl.OperationSearch, eacl.ActionAllow}: {idA},
				{eacl.OperationDelete, eacl.ActionAllow}: {idA},
				{eacl.OperationPut, eacl.ActionDeny}:     {idA},
			},
		},
		"others, deny last": {
			statements: []string{statement("Allow", `"*"`, "s3:GetObject"), statement("Deny", `"*"`, "s3:*")},
			grantee:    astGranteeRoleOthers,
			expected: map[opKey][]user.ID{
				{eacl.OperationGet, eacl.ActionDeny}:    nil,
				{eacl.OperationHead, eacl.ActionDeny}:   nil,
				{eacl.OperationSearch, eacl.ActionDeny}: nil,
				{eacl.OperationPut, eacl.ActionDeny}:    nil,
				{eacl.OperationDelete, eacl.ActionDeny}: nil,
			},
		},
		"others, deny first": {
			statements: []string{statement("Deny", `"*"`, "s3:PutObject"), statement("Allow", `"*"`, "s3:*")},
			grantee:    astGranteeRoleOthers,
			expected: map[opKey][]user.ID{
				{eacl.OperationGet, eacl.ActionAllow}:    nil,
				{eacl.OperationHead, eacl.ActionAllow}:   nil,
				{eacl.OperationSearch, eacl.ActionAllow}: nil,
				{eacl.OperationDelete, eacl.ActionAllow}: nil,
				{eacl.OperationPut, eacl.ActionDeny}:     nil,
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			policy := &bucketPolicy{Bucket: "bucketName"}
			require.NoError(t, json.Unmarshal([]byte(`{"Statement":[`+strings.Join(tc.statements, ",")+`]}`), policy))

			actualAst, err := policyToAst(policy)
			require.NoError(t, err)
			require.Len(t, actualAst.Resources, 1)

			actual := make(map[opKey][]user.ID)
			for _, op := range actualAst.Resources[0].Operations {
				require.Equal(t, tc.grantee, op.Grantee)
				require.NotContains(t, actual, opKey{op.Op, op.Action})
				actual[opKey{op.Op, op.Action}] = op.Users
			}
			require.Equal(t, tc.expected, actual)
		})
	}
}

func getReadOps(key *keys.PrivateKey, gt astGrantee, action eacl.Action) []*astOperation {
	var (
		result []*astOperation
		users  []user.ID
	)
	if gt == astGranteeAccount {
		users = append(users, user.NewFromScriptHash(key.GetScriptHash()))
	}

	for _, op := range readOps {
		result = append(result, &astOperation{
			Users:   users,
			Op:      op,
			Action:  action,
			Grantee: gt,
		})
	}

	return result
}

func TestPolicyUpdateKeepsObjectRecordsFirst(t *testing.T) {
	const bktName = "bucket"

	key, err := keys.NewPrivateKey()
	require.NoError(t, err)

	for name, principal := range map[string]string{
		"wildcard":       `"*"`,
		"canonical user": `{"CanonicalUser":"` + user.NewFromScriptHash(key.GetScriptHash()).String() + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			table, err := bucketACLToTable(&AccessControlPolicy{})
			require.NoError(t, err)

			for _, objName := range []string{"first", "second", "third"} {
				policy := &bucketPolicy{Bucket: bktName}
				require.NoError(t, json.Unmarshal([]byte(`{"Statement":[{"Effect":"Allow","Principal":`+principal+
					`,"Action":"s3:GetObject","Resource":"arn:aws:s3:::`+bktName+`/`+objName+`"}]}`), policy))

				child, err := policyToAst(policy)
				require.NoError(t, err)

				resAst, updated := mergeAst(tableToAst(table, bktName), child)
				require.True(t, updated)

				table, err = astToTable(resAst)
				require.NoError(t, err)

				var denied bool
				for _, record := range table.Records() {
					if record.Action() == eacl.ActionDeny {
						denied = true
						continue
					}
					require.False(t, denied, "allow record after the deny ones")
				}
			}

			// Wide search record and three ones with filters per object, deny record per operation.
			require.Len(t, table.Records(), 3*(1+len(readOps))+len(fullOps))
		})
	}
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
						Op:      eacl.OperationGet,
						Action:  eacl.ActionDeny,
						Grantee: astGranteeRoleOthers,
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
						Op:      eacl.OperationPut,
						Action:  eacl.ActionDeny,
						Grantee: astGranteeRoleOthers,
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
			Operations: []*astOperation{{Op: eacl.OperationDelete, Action: eacl.ActionDeny, Grantee: astGranteeRoleOthers}}}},
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
					Op:      eacl.OperationGet,
					Action:  eacl.ActionDeny,
					Grantee: astGranteeRoleOthers,
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
	for i := range slices.Backward(writeOps) {
		op := writeOps[i]
		record := getAllowRecordWithUser(op, user.NewFromScriptHash(key.GetScriptHash()))

		applyFilters(record)
		records = append(records, *record)
	}
	for i := range slices.Backward(readOps) {
		op := readOps[i]
		record := getAllowRecordWithUser(op, user.NewFromScriptHash(key.GetScriptHash()))

		if op == eacl.OperationSearch {
			records = append(records, *getAllowRecordWithUser(op, user.NewFromScriptHash(key.GetScriptHash())))
		}

		applyFilters(record)
		records = append(records, *record)
	}

	for i := range slices.Backward(writeOps) {
		op := writeOps[i]
		record := getOthersRecord(op, eacl.ActionDeny)

		applyFilters(record)
		records = append(records, *record)
	}
	for i := range slices.Backward(readOps) {
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
		if _, ok := readOpsMap[op]; !ok {
			records = append(records, *getOthersRecord(op, eacl.ActionDeny))
		}
	}

	actualTable, err := bucketACLToTable(acl)
	require.NoError(t, err)
	require.Equal(t, records, actualTable.Records())
}

func TestObjectAclToAst(t *testing.T) {
	b := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, b)
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
			user.NewFromScriptHash(key2.GetScriptHash()),
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
	_, _ = io.ReadFull(rand.Reader, b)

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
	for _, op := range writeOps {
		astOp := &astOperation{Users: []user.ID{
			user.NewFromScriptHash(key2.GetScriptHash()),
		},
			Op:     op,
			Action: eacl.ActionAllow,
		}
		operations = append(operations, astOp)
	}
	for _, op := range readOps {
		astOp := &astOperation{
			Op:      op,
			Action:  eacl.ActionAllow,
			Grantee: astGranteeRoleOthers,
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
	bktInfo := createBucket(t, tc, bktName, box, nil)

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

func TestPutBucketACLOnStaleContainerRevision(t *testing.T) {
	tc := prepareHandlerContext(t)
	bktName := "bucket-for-acl-revision"

	box, _ := createAccessBox(t)
	createBucket(t, tc, bktName, box, nil)

	putBucketOwnership(tc, bktName, box, amzBucketOwnerObjectWriter, http.StatusOK)

	// Caches the bucket info the eACL update below is planned against.
	bktInfo, err := tc.Layer().GetBucketInfo(tc.Context(), bktName)
	require.NoError(t, err)

	// Another gateway turns versioning on, keeping the rest of the settings.
	settings := *bktInfo.Settings
	settings.Versioning = data.VersioningEnabled
	putBucketSettingsBehindCache(t, tc, bktInfo, &settings)

	header := map[string]string{api.AmzACL: "public-read"}
	// The table is merged into an eACL read at a revision the container has left.
	putBucketACL(t, tc, bktName, box, header, http.StatusConflict)

	// The stale bucket info has been dropped, so repeating the request works.
	putBucketACL(t, tc, bktName, box, header, http.StatusOK)
}

func TestPutBucketACLGrantWrite(t *testing.T) {
	tc := prepareHandlerContext(t)
	bktName := "bucket-for-acl-grant"

	box, _ := createAccessBox(t)
	bktInfo := createBucket(t, tc, bktName, box, map[string]string{api.AmzACL: "public-read"})

	putBucketOwnership(tc, bktName, box, amzBucketOwnerObjectWriter, http.StatusOK)

	grantee, err := keys.NewPrivateKey()
	require.NoError(t, err)
	granteeID := user.NewFromScriptHash(grantee.GetScriptHash())

	acl := &AccessControlPolicy{
		Owner: Owner{
			ID:          bktInfo.Owner.String(),
			DisplayName: bktInfo.Owner.String(),
		},
		AccessControlList: []*Grant{
			{
				Grantee: &Grantee{
					ID:   bktInfo.Owner.String(),
					Type: granteeCanonicalUser,
				},
				Permission: awsPermFullControl,
			},
			{
				Grantee: &Grantee{
					ID:   granteeID.String(),
					Type: granteeCanonicalUser,
				},
				Permission: awsPermWrite,
			},
		},
	}

	w, r := prepareTestRequest(tc, bktName, "", acl)
	ctx := context.WithValue(r.Context(), api.BoxData, box)
	r = r.WithContext(ctx)
	tc.Handler().PutBucketACLHandler(w, r)
	assertStatus(t, w, http.StatusOK)

	bktACL, err := tc.Layer().GetBucketACL(tc.Context(), bktInfo)
	require.NoError(t, err)

	records := bktACL.EACL.Records()

	type recordKey struct {
		action eacl.Action
		op     eacl.Operation
		role   eacl.Role
	}

	seen := make(map[recordKey]struct{})
	for _, rec := range records {
		for _, target := range rec.Targets() {
			seen[recordKey{rec.Action(), rec.Operation(), target.Role()}] = struct{}{}
		}
	}

	for key := range seen {
		if key.role == eacl.RoleOthers || key.role == eacl.RoleUser {
			var opposite eacl.Action
			if key.action == eacl.ActionAllow {
				opposite = eacl.ActionDeny
			} else {
				opposite = eacl.ActionAllow
			}
			_, conflict := seen[recordKey{opposite, key.op, key.role}]
			require.False(t, conflict,
				"contradictory records: %s %s for role %s has both ALLOW and DENY",
				key.action, key.op, key.role)
		}
	}
}

func TestBucketPolicy(t *testing.T) {
	hc := prepareHandlerContext(t)
	bktName := "bucket-for-policy"

	box, key := createAccessBox(t)
	createBucket(t, hc, bktName, box, nil)

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
	newPolicy.Statement[0].Condition = map[string]map[string]string{"StringEquals": {s3ConditionXAmzACL: "public-read"}}
	putBucketPolicy(hc, bktName, newPolicy, box, http.StatusUnprocessableEntity)

	newPolicy.Statement[0].Condition = nil
	putBucketPolicy(hc, bktName, newPolicy, box, http.StatusOK)

	bktPolicy = getBucketPolicy(hc, bktName)
	for _, st := range bktPolicy.Statement {
		if st.Effect == "Allow" && st.Principal.AWS == allUsersWildcard {
			require.Equal(t, []string{arnAwsPrefix + bktName}, st.Resource.values)
			require.ElementsMatch(t, []string{s3GetObject, s3ListBucket}, st.Action.values)
		}
	}
}

func TestBucketPolicyDenyActions(t *testing.T) {
	hc := prepareHandlerContext(t)
	bktName := "bucket-for-policy"

	box, _ := createAccessBox(t)
	bktInfo := createBucket(t, hc, bktName, box, map[string]string{api.AmzACL: "public-read-write"})

	deniedOps := func() []eacl.Operation {
		bucketACL, err := hc.Layer().GetBucketACL(hc.Context(), bktInfo)
		require.NoError(t, err)

		var ops []eacl.Operation
		for _, record := range bucketACL.EACL.Records() {
			if record.Action() != eacl.ActionDeny || len(record.Filters()) != 0 {
				continue
			}
			if targets := record.Targets(); len(targets) == 1 && targets[0].Role() == eacl.RoleOthers {
				ops = append(ops, record.Operation())
			}
		}
		return ops
	}

	policy := &bucketPolicy{
		Statement: []statement{{
			Effect:    "Deny",
			Principal: principal{AWS: allUsersWildcard},
			Action:    stringOrSlice{values: []string{"s3:GetBucketLocation"}},
			Resource:  stringOrSlice{values: []string{arnAwsPrefix + bktName}},
		}},
	}
	putBucketPolicy(hc, bktName, policy, box, http.StatusUnprocessableEntity)
	require.Empty(t, deniedOps())

	policy.Statement[0].Action.values[0] = "s3:*"
	putBucketPolicy(hc, bktName, policy, box, http.StatusOK)
	require.ElementsMatch(t, fullOps, deniedOps())
}

func TestBucketPolicyOwnerFullControl(t *testing.T) {
	hc := prepareHandlerContext(t)
	bktName := "bucket-for-policy"

	box, _ := createAccessBox(t)
	createBucket(t, hc, bktName, box, nil)

	putBucketPolicy(hc, bktName, &bucketPolicy{
		Statement: []statement{{
			Effect:    "Allow",
			Principal: principal{AWS: allUsersWildcard},
			Action:    stringOrSlice{values: []string{"s3:PutObject"}},
			Resource:  stringOrSlice{values: []string{arnAwsPrefix + bktName + "/*"}},
			Condition: map[string]map[string]string{"StringEquals": {s3ConditionXAmzACL: cannedACLBucketOwnerFullControl}},
		}},
	}, box, http.StatusOK)

	put := func(acl string, status int) {
		w, r := prepareTestPayloadRequest(hc, bktName, "object", bytes.NewReader([]byte("content")))
		r = r.WithContext(context.WithValue(r.Context(), api.BoxData, box))
		if acl != "" {
			r.Header.Set(api.AmzACL, acl)
		}
		hc.Handler().PutObjectHandler(w, r)
		assertStatus(t, w, status)
	}

	put("", http.StatusForbidden)
	put(cannedACLBucketOwnerFullControl, http.StatusOK)
}

func TestBucketPolicyOwnerFullControlWithOtherStatements(t *testing.T) {
	hc := prepareHandlerContext(t)
	bktName := "bucket-for-policy"

	box, _ := createAccessBox(t)
	createBucket(t, hc, bktName, box, nil)

	policy := &bucketPolicy{
		Statement: []statement{{
			Effect:    "Allow",
			Principal: principal{AWS: allUsersWildcard},
			Action:    stringOrSlice{values: []string{"s3:PutObject"}},
			Resource:  stringOrSlice{values: []string{arnAwsPrefix + bktName + "/*"}},
			Condition: map[string]map[string]string{"StringEquals": {s3ConditionXAmzACL: cannedACLBucketOwnerFullControl}},
		}, {
			Effect:    "Allow",
			Principal: principal{AWS: allUsersWildcard},
			Action:    stringOrSlice{values: []string{s3GetObject}},
			Resource:  stringOrSlice{values: []string{arnAwsPrefix + bktName + "/object:bad-version"}},
		}},
	}

	put := func(acl string, status int) {
		w, r := prepareTestPayloadRequest(hc, bktName, "object", bytes.NewReader([]byte("content")))
		r = r.WithContext(context.WithValue(r.Context(), api.BoxData, box))
		if acl != "" {
			r.Header.Set(api.AmzACL, acl)
		}
		hc.Handler().PutObjectHandler(w, r)
		assertStatus(t, w, status)
	}

	// A rejected policy must not restrict the bucket.
	putBucketPolicy(hc, bktName, policy, box, http.StatusInternalServerError)
	put("", http.StatusOK)

	policy.Statement[1].Resource.values[0] = arnAwsPrefix + bktName + "/object"
	putBucketPolicy(hc, bktName, policy, box, http.StatusOK)

	put("", http.StatusForbidden)
	put(cannedACLBucketOwnerFullControl, http.StatusOK)
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

	if length < 5 {
		t.Fatalf("length of records is less than 5: '%d'", length)
	}

	for _, rec := range bktACL.EACL.Records()[length-5:] {
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

	signer := user.NewAutoIDSignerRFC6979(key.PrivateKey)

	box := &accessbox.Box{
		Gate: &accessbox.GateData{
			SessionTokenV2: newTestSessionTokenV2(t, signer),
		},
	}

	return box, key
}

func createBucket(t *testing.T, tc *handlerContext, bktName string, box *accessbox.Box, headers map[string]string) *data.BucketInfo {
	w, r := prepareTestRequest(tc, bktName, "", nil)
	ctx := context.WithValue(r.Context(), api.BoxData, box)
	r = r.WithContext(ctx)
	for k, v := range headers {
		r.Header.Set(k, v)
	}

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
		Info: &data.BucketInfo{},
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

	records = append(records, *generateRecord(eacl.ActionAllow, eacl.OperationGet, []eacl.Target{othersTarget}))
	records = append(records, *generateRecord(eacl.ActionAllow, eacl.OperationHead, []eacl.Target{othersTarget}))
	records = append(records, *generateRecord(eacl.ActionAllow, eacl.OperationSearch, []eacl.Target{othersTarget}))

	records = append(records, *generateRecord(eacl.ActionDeny, eacl.OperationGet, []eacl.Target{othersTarget}))
	records = append(records, *generateRecord(eacl.ActionDeny, eacl.OperationHead, []eacl.Target{othersTarget}))
	records = append(records, *generateRecord(eacl.ActionDeny, eacl.OperationPut, []eacl.Target{othersTarget}))
	records = append(records, *generateRecord(eacl.ActionDeny, eacl.OperationDelete, []eacl.Target{othersTarget}))
	records = append(records, *generateRecord(eacl.ActionDeny, eacl.OperationSearch, []eacl.Target{othersTarget}))

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
