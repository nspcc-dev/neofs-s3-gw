package layer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-api-go/pkg/acl/eacl"
	"github.com/nspcc-dev/neofs-api-go/pkg/client"
	"github.com/nspcc-dev/neofs-api-go/pkg/container"
	cid "github.com/nspcc-dev/neofs-api-go/pkg/container/id"
	"github.com/nspcc-dev/neofs-api-go/pkg/object"
	"github.com/nspcc-dev/neofs-api-go/pkg/owner"
	"github.com/nspcc-dev/neofs-api-go/pkg/session"
	"github.com/nspcc-dev/neofs-api-go/pkg/token"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/cache"
	"github.com/nspcc-dev/neofs-s3-gw/creds/accessbox"
	"github.com/nspcc-dev/neofs-sdk-go/logger"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/stretchr/testify/require"
)

type testPool struct {
	objects      map[string]*object.Object
	containers   map[string]*container.Container
	currentEpoch uint64
}

func newTestPool() *testPool {
	return &testPool{
		objects:    make(map[string]*object.Object),
		containers: make(map[string]*container.Container),
	}
}

func (t *testPool) PutObject(ctx context.Context, params *client.PutObjectParams, option ...client.CallOption) (*object.ID, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}

	oid := object.NewID()
	oid.SetSHA256(sha256.Sum256(b))

	raw := object.NewRawFrom(params.Object())
	raw.SetID(oid)
	raw.SetCreationEpoch(t.currentEpoch)
	t.currentEpoch++

	if params.PayloadReader() != nil {
		all, err := io.ReadAll(params.PayloadReader())
		if err != nil {
			return nil, err
		}
		raw.SetPayload(all)
	}

	addr := newAddress(raw.ContainerID(), raw.ID())
	t.objects[addr.String()] = raw.Object()
	return raw.ID(), nil
}

func (t *testPool) DeleteObject(ctx context.Context, params *client.DeleteObjectParams, option ...client.CallOption) error {
	delete(t.objects, params.Address().String())
	return nil
}

func (t *testPool) GetObject(ctx context.Context, params *client.GetObjectParams, option ...client.CallOption) (*object.Object, error) {
	if obj, ok := t.objects[params.Address().String()]; ok {
		if params.PayloadWriter() != nil {
			_, err := params.PayloadWriter().Write(obj.Payload())
			if err != nil {
				return nil, err
			}
		}
		return obj, nil
	}

	return nil, fmt.Errorf("object not found " + params.Address().String())
}

func (t *testPool) GetObjectHeader(ctx context.Context, params *client.ObjectHeaderParams, option ...client.CallOption) (*object.Object, error) {
	p := new(client.GetObjectParams).WithAddress(params.Address())
	return t.GetObject(ctx, p)
}

func (t *testPool) ObjectPayloadRangeData(ctx context.Context, params *client.RangeDataParams, option ...client.CallOption) ([]byte, error) {
	panic("implement me")
}

func (t *testPool) ObjectPayloadRangeSHA256(ctx context.Context, params *client.RangeChecksumParams, option ...client.CallOption) ([][32]byte, error) {
	panic("implement me")
}

func (t *testPool) ObjectPayloadRangeTZ(ctx context.Context, params *client.RangeChecksumParams, option ...client.CallOption) ([][64]byte, error) {
	panic("implement me")
}

func (t *testPool) SearchObject(ctx context.Context, params *client.SearchObjectParams, option ...client.CallOption) ([]*object.ID, error) {
	cidStr := params.ContainerID().String()

	var res []*object.ID

	if len(params.SearchFilters()) == 1 {
		for k, v := range t.objects {
			if strings.Contains(k, cidStr) {
				res = append(res, v.ID())
			}
		}
		return res, nil
	}

	filter := params.SearchFilters()[1]
	if len(params.SearchFilters()) != 2 || filter.Operation() != object.MatchStringEqual ||
		(filter.Header() != object.AttributeFileName && filter.Header() != objectSystemAttributeName) {
		return nil, fmt.Errorf("usupported filters")
	}

	for k, v := range t.objects {
		if strings.Contains(k, cidStr) && isMatched(v.Attributes(), filter) {
			res = append(res, v.ID())
		}
	}

	return res, nil
}

func isMatched(attributes []*object.Attribute, filter object.SearchFilter) bool {
	for _, attr := range attributes {
		if attr.Key() == filter.Header() && attr.Value() == filter.Value() {
			return true
		}
	}

	return false
}

func (t *testPool) PutContainer(ctx context.Context, container *container.Container, option ...client.CallOption) (*cid.ID, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}

	id := cid.New()
	id.SetSHA256(sha256.Sum256(b))
	t.containers[id.String()] = container

	return id, nil
}

func (t *testPool) GetContainer(ctx context.Context, id *cid.ID, option ...client.CallOption) (*container.Container, error) {
	for k, v := range t.containers {
		if k == id.String() {
			return v, nil
		}
	}

	return nil, fmt.Errorf("container not found " + id.String())
}

func (t *testPool) ListContainers(ctx context.Context, id *owner.ID, option ...client.CallOption) ([]*cid.ID, error) {
	var res []*cid.ID
	for k := range t.containers {
		cID := cid.New()
		if err := cID.Parse(k); err != nil {
			return nil, err
		}
		res = append(res, cID)
	}

	return res, nil
}

func (t *testPool) DeleteContainer(ctx context.Context, id *cid.ID, option ...client.CallOption) error {
	delete(t.containers, id.String())
	return nil
}

func (t *testPool) GetEACL(ctx context.Context, id *cid.ID, option ...client.CallOption) (*client.EACLWithSignature, error) {
	panic("implement me")
}

func (t *testPool) SetEACL(ctx context.Context, table *eacl.Table, option ...client.CallOption) error {
	panic("implement me")
}

func (t *testPool) AnnounceContainerUsedSpace(ctx context.Context, announcements []container.UsedSpaceAnnouncement, option ...client.CallOption) error {
	panic("implement me")
}

func (t *testPool) Connection() (client.Client, *session.Token, error) {
	panic("implement me")
}

func (t *testPool) OwnerID() *owner.ID {
	return nil
}

func (t *testPool) WaitForContainerPresence(ctx context.Context, id *cid.ID, params *pool.ContainerPollingParams) error {
	return nil
}

func (tc *testContext) putObject(content []byte) *api.ObjectInfo {
	objInfo, err := tc.layer.PutObject(tc.ctx, &PutObjectParams{
		Bucket: tc.bkt,
		Object: tc.obj,
		Size:   int64(len(content)),
		Reader: bytes.NewReader(content),
		Header: make(map[string]string),
	})
	require.NoError(tc.t, err)

	return objInfo
}

func (tc *testContext) getObject(objectName, versionID string, needError bool) (*api.ObjectInfo, []byte) {
	objInfo, err := tc.layer.GetObjectInfo(tc.ctx, &HeadObjectParams{
		Bucket:    tc.bkt,
		Object:    objectName,
		VersionID: versionID,
	})
	if needError {
		require.Error(tc.t, err)
		return nil, nil
	}
	require.NoError(tc.t, err)

	content := bytes.NewBuffer(nil)
	err = tc.layer.GetObject(tc.ctx, &GetObjectParams{
		ObjectInfo: objInfo,
		Writer:     content,
		VersionID:  versionID,
	})
	require.NoError(tc.t, err)

	return objInfo, content.Bytes()
}

func (tc *testContext) deleteObject(objectName, versionID string) {
	errs := tc.layer.DeleteObjects(tc.ctx, tc.bkt, []*VersionedObject{
		{Name: objectName, VersionID: versionID},
	})
	for _, err := range errs {
		require.NoError(tc.t, err)
	}
}

func (tc *testContext) listObjectsV1() []*api.ObjectInfo {
	res, err := tc.layer.ListObjectsV1(tc.ctx, &ListObjectsParamsV1{
		ListObjectsParamsCommon: ListObjectsParamsCommon{
			Bucket:  tc.bkt,
			MaxKeys: 1000,
		},
	})
	require.NoError(tc.t, err)
	return res.Objects
}

func (tc *testContext) listObjectsV2() []*api.ObjectInfo {
	res, err := tc.layer.ListObjectsV2(tc.ctx, &ListObjectsParamsV2{
		ListObjectsParamsCommon: ListObjectsParamsCommon{
			Bucket:  tc.bkt,
			MaxKeys: 1000,
		},
	})
	require.NoError(tc.t, err)
	return res.Objects
}

func (tc *testContext) listVersions() *ListObjectVersionsInfo {
	res, err := tc.layer.ListObjectVersions(tc.ctx, &ListObjectVersionsParams{
		Bucket:  tc.bkt,
		MaxKeys: 1000,
	})
	require.NoError(tc.t, err)
	return res
}

func (tc *testContext) checkListObjects(ids ...*object.ID) {
	objs := tc.listObjectsV1()
	require.Equal(tc.t, len(ids), len(objs))
	for _, id := range ids {
		require.Contains(tc.t, ids, id)
	}

	objs = tc.listObjectsV2()
	require.Equal(tc.t, len(ids), len(objs))
	for _, id := range ids {
		require.Contains(tc.t, ids, id)
	}
}

type testContext struct {
	t        *testing.T
	ctx      context.Context
	layer    Client
	bkt      string
	bktID    *cid.ID
	obj      string
	testPool *testPool
}

func prepareContext(t *testing.T) *testContext {
	key, err := keys.NewPrivateKey()
	require.NoError(t, err)

	ctx := context.WithValue(context.Background(), api.BoxData, &accessbox.Box{
		Gate: &accessbox.GateData{
			BearerToken: token.NewBearerToken(),
			GateKey:     key.PublicKey(),
		},
	})
	l, err := logger.New(logger.WithTraceLevel("panic"))
	require.NoError(t, err)
	tp := newTestPool()

	bktName := "testbucket1"
	cnr := container.New(container.WithAttribute(container.AttributeName, bktName))
	bktID, err := tp.PutContainer(ctx, cnr)
	require.NoError(t, err)

	return &testContext{
		ctx: ctx,
		layer: NewLayer(l, tp, &CacheConfig{
			Size:                cache.DefaultObjectsCacheSize,
			Lifetime:            cache.DefaultObjectsCacheLifetime,
			ListObjectsLifetime: cache.DefaultObjectsListCacheLifetime},
		),
		bkt:      bktName,
		bktID:    bktID,
		obj:      "obj1",
		t:        t,
		testPool: tp,
	}
}

func TestSimpleVersioning(t *testing.T) {
	tc := prepareContext(t)
	_, err := tc.layer.PutBucketVersioning(tc.ctx, &PutVersioningParams{
		Bucket:   tc.bkt,
		Settings: &BucketSettings{VersioningEnabled: true},
	})
	require.NoError(t, err)

	obj1Content1 := []byte("content obj1 v1")
	obj1v1 := tc.putObject(obj1Content1)

	obj1Content2 := []byte("content obj1 v2")
	obj1v2 := tc.putObject(obj1Content2)

	objv2, buffer2 := tc.getObject(tc.obj, "", false)
	require.Equal(t, obj1Content2, buffer2)
	require.Contains(t, objv2.Headers[versionsAddAttr], obj1v1.ID.String())

	_, buffer1 := tc.getObject(tc.obj, obj1v1.ID.String(), false)
	require.Equal(t, obj1Content1, buffer1)

	tc.checkListObjects(obj1v2.ID)
}

func TestSimpleNoVersioning(t *testing.T) {
	tc := prepareContext(t)

	obj1Content1 := []byte("content obj1 v1")
	obj1v1 := tc.putObject(obj1Content1)

	obj1Content2 := []byte("content obj1 v2")
	obj1v2 := tc.putObject(obj1Content2)

	objv2, buffer2 := tc.getObject(tc.obj, "", false)
	require.Equal(t, obj1Content2, buffer2)
	require.Contains(t, objv2.Headers[versionsDelAttr], obj1v1.ID.String())

	tc.getObject(tc.obj, obj1v1.ID.String(), true)
	tc.checkListObjects(obj1v2.ID)
}

func TestVersioningDeleteObject(t *testing.T) {
	tc := prepareContext(t)
	_, err := tc.layer.PutBucketVersioning(tc.ctx, &PutVersioningParams{
		Bucket:   tc.bkt,
		Settings: &BucketSettings{VersioningEnabled: true},
	})
	require.NoError(t, err)

	tc.putObject([]byte("content obj1 v1"))
	tc.putObject([]byte("content obj1 v2"))

	tc.deleteObject(tc.obj, "")
	tc.getObject(tc.obj, "", true)

	tc.checkListObjects()
}

func TestVersioningDeleteSpecificObjectVersion(t *testing.T) {
	tc := prepareContext(t)
	_, err := tc.layer.PutBucketVersioning(tc.ctx, &PutVersioningParams{
		Bucket:   tc.bkt,
		Settings: &BucketSettings{VersioningEnabled: true},
	})
	require.NoError(t, err)

	tc.putObject([]byte("content obj1 v1"))
	objV2Info := tc.putObject([]byte("content obj1 v2"))
	objV3Content := []byte("content obj1 v3")
	objV3Info := tc.putObject(objV3Content)

	tc.deleteObject(tc.obj, objV2Info.Version())
	tc.getObject(tc.obj, objV2Info.Version(), true)

	_, buffer3 := tc.getObject(tc.obj, "", false)
	require.Equal(t, objV3Content, buffer3)

	tc.deleteObject(tc.obj, "")
	tc.getObject(tc.obj, "", true)

	for _, ver := range tc.listVersions().DeleteMarker {
		if ver.IsLatest {
			tc.deleteObject(tc.obj, ver.Object.Version())
		}
	}

	resInfo, buffer := tc.getObject(tc.obj, "", false)
	require.Equal(t, objV3Content, buffer)
	require.Equal(t, objV3Info.Version(), resInfo.Version())
}

func TestNoVersioningDeleteObject(t *testing.T) {
	tc := prepareContext(t)

	tc.putObject([]byte("content obj1 v1"))
	tc.putObject([]byte("content obj1 v2"))

	tc.deleteObject(tc.obj, "")
	tc.getObject(tc.obj, "", true)
	tc.checkListObjects()
}

func TestGetLastVersion(t *testing.T) {
	obj1 := getTestObjectInfo(1, getOID(1), "", "", "")
	obj1V2 := getTestObjectInfo(1, getOID(2), "", "", "")
	obj2 := getTestObjectInfo(2, getOID(2), obj1.Version(), "", "")
	obj3 := getTestObjectInfo(3, getOID(3), joinVers(obj1, obj2), "", "*")
	obj4 := getTestObjectInfo(4, getOID(4), joinVers(obj1, obj2), obj2.Version(), obj2.Version())
	obj5 := getTestObjectInfo(5, getOID(5), obj1.Version(), obj1.Version(), obj1.Version())
	obj6 := getTestObjectInfo(6, getOID(6), joinVers(obj1, obj2, obj3), obj3.Version(), obj3.Version())

	for _, tc := range []struct {
		versions *objectVersions
		expected *api.ObjectInfo
	}{
		{
			versions: &objectVersions{},
			expected: nil,
		},
		{
			versions: &objectVersions{
				objects: []*api.ObjectInfo{obj2, obj1},
				addList: []string{obj1.Version(), obj2.Version()},
			},
			expected: obj2,
		},
		{
			versions: &objectVersions{
				objects: []*api.ObjectInfo{obj2, obj1, obj3},
				addList: []string{obj1.Version(), obj2.Version(), obj3.Version()},
			},
			expected: nil,
		},
		{
			versions: &objectVersions{
				objects: []*api.ObjectInfo{obj2, obj1, obj4},
				addList: []string{obj1.Version(), obj2.Version(), obj4.Version()},
				delList: []string{obj2.Version()},
			},
			expected: obj1,
		},
		{
			versions: &objectVersions{
				objects: []*api.ObjectInfo{obj1, obj5},
				addList: []string{obj1.Version(), obj5.Version()},
				delList: []string{obj1.Version()},
			},
			expected: nil,
		},
		{
			versions: &objectVersions{
				objects: []*api.ObjectInfo{obj5},
			},
			expected: nil,
		},
		{
			versions: &objectVersions{
				objects: []*api.ObjectInfo{obj1, obj2, obj3, obj6},
				addList: []string{obj1.Version(), obj2.Version(), obj3.Version(), obj6.Version()},
				delList: []string{obj3.Version()},
			},
			expected: obj2,
		},
		{
			versions: &objectVersions{
				objects: []*api.ObjectInfo{obj1, obj1V2},
				addList: []string{obj1.Version(), obj1V2.Version()},
			},
			// creation epochs are equal
			// obj1 version/oid > obj1_1 version/oid
			expected: obj1,
		},
	} {
		actualObjInfo := tc.versions.getLast()
		require.Equal(t, tc.expected, actualObjInfo)
	}
}

func TestAppendVersions(t *testing.T) {
	obj1 := getTestObjectInfo(1, getOID(1), "", "", "")
	obj2 := getTestObjectInfo(2, getOID(2), obj1.Version(), "", "")
	obj3 := getTestObjectInfo(3, getOID(3), joinVers(obj1, obj2), "", "*")
	obj4 := getTestObjectInfo(4, getOID(4), joinVers(obj1, obj2), obj2.Version(), obj2.Version())

	for _, tc := range []struct {
		versions         *objectVersions
		objectToAdd      *api.ObjectInfo
		expectedVersions *objectVersions
	}{
		{
			versions:    &objectVersions{},
			objectToAdd: obj1,
			expectedVersions: &objectVersions{
				objects: []*api.ObjectInfo{obj1},
				addList: []string{obj1.Version()},
			},
		},
		{
			versions:    &objectVersions{objects: []*api.ObjectInfo{obj1}},
			objectToAdd: obj2,
			expectedVersions: &objectVersions{
				objects: []*api.ObjectInfo{obj1, obj2},
				addList: []string{obj1.Version(), obj2.Version()},
			},
		},
		{
			versions:    &objectVersions{objects: []*api.ObjectInfo{obj1, obj2}},
			objectToAdd: obj3,
			expectedVersions: &objectVersions{
				objects: []*api.ObjectInfo{obj1, obj2, obj3},
				addList: []string{obj1.Version(), obj2.Version(), obj3.Version()},
			},
		},
		{
			versions:    &objectVersions{objects: []*api.ObjectInfo{obj1, obj2}},
			objectToAdd: obj4,
			expectedVersions: &objectVersions{
				objects: []*api.ObjectInfo{obj1, obj2, obj4},
				addList: []string{obj1.Version(), obj2.Version(), obj4.Version()},
				delList: []string{obj2.Version()},
			},
		},
	} {
		tc.versions.appendVersion(tc.objectToAdd)
		require.Equal(t, tc.expectedVersions, tc.versions)
	}
}

func joinVers(objs ...*api.ObjectInfo) string {
	if len(objs) == 0 {
		return ""
	}

	var versions []string
	for _, obj := range objs {
		versions = append(versions, obj.Version())
	}

	return strings.Join(versions, ",")
}

func getOID(id byte) *object.ID {
	b := make([]byte, 32)
	b[0] = id
	oid := object.NewID()
	oid.SetSHA256(sha256.Sum256(b))
	return oid
}

func getTestObjectInfo(epoch uint64, oid *object.ID, addAttr, delAttr, delMarkAttr string) *api.ObjectInfo {
	headers := make(map[string]string)
	if addAttr != "" {
		headers[versionsAddAttr] = addAttr
	}
	if delAttr != "" {
		headers[versionsDelAttr] = delAttr
	}
	if delMarkAttr != "" {
		headers[versionsDeleteMarkAttr] = delMarkAttr
	}

	return &api.ObjectInfo{
		ID:            oid,
		CreationEpoch: epoch,
		Headers:       headers,
	}
}
