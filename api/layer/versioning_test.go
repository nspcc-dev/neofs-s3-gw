package layer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/creds/accessbox"
	"github.com/nspcc-dev/neofs-sdk-go/container"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/logger"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	"github.com/nspcc-dev/neofs-sdk-go/object/address"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/object/id/test"
	"github.com/nspcc-dev/neofs-sdk-go/owner"
	tokentest "github.com/nspcc-dev/neofs-sdk-go/token/test"
	"github.com/stretchr/testify/require"
)

type testNeoFS struct {
	NeoFS

	objects      map[string]*object.Object
	containers   map[string]*container.Container
	currentEpoch uint64
}

func (t *testNeoFS) CreateContainer(_ context.Context, prm PrmContainerCreate) (*cid.ID, error) {
	var opts []container.Option

	opts = append(opts,
		container.WithOwnerID(&prm.Creator),
		container.WithPolicy(&prm.Policy),
		container.WithCustomBasicACL(prm.BasicACL),
		container.WithAttribute(container.AttributeTimestamp, strconv.FormatInt(prm.Time.Unix(), 10)),
	)

	if prm.Name != "" {
		opts = append(opts, container.WithAttribute(container.AttributeName, prm.Name))
	}

	cnr := container.New(opts...)
	cnr.SetSessionToken(prm.SessionToken)

	if prm.Name != "" {
		container.SetNativeName(cnr, prm.Name)
	}

	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}

	id := cid.New()
	id.SetSHA256(sha256.Sum256(b))
	t.containers[id.String()] = cnr

	return id, nil
}

func (t *testNeoFS) Container(_ context.Context, id cid.ID) (*container.Container, error) {
	for k, v := range t.containers {
		if k == id.String() {
			return v, nil
		}
	}

	return nil, fmt.Errorf("container not found " + id.String())
}

func (t *testNeoFS) UserContainers(_ context.Context, _ owner.ID) ([]cid.ID, error) {
	var res []cid.ID
	for k := range t.containers {
		var idCnr cid.ID
		if err := idCnr.Parse(k); err != nil {
			return nil, err
		}
		res = append(res, idCnr)
	}

	return res, nil
}

func (t *testNeoFS) SelectObjects(_ context.Context, prm PrmObjectSelect) ([]oid.ID, error) {
	var filters object.SearchFilters
	filters.AddRootFilter()

	if prm.FilePrefix != "" {
		filters.AddFilter(object.AttributeFileName, prm.FilePrefix, object.MatchCommonPrefix)
	}

	if prm.ExactAttribute[0] != "" {
		filters.AddFilter(prm.ExactAttribute[0], prm.ExactAttribute[1], object.MatchStringEqual)
	}

	cidStr := prm.Container.String()

	var res []oid.ID

	if len(filters) == 1 {
		for k, v := range t.objects {
			if strings.Contains(k, cidStr) {
				res = append(res, *v.ID())
			}
		}
		return res, nil
	}

	filter := filters[1]
	if len(filters) != 2 || filter.Operation() != object.MatchStringEqual ||
		(filter.Header() != object.AttributeFileName && filter.Header() != objectSystemAttributeName) {
		return nil, fmt.Errorf("usupported filters")
	}

	for k, v := range t.objects {
		if strings.Contains(k, cidStr) && isMatched(v.Attributes(), filter) {
			res = append(res, *v.ID())
		}
	}

	return res, nil
}

func (t *testNeoFS) ReadObject(_ context.Context, prm PrmObjectRead) (*ObjectPart, error) {
	var addr address.Address
	addr.SetContainerID(&prm.Container)
	addr.SetObjectID(&prm.Object)

	sAddr := addr.String()

	if obj, ok := t.objects[sAddr]; ok {
		return &ObjectPart{
			Head:    obj,
			Payload: io.NopCloser(bytes.NewReader(obj.Payload())),
		}, nil
	}

	return nil, fmt.Errorf("object not found " + addr.String())
}

func (t *testNeoFS) CreateObject(_ context.Context, prm PrmObjectCreate) (*oid.ID, error) {
	id := test.ID()

	attrs := make([]object.Attribute, 0)

	if prm.Filename != "" {
		a := object.NewAttribute()
		a.SetKey(object.AttributeFileName)
		a.SetValue(prm.Filename)
		attrs = append(attrs, *a)
	}

	for i := range prm.Attributes {
		a := object.NewAttribute()
		a.SetKey(prm.Attributes[i][0])
		a.SetValue(prm.Attributes[i][1])
		attrs = append(attrs, *a)
	}

	obj := object.New()
	obj.SetContainerID(&prm.Container)
	obj.SetID(id)
	obj.SetPayloadSize(prm.PayloadSize)
	obj.SetAttributes(attrs...)
	obj.SetCreationEpoch(t.currentEpoch)
	t.currentEpoch++

	if prm.Payload != nil {
		all, err := io.ReadAll(prm.Payload)
		if err != nil {
			return nil, err
		}
		obj.SetPayload(all)
	}

	addr := newAddress(obj.ContainerID(), obj.ID())
	t.objects[addr.String()] = obj
	return obj.ID(), nil
}

func (t *testNeoFS) DeleteObject(_ context.Context, prm PrmObjectDelete) error {
	var addr address.Address
	addr.SetContainerID(&prm.Container)
	addr.SetObjectID(&prm.Object)

	delete(t.objects, addr.String())

	return nil
}

func newTestPool() *testNeoFS {
	return &testNeoFS{
		objects:    make(map[string]*object.Object),
		containers: make(map[string]*container.Container),
	}
}

func isMatched(attributes []object.Attribute, filter object.SearchFilter) bool {
	for _, attr := range attributes {
		if attr.Key() == filter.Header() && attr.Value() == filter.Value() {
			return true
		}
	}

	return false
}

func (tc *testContext) putObject(content []byte) *data.ObjectInfo {
	objInfo, err := tc.layer.PutObject(tc.ctx, &PutObjectParams{
		Bucket: tc.bktID.String(),
		Object: tc.obj,
		Size:   int64(len(content)),
		Reader: bytes.NewReader(content),
		Header: make(map[string]string),
	})
	require.NoError(tc.t, err)

	return objInfo
}

func (tc *testContext) getObject(objectName, versionID string, needError bool) (*data.ObjectInfo, []byte) {
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
	deletedObjects, err := tc.layer.DeleteObjects(tc.ctx, tc.bkt, []*VersionedObject{
		{Name: objectName, VersionID: versionID},
	})
	require.NoError(tc.t, err)
	for _, obj := range deletedObjects {
		require.NoError(tc.t, obj.Error)
	}
}

func (tc *testContext) listObjectsV1() []*data.ObjectInfo {
	res, err := tc.layer.ListObjectsV1(tc.ctx, &ListObjectsParamsV1{
		ListObjectsParamsCommon: ListObjectsParamsCommon{
			Bucket:  tc.bkt,
			MaxKeys: 1000,
		},
	})
	require.NoError(tc.t, err)
	return res.Objects
}

func (tc *testContext) listObjectsV2() []*data.ObjectInfo {
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

func (tc *testContext) checkListObjects(ids ...*oid.ID) {
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

func (tc *testContext) getSystemObject(objectName string) *object.Object {
	for _, obj := range tc.testNeoFS.objects {
		for _, attr := range obj.Attributes() {
			if attr.Key() == objectSystemAttributeName && attr.Value() == objectName {
				return obj
			}
		}
	}
	return nil
}

type testContext struct {
	t         *testing.T
	ctx       context.Context
	layer     Client
	bkt       string
	bktID     *cid.ID
	bktInfo   *data.BucketInfo
	obj       string
	testNeoFS *testNeoFS
}

func prepareContext(t *testing.T, cachesConfig ...*CachesConfig) *testContext {
	key, err := keys.NewPrivateKey()
	require.NoError(t, err)

	bearerToken := tokentest.BearerToken()
	require.NoError(t, bearerToken.SignToken(&key.PrivateKey))

	ctx := context.WithValue(context.Background(), api.BoxData, &accessbox.Box{
		Gate: &accessbox.GateData{
			BearerToken: bearerToken,
			GateKey:     key.PublicKey(),
		},
	})
	l, err := logger.New(logger.WithTraceLevel("panic"))
	require.NoError(t, err)
	tp := newTestPool()

	bktName := "testbucket1"
	bktID, err := tp.CreateContainer(ctx, PrmContainerCreate{
		Name: bktName,
	})
	require.NoError(t, err)

	config := DefaultCachesConfigs()
	if len(cachesConfig) != 0 {
		config = cachesConfig[0]
	}

	layerCfg := &Config{
		Caches:  config,
		AnonKey: AnonymousKey{Key: key},
	}

	return &testContext{
		ctx:   ctx,
		layer: NewLayer(l, tp, layerCfg),
		bkt:   bktName,
		bktID: bktID,
		bktInfo: &data.BucketInfo{
			Name: bktName,
			CID:  bktID,
		},
		obj:       "obj1",
		t:         t,
		testNeoFS: tp,
	}
}

func TestSimpleVersioning(t *testing.T) {
	tc := prepareContext(t)
	err := tc.layer.PutBucketSettings(tc.ctx, &PutSettingsParams{
		BktInfo:  tc.bktInfo,
		Settings: &data.BucketSettings{VersioningEnabled: true},
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
	err := tc.layer.PutBucketSettings(tc.ctx, &PutSettingsParams{
		BktInfo:  tc.bktInfo,
		Settings: &data.BucketSettings{VersioningEnabled: true},
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
	err := tc.layer.PutBucketSettings(tc.ctx, &PutSettingsParams{
		BktInfo:  tc.bktInfo,
		Settings: &data.BucketSettings{VersioningEnabled: true},
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

func TestGetLastVersion(t *testing.T) {
	obj1 := getTestObjectInfo(1, "", "", "")
	obj1V2 := getTestObjectInfo(2, "", "", "")
	obj2 := getTestObjectInfoEpoch(1, 2, obj1.Version(), "", "")
	obj3 := getTestObjectInfoEpoch(1, 3, joinVers(obj1, obj2), "", "*")
	obj4 := getTestObjectInfoEpoch(1, 4, joinVers(obj1, obj2), obj2.Version(), obj2.Version())
	obj5 := getTestObjectInfoEpoch(1, 5, obj1.Version(), obj1.Version(), obj1.Version())
	obj6 := getTestObjectInfoEpoch(1, 6, joinVers(obj1, obj2, obj3), obj3.Version(), obj3.Version())

	for _, tc := range []struct {
		versions *objectVersions
		expected *data.ObjectInfo
	}{
		{
			versions: &objectVersions{},
			expected: nil,
		},
		{
			versions: &objectVersions{
				objects: []*data.ObjectInfo{obj2, obj1},
				addList: []string{obj1.Version(), obj2.Version()},
			},
			expected: obj2,
		},
		{
			versions: &objectVersions{
				objects: []*data.ObjectInfo{obj2, obj1, obj3},
				addList: []string{obj1.Version(), obj2.Version(), obj3.Version()},
			},
			expected: nil,
		},
		{
			versions: &objectVersions{
				objects: []*data.ObjectInfo{obj2, obj1, obj4},
				addList: []string{obj1.Version(), obj2.Version(), obj4.Version()},
				delList: []string{obj2.Version()},
			},
			expected: obj1,
		},
		{
			versions: &objectVersions{
				objects: []*data.ObjectInfo{obj1, obj5},
				addList: []string{obj1.Version(), obj5.Version()},
				delList: []string{obj1.Version()},
			},
			expected: nil,
		},
		{
			versions: &objectVersions{
				objects: []*data.ObjectInfo{obj5},
			},
			expected: nil,
		},
		{
			versions: &objectVersions{
				objects: []*data.ObjectInfo{obj1, obj2, obj3, obj6},
				addList: []string{obj1.Version(), obj2.Version(), obj3.Version(), obj6.Version()},
				delList: []string{obj3.Version()},
			},
			expected: obj2,
		},
		{
			versions: &objectVersions{
				objects: []*data.ObjectInfo{obj1, obj1V2},
				addList: []string{obj1.Version(), obj1V2.Version()},
			},
			expected: obj1V2,
		},
	} {
		actualObjInfo := tc.versions.getLast()
		require.Equal(t, tc.expected, actualObjInfo)
	}
}

func TestNoVersioningDeleteObject(t *testing.T) {
	tc := prepareContext(t)

	tc.putObject([]byte("content obj1 v1"))
	tc.putObject([]byte("content obj1 v2"))

	tc.deleteObject(tc.obj, "")
	tc.getObject(tc.obj, "", true)
	tc.checkListObjects()
}

func TestAppendVersions(t *testing.T) {
	obj1 := getTestObjectInfo(1, "", "", "")
	obj2 := getTestObjectInfo(2, obj1.Version(), "", "")
	obj3 := getTestObjectInfo(3, joinVers(obj1, obj2), "", "*")
	obj4 := getTestObjectInfo(4, joinVers(obj1, obj2), obj2.Version(), obj2.Version())
	obj5 := getTestObjectInfo(5, joinVers(obj1, obj2), "", "")
	obj6 := getTestObjectInfo(6, joinVers(obj1, obj3), "", "")

	for _, tc := range []struct {
		versions         *objectVersions
		objectToAdd      *data.ObjectInfo
		expectedVersions *objectVersions
	}{
		{
			versions:    &objectVersions{},
			objectToAdd: obj1,
			expectedVersions: &objectVersions{
				objects:  []*data.ObjectInfo{obj1},
				addList:  []string{obj1.Version()},
				isSorted: true,
			},
		},
		{
			versions:    &objectVersions{objects: []*data.ObjectInfo{obj1}},
			objectToAdd: obj2,
			expectedVersions: &objectVersions{
				objects:  []*data.ObjectInfo{obj1, obj2},
				addList:  []string{obj1.Version(), obj2.Version()},
				isSorted: true,
			},
		},
		{
			versions:    &objectVersions{objects: []*data.ObjectInfo{obj1, obj2}},
			objectToAdd: obj3,
			expectedVersions: &objectVersions{
				objects:  []*data.ObjectInfo{obj1, obj2, obj3},
				addList:  []string{obj1.Version(), obj2.Version(), obj3.Version()},
				isSorted: true,
			},
		},
		{
			versions:    &objectVersions{objects: []*data.ObjectInfo{obj1, obj2}},
			objectToAdd: obj4,
			expectedVersions: &objectVersions{
				objects:  []*data.ObjectInfo{obj1, obj2, obj4},
				addList:  []string{obj1.Version(), obj2.Version(), obj4.Version()},
				delList:  []string{obj2.Version()},
				isSorted: true,
			},
		},
		{
			versions:    &objectVersions{objects: []*data.ObjectInfo{obj5}},
			objectToAdd: obj6,
			expectedVersions: &objectVersions{
				objects:  []*data.ObjectInfo{obj5, obj6},
				addList:  []string{obj1.Version(), obj2.Version(), obj3.Version(), obj5.Version(), obj6.Version()},
				isSorted: true,
			},
		},
	} {
		tc.versions.appendVersion(tc.objectToAdd)
		tc.versions.sort()
		require.Equal(t, tc.expectedVersions, tc.versions)
	}
}

func TestSortAddHeaders(t *testing.T) {
	obj1 := getTestObjectInfo(1, "", "", "")
	obj2 := getTestObjectInfo(2, "", "", "")
	obj3 := getTestObjectInfo(3, "", "", "")
	obj4 := getTestObjectInfo(4, "", "", "")
	obj5 := getTestObjectInfo(5, "", "", "")

	obj6 := getTestObjectInfoEpoch(1, 6, joinVers(obj1, obj2, obj3), "", "")
	obj7 := getTestObjectInfoEpoch(1, 7, joinVers(obj1, obj4), "", "")
	obj8 := getTestObjectInfoEpoch(1, 8, joinVers(obj5), "", "")
	obj9 := getTestObjectInfoEpoch(1, 8, joinVers(obj1, obj5), "", "")
	obj10 := getTestObjectInfo(11, "", "", "")
	obj11 := getTestObjectInfo(10, joinVers(obj10), "", "")
	obj12 := getTestObjectInfo(9, joinVers(obj10, obj11), "", "")

	for _, tc := range []struct {
		versions           *objectVersions
		expectedAddHeaders string
	}{
		{
			versions:           &objectVersions{objects: []*data.ObjectInfo{obj6, obj7, obj8}},
			expectedAddHeaders: joinVers(obj1, obj2, obj3, obj4, obj5, obj6, obj7, obj8),
		},
		{
			versions:           &objectVersions{objects: []*data.ObjectInfo{obj7, obj9}},
			expectedAddHeaders: joinVers(obj1, obj4, obj5, obj7, obj9),
		},
		{
			versions:           &objectVersions{objects: []*data.ObjectInfo{obj11, obj10, obj12}},
			expectedAddHeaders: joinVers(obj10, obj11, obj12),
		},
	} {
		require.Equal(t, tc.expectedAddHeaders, tc.versions.getAddHeader())
	}
}

func joinVers(objs ...*data.ObjectInfo) string {
	if len(objs) == 0 {
		return ""
	}

	var versions []string
	for _, obj := range objs {
		versions = append(versions, obj.Version())
	}

	return strings.Join(versions, ",")
}

func getOID(id byte) *oid.ID {
	b := [32]byte{}
	b[31] = id
	idObj := oid.NewID()
	idObj.SetSHA256(b)
	return idObj
}

func getTestObjectInfo(id byte, addAttr, delAttr, delMarkAttr string) *data.ObjectInfo {
	headers := make(map[string]string)
	if addAttr != "" {
		headers[versionsAddAttr] = addAttr
	}
	if delAttr != "" {
		headers[versionsDelAttr] = delAttr
	}
	if delMarkAttr != "" {
		headers[VersionsDeleteMarkAttr] = delMarkAttr
	}

	return &data.ObjectInfo{
		ID:      getOID(id),
		Name:    strconv.Itoa(int(id)),
		Headers: headers,
	}
}

func getTestUnversionedObjectInfo(id byte, addAttr, delAttr, delMarkAttr string) *data.ObjectInfo {
	objInfo := getTestObjectInfo(id, addAttr, delAttr, delMarkAttr)
	objInfo.Headers[versionsUnversionedAttr] = "true"
	return objInfo
}

func getTestObjectInfoEpoch(epoch uint64, id byte, addAttr, delAttr, delMarkAttr string) *data.ObjectInfo {
	obj := getTestObjectInfo(id, addAttr, delAttr, delMarkAttr)
	obj.CreationEpoch = epoch
	return obj
}

func TestUpdateCRDT2PSetHeaders(t *testing.T) {
	obj1 := getTestUnversionedObjectInfo(1, "", "", "")
	obj2 := getTestUnversionedObjectInfo(2, "", "", "")
	obj3 := getTestObjectInfo(3, "", "", "")
	obj4 := getTestObjectInfo(4, "", "", "")

	for _, tc := range []struct {
		name                string
		header              map[string]string
		versions            *objectVersions
		versioningEnabled   bool
		expectedHeader      map[string]string
		expectedIdsToDelete []*oid.ID
	}{
		{
			name:           "unversioned save headers",
			header:         map[string]string{"someKey": "someValue"},
			expectedHeader: map[string]string{"someKey": "someValue", versionsUnversionedAttr: "true"},
		},
		{
			name:   "unversioned put",
			header: map[string]string{},
			versions: &objectVersions{
				objects: []*data.ObjectInfo{obj1},
			},
			expectedHeader: map[string]string{
				versionsAddAttr:         obj1.Version(),
				versionsDelAttr:         obj1.Version(),
				versionsUnversionedAttr: "true",
			},
			expectedIdsToDelete: []*oid.ID{obj1.ID},
		},
		{
			name:   "unversioned del header",
			header: map[string]string{},
			versions: &objectVersions{
				objects: []*data.ObjectInfo{obj2},
				delList: []string{obj1.Version()},
			},
			expectedHeader: map[string]string{
				versionsAddAttr:         obj2.Version(),
				versionsDelAttr:         joinVers(obj1, obj2),
				versionsUnversionedAttr: "true",
			},
			expectedIdsToDelete: []*oid.ID{obj2.ID},
		},
		{
			name:   "versioned put",
			header: map[string]string{},
			versions: &objectVersions{
				objects: []*data.ObjectInfo{obj3},
			},
			versioningEnabled: true,
			expectedHeader:    map[string]string{versionsAddAttr: obj3.Version()},
		},
		{
			name:   "versioned del header",
			header: map[string]string{versionsDelAttr: obj4.Version()},
			versions: &objectVersions{
				objects: []*data.ObjectInfo{obj4},
				delList: []string{obj3.Version()},
			},
			versioningEnabled: true,
			expectedHeader: map[string]string{
				versionsAddAttr: obj4.Version(),
				versionsDelAttr: joinVers(obj3, obj4),
			},
		},
		{
			name:   "unversioned put after some version",
			header: map[string]string{},
			versions: &objectVersions{
				objects: []*data.ObjectInfo{obj1, obj3},
			},
			expectedHeader: map[string]string{
				versionsAddAttr:         joinVers(obj1, obj3),
				versionsDelAttr:         obj1.Version(),
				versionsUnversionedAttr: "true",
			},
			expectedIdsToDelete: []*oid.ID{obj1.ID},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idsToDelete := updateCRDT2PSetHeaders(tc.header, tc.versions, tc.versioningEnabled)
			require.Equal(t, tc.expectedHeader, tc.header)
			require.Equal(t, tc.expectedIdsToDelete, idsToDelete)
		})
	}
}

func TestSystemObjectsVersioning(t *testing.T) {
	cacheConfig := DefaultCachesConfigs()
	cacheConfig.System.Lifetime = 0

	tc := prepareContext(t, cacheConfig)
	err := tc.layer.PutBucketSettings(tc.ctx, &PutSettingsParams{
		BktInfo:  tc.bktInfo,
		Settings: &data.BucketSettings{VersioningEnabled: false},
	})
	require.NoError(t, err)

	objMeta := tc.getSystemObject(tc.bktInfo.SettingsObjectName())
	require.NotNil(t, objMeta)

	err = tc.layer.PutBucketSettings(tc.ctx, &PutSettingsParams{
		BktInfo:  tc.bktInfo,
		Settings: &data.BucketSettings{VersioningEnabled: true},
	})
	require.NoError(t, err)

	addr := object.NewAddress()
	addr.SetContainerID(objMeta.ContainerID())
	addr.SetObjectID(objMeta.ID())

	// simulate failed deletion
	tc.testNeoFS.objects[addr.String()] = objMeta

	bktInfo := &data.BucketInfo{
		Name: tc.bkt,
		CID:  tc.bktID,
	}

	versioning, err := tc.layer.GetBucketSettings(tc.ctx, bktInfo)
	require.NoError(t, err)
	require.True(t, versioning.VersioningEnabled)
}

func TestDeleteSystemObjectsVersioning(t *testing.T) {
	cacheConfig := DefaultCachesConfigs()
	cacheConfig.System.Lifetime = 0

	tc := prepareContext(t, cacheConfig)

	tagSet := map[string]string{
		"tag1": "val1",
	}

	err := tc.layer.PutBucketTagging(tc.ctx, tc.bktID.String(), tagSet)
	require.NoError(t, err)

	objMeta := tc.getSystemObject(formBucketTagObjectName(tc.bktID.String()))

	tagSet["tag2"] = "val2"
	err = tc.layer.PutBucketTagging(tc.ctx, tc.bkt, tagSet)
	require.NoError(t, err)

	// simulate failed deletion
	tc.testNeoFS.objects[newAddress(objMeta.ContainerID(), objMeta.ID()).String()] = objMeta

	tagging, err := tc.layer.GetBucketTagging(tc.ctx, tc.bkt)
	require.NoError(t, err)

	expectedTagSet := map[string]string{
		"tag1": "val1",
		"tag2": "val2",
	}
	require.Equal(t, expectedTagSet, tagging)

	err = tc.layer.DeleteBucketTagging(tc.ctx, tc.bkt)
	require.NoError(t, err)

	require.Nil(t, tc.getSystemObject(formBucketTagObjectName(tc.bkt)))
}
