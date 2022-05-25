package layer

import (
	"bytes"
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer/neofs"
	"github.com/nspcc-dev/neofs-s3-gw/creds/accessbox"
	"github.com/nspcc-dev/neofs-s3-gw/internal/neofstest"
	bearertest "github.com/nspcc-dev/neofs-sdk-go/bearer/test"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	usertest "github.com/nspcc-dev/neofs-sdk-go/user/test"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func (tc *testContext) putObject(content []byte) *data.ObjectInfo {
	objInfo, err := tc.layer.PutObject(tc.ctx, &PutObjectParams{
		BktInfo: tc.bktInfo,
		Object:  tc.obj,
		Size:    int64(len(content)),
		Reader:  bytes.NewReader(content),
		Header:  make(map[string]string),
	})
	require.NoError(tc.t, err)

	return objInfo
}

func (tc *testContext) getObject(objectName, versionID string, needError bool) (*data.ObjectInfo, []byte) {
	objInfo, err := tc.layer.GetObjectInfo(tc.ctx, &HeadObjectParams{
		BktInfo:   tc.bktInfo,
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

func (tc *testContext) deleteObject(objectName, versionID string, settings *data.BucketSettings) {
	p := &DeleteObjectParams{
		BktInfo:     tc.bktInfo,
		BktSettings: settings,
		Objects: []*VersionedObject{
			{Name: objectName, VersionID: versionID},
		},
	}
	deletedObjects, err := tc.layer.DeleteObjects(tc.ctx, p)
	require.NoError(tc.t, err)
	for _, obj := range deletedObjects {
		require.NoError(tc.t, obj.Error)
	}
}

func (tc *testContext) listObjectsV1() []*data.ObjectInfo {
	res, err := tc.layer.ListObjectsV1(tc.ctx, &ListObjectsParamsV1{
		ListObjectsParamsCommon: ListObjectsParamsCommon{
			BktInfo: tc.bktInfo,
			MaxKeys: 1000,
		},
	})
	require.NoError(tc.t, err)
	return res.Objects
}

func (tc *testContext) listObjectsV2() []*data.ObjectInfo {
	res, err := tc.layer.ListObjectsV2(tc.ctx, &ListObjectsParamsV2{
		ListObjectsParamsCommon: ListObjectsParamsCommon{
			BktInfo: tc.bktInfo,
			MaxKeys: 1000,
		},
	})
	require.NoError(tc.t, err)
	return res.Objects
}

func (tc *testContext) listVersions() *ListObjectVersionsInfo {
	res, err := tc.layer.ListObjectVersions(tc.ctx, &ListObjectVersionsParams{
		BktInfo: tc.bktInfo,
		MaxKeys: 1000,
	})
	require.NoError(tc.t, err)
	return res
}

func (tc *testContext) checkListObjects(ids ...oid.ID) {
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
	for _, obj := range tc.testNeoFS.Objects() {
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
	bktInfo   *data.BucketInfo
	obj       string
	testNeoFS *neofstest.TestNeoFS
}

func prepareContext(t *testing.T, cachesConfig ...*CachesConfig) *testContext {
	key, err := keys.NewPrivateKey()
	require.NoError(t, err)

	bearerToken := bearertest.Token()
	require.NoError(t, bearerToken.Sign(key.PrivateKey))

	ctx := context.WithValue(context.Background(), api.BoxData, &accessbox.Box{
		Gate: &accessbox.GateData{
			BearerToken: &bearerToken,
			GateKey:     key.PublicKey(),
		},
	})
	tp := neofstest.NewTestNeoFS()

	bktName := "testbucket1"
	bktID, err := tp.CreateContainer(ctx, neofs.PrmContainerCreate{
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
		layer: NewLayer(zap.NewNop(), tp, layerCfg),
		bktInfo: &data.BucketInfo{
			Name:  bktName,
			Owner: *usertest.ID(),
			CID:   *bktID,
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
	require.Contains(t, objv2.Headers[versionsAddAttr], obj1v1.ID.EncodeToString())

	_, buffer1 := tc.getObject(tc.obj, obj1v1.ID.EncodeToString(), false)
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
	require.Contains(t, objv2.Headers[versionsDelAttr], obj1v1.ID.EncodeToString())

	tc.getObject(tc.obj, obj1v1.ID.EncodeToString(), true)
	tc.checkListObjects(obj1v2.ID)
}

func TestVersioningDeleteObject(t *testing.T) {
	tc := prepareContext(t)
	settings := &data.BucketSettings{VersioningEnabled: true}
	err := tc.layer.PutBucketSettings(tc.ctx, &PutSettingsParams{
		BktInfo:  tc.bktInfo,
		Settings: settings,
	})
	require.NoError(t, err)

	tc.putObject([]byte("content obj1 v1"))
	tc.putObject([]byte("content obj1 v2"))

	tc.deleteObject(tc.obj, "", settings)
	tc.getObject(tc.obj, "", true)

	tc.checkListObjects()
}

func TestVersioningDeleteSpecificObjectVersion(t *testing.T) {
	tc := prepareContext(t)
	settings := &data.BucketSettings{VersioningEnabled: true}
	err := tc.layer.PutBucketSettings(tc.ctx, &PutSettingsParams{
		BktInfo:  tc.bktInfo,
		Settings: settings,
	})
	require.NoError(t, err)

	tc.putObject([]byte("content obj1 v1"))
	objV2Info := tc.putObject([]byte("content obj1 v2"))
	objV3Content := []byte("content obj1 v3")
	objV3Info := tc.putObject(objV3Content)

	tc.deleteObject(tc.obj, objV2Info.Version(), settings)
	tc.getObject(tc.obj, objV2Info.Version(), true)

	_, buffer3 := tc.getObject(tc.obj, "", false)
	require.Equal(t, objV3Content, buffer3)

	tc.deleteObject(tc.obj, "", settings)
	tc.getObject(tc.obj, "", true)

	for _, ver := range tc.listVersions().DeleteMarker {
		if ver.IsLatest {
			tc.deleteObject(tc.obj, ver.Object.Version(), settings)
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

	versioning, err := tc.layer.GetBucketSettings(tc.ctx, tc.bktInfo)
	require.NoError(t, err)

	tc.deleteObject(tc.obj, "", versioning)
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

func getOID(id byte) oid.ID {
	b := [32]byte{}
	b[31] = id

	var idObj oid.ID
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
		expectedIdsToDelete []oid.ID
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
			expectedIdsToDelete: []oid.ID{obj1.ID},
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
			expectedIdsToDelete: []oid.ID{obj2.ID},
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
			expectedIdsToDelete: []oid.ID{obj1.ID},
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

	cnrID, _ := objMeta.ContainerID()
	objID, _ := objMeta.ID()

	var addr oid.Address
	addr.SetContainer(cnrID)
	addr.SetObject(objID)

	// simulate failed deletion
	tc.testNeoFS.AddObject(addr.EncodeToString(), objMeta)

	versioning, err := tc.layer.GetBucketSettings(tc.ctx, tc.bktInfo)
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

	err := tc.layer.PutBucketTagging(tc.ctx, tc.bktInfo, tagSet)
	require.NoError(t, err)

	objMeta := tc.getSystemObject(formBucketTagObjectName(tc.bktInfo.CID.EncodeToString()))

	tagSet["tag2"] = "val2"
	err = tc.layer.PutBucketTagging(tc.ctx, tc.bktInfo, tagSet)
	require.NoError(t, err)

	// simulate failed deletion
	cnrID, _ := objMeta.ContainerID()
	objID, _ := objMeta.ID()
	tc.testNeoFS.AddObject(newAddress(cnrID, objID).EncodeToString(), objMeta)

	tagging, err := tc.layer.GetBucketTagging(tc.ctx, tc.bktInfo)
	require.NoError(t, err)

	expectedTagSet := map[string]string{
		"tag1": "val1",
		"tag2": "val2",
	}
	require.Equal(t, expectedTagSet, tagging)

	err = tc.layer.DeleteBucketTagging(tc.ctx, tc.bktInfo)
	require.NoError(t, err)

	require.Nil(t, tc.getSystemObject(formBucketTagObjectName(tc.bktInfo.Name)))
}
