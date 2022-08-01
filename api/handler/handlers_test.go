package handler

import (
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/nspcc-dev/neofs-s3-gw/api/resolver"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	usertest "github.com/nspcc-dev/neofs-sdk-go/user/test"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type handlerContext struct {
	h       *handler
	tp      *layer.TestNeoFS
	context context.Context
}

func (hc *handlerContext) Handler() *handler {
	return hc.h
}

func (hc *handlerContext) MockedPool() *layer.TestNeoFS {
	return hc.tp
}

func (hc *handlerContext) Layer() layer.Client {
	return hc.h.obj
}

func (hc *handlerContext) Context() context.Context {
	return hc.context
}

func prepareHandlerContext(t *testing.T) *handlerContext {
	key, err := keys.NewPrivateKey()
	require.NoError(t, err)

	l := zap.NewExample()
	tp := layer.NewTestNeoFS()

	testResolver := &resolver.BucketResolver{Name: "test_resolver"}
	testResolver.SetResolveFunc(func(_ context.Context, name string) (cid.ID, error) {
		return tp.ContainerID(name)
	})

	layerCfg := &layer.Config{
		Caches:      layer.DefaultCachesConfigs(zap.NewExample()),
		AnonKey:     layer.AnonymousKey{Key: key},
		Resolver:    testResolver,
		TreeService: layer.NewTreeService(),
	}

	h := &handler{
		log: l,
		obj: layer.NewLayer(l, tp, layerCfg),
		cfg: &Config{},
	}

	return &handlerContext{
		h:       h,
		tp:      tp,
		context: context.Background(),
	}
}

func createTestBucket(ctx context.Context, t *testing.T, h *handlerContext, bktName string) *data.BucketInfo {
	_, err := h.MockedPool().CreateContainer(ctx, layer.PrmContainerCreate{
		Creator: *usertest.ID(),
		Name:    bktName,
	})
	require.NoError(t, err)

	bktInfo, err := h.Layer().GetBucketInfo(ctx, bktName)
	require.NoError(t, err)
	return bktInfo
}

func createTestBucketWithLock(ctx context.Context, t *testing.T, h *handlerContext, bktName string, conf *data.ObjectLockConfiguration) *data.BucketInfo {
	cnrID, err := h.MockedPool().CreateContainer(ctx, layer.PrmContainerCreate{
		Creator:              *usertest.ID(),
		Name:                 bktName,
		AdditionalAttributes: [][2]string{{layer.AttributeLockEnabled, "true"}},
	})
	require.NoError(t, err)

	var ownerID user.ID

	bktInfo := &data.BucketInfo{
		CID:               cnrID,
		Name:              bktName,
		ObjectLockEnabled: true,
		Owner:             ownerID,
	}

	sp := &layer.PutSettingsParams{
		BktInfo: bktInfo,
		Settings: &data.BucketSettings{
			Versioning:        data.VersioningEnabled,
			LockConfiguration: conf,
		},
	}

	err = h.Layer().PutBucketSettings(ctx, sp)
	require.NoError(t, err)

	return bktInfo
}

func createTestObject(ctx context.Context, t *testing.T, h *handlerContext, bktInfo *data.BucketInfo, objName string) *data.ObjectInfo {
	content := make([]byte, 1024)
	_, err := rand.Read(content)
	require.NoError(t, err)

	header := map[string]string{
		object.AttributeTimestamp: strconv.FormatInt(time.Now().UTC().Unix(), 10),
	}

	objInfo, err := h.Layer().PutObject(ctx, &layer.PutObjectParams{
		BktInfo: bktInfo,
		Object:  objName,
		Size:    int64(len(content)),
		Reader:  bytes.NewReader(content),
		Header:  header,
	})
	require.NoError(t, err)

	return objInfo
}

func prepareTestRequest(t *testing.T, bktName, objName string, body interface{}) (*httptest.ResponseRecorder, *http.Request) {
	return prepareTestFullRequest(t, bktName, objName, make(url.Values), body)
}

func prepareTestFullRequest(t *testing.T, bktName, objName string, query url.Values, body interface{}) (*httptest.ResponseRecorder, *http.Request) {
	rawBody, err := xml.Marshal(body)
	require.NoError(t, err)

	return prepareTestRequestWithQuery(bktName, objName, query, rawBody)
}

func prepareTestRequestWithQuery(bktName, objName string, query url.Values, body []byte) (*httptest.ResponseRecorder, *http.Request) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, defaultURL, bytes.NewReader(body))
	r.URL.RawQuery = query.Encode()

	reqInfo := api.NewReqInfo(w, r, api.ObjectRequest{Bucket: bktName, Object: objName})
	r = r.WithContext(api.SetReqInfo(r.Context(), reqInfo))

	return w, r
}

func prepareTestPayloadRequest(bktName, objName string, payload io.Reader) (*httptest.ResponseRecorder, *http.Request) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, defaultURL, payload)

	reqInfo := api.NewReqInfo(w, r, api.ObjectRequest{Bucket: bktName, Object: objName})
	r = r.WithContext(api.SetReqInfo(r.Context(), reqInfo))

	return w, r
}

func parseTestResponse(t *testing.T, response *httptest.ResponseRecorder, body interface{}) {
	assertStatus(t, response, http.StatusOK)
	err := xml.NewDecoder(response.Result().Body).Decode(body)
	require.NoError(t, err)
}

func existInMockedNeoFS(tc *handlerContext, bktInfo *data.BucketInfo, objInfo *data.ObjectInfo) bool {
	p := &layer.GetObjectParams{
		BucketInfo: bktInfo,
		ObjectInfo: objInfo,
		Writer:     io.Discard,
	}

	return tc.Layer().GetObject(tc.Context(), p) == nil
}

func listOIDsFromMockedNeoFS(t *testing.T, tc *handlerContext, bktName, objectName string) []oid.ID {
	bktInfo, err := tc.Layer().GetBucketInfo(tc.Context(), bktName)
	require.NoError(t, err)

	p := layer.PrmObjectSelect{
		Container: bktInfo.CID,
		ExactAttribute: [2]string{
			object.AttributeFileName, objectName,
		},
	}
	ids, err := tc.MockedPool().SelectObjects(tc.Context(), p)
	require.NoError(t, err)

	return ids
}

func assertStatus(t *testing.T, w *httptest.ResponseRecorder, status int) {
	if w.Code != status {
		resp, err := io.ReadAll(w.Result().Body)
		require.NoError(t, err)
		require.Failf(t, "unexpected status", "expected: %d, actual: %d, resp: '%s'", status, w.Code, string(resp))
	}
}

func readResponse(t *testing.T, w *httptest.ResponseRecorder, status int, model interface{}) {
	assertStatus(t, w, status)
	err := xml.NewDecoder(w.Result().Body).Decode(model)
	require.NoError(t, err)
}
