package handler

import (
	"bytes"
	"context"
	"encoding/xml"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer/neofs"
	"github.com/nspcc-dev/neofs-s3-gw/api/resolver"
	"github.com/nspcc-dev/neofs-s3-gw/internal/neofstest"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type handlerContext struct {
	h  *handler
	tp *neofstest.TestNeoFS
}

func (hc *handlerContext) Handler() *handler {
	return hc.h
}

func (hc *handlerContext) MockedPool() *neofstest.TestNeoFS {
	return hc.tp
}

func (hc *handlerContext) Layer() layer.Client {
	return hc.h.obj
}

func prepareHandlerContext(t *testing.T) *handlerContext {
	key, err := keys.NewPrivateKey()
	require.NoError(t, err)

	l := zap.NewNop()
	tp := neofstest.NewTestNeoFS()

	testResolver := &resolver.BucketResolver{Name: "test_resolver"}
	testResolver.SetResolveFunc(func(_ context.Context, name string) (*cid.ID, error) {
		return tp.ContainerID(name)
	})

	layerCfg := &layer.Config{
		Caches:   layer.DefaultCachesConfigs(),
		AnonKey:  layer.AnonymousKey{Key: key},
		Resolver: testResolver,
	}

	h := &handler{
		log: l,
		obj: layer.NewLayer(l, tp, layerCfg),
		cfg: &Config{},
	}

	return &handlerContext{
		h:  h,
		tp: tp,
	}
}

func createTestBucket(ctx context.Context, t *testing.T, h *handlerContext, bktName string) {
	_, err := h.MockedPool().CreateContainer(ctx, neofs.PrmContainerCreate{
		Name: bktName,
	})
	require.NoError(t, err)
}

func createTestBucketWithLock(ctx context.Context, t *testing.T, h *handlerContext, bktName string, conf *data.ObjectLockConfiguration) *data.BucketInfo {
	cnrID, err := h.MockedPool().CreateContainer(ctx, neofs.PrmContainerCreate{
		Name:                 bktName,
		AdditionalAttributes: [][2]string{{layer.AttributeLockEnabled, "true"}},
	})
	require.NoError(t, err)

	var ownerID user.ID

	bktInfo := &data.BucketInfo{
		CID:               *cnrID,
		Name:              bktName,
		ObjectLockEnabled: true,
		Owner:             ownerID,
	}

	sp := &layer.PutSettingsParams{
		BktInfo: bktInfo,
		Settings: &data.BucketSettings{
			VersioningEnabled: true,
			LockConfiguration: conf,
		},
	}

	err = h.Layer().PutBucketSettings(ctx, sp)
	require.NoError(t, err)

	return bktInfo
}

func createTestObject(ctx context.Context, t *testing.T, h *handlerContext, bktInfo *data.BucketInfo, objName string) {
	content := make([]byte, 1024)
	_, err := rand.Read(content)
	require.NoError(t, err)

	_, err = h.Layer().PutObject(ctx, &layer.PutObjectParams{
		BktInfo: bktInfo,
		Object:  objName,
		Size:    int64(len(content)),
		Reader:  bytes.NewReader(content),
		Header:  make(map[string]string),
	})
	require.NoError(t, err)
}

func prepareTestRequest(t *testing.T, bktName, objName string, body interface{}) (*httptest.ResponseRecorder, *http.Request) {
	rawBody, err := xml.Marshal(body)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, defaultURL, bytes.NewReader(rawBody))

	reqInfo := api.NewReqInfo(w, r, api.ObjectRequest{Bucket: bktName, Object: objName})
	r = r.WithContext(api.SetReqInfo(r.Context(), reqInfo))

	return w, r
}
