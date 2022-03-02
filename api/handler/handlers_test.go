package handler

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/nspcc-dev/neofs-s3-gw/api"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"

	"github.com/nspcc-dev/neofs-s3-gw/api/resolver"
	"github.com/nspcc-dev/neofs-sdk-go/container"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/nspcc-dev/neofs-s3-gw/api/mock"
	"github.com/nspcc-dev/neofs-sdk-go/logger"
	"github.com/stretchr/testify/require"
)

type handlerContext struct {
	h  *handler
	tp *mock.TestPool
}

func (hc *handlerContext) Handler() *handler {
	return hc.h
}

func (hc *handlerContext) MockedPool() *mock.TestPool {
	return hc.tp
}

func (hc *handlerContext) Layer() layer.Client {
	return hc.h.obj
}

func prepareHandlerContext(t *testing.T) *handlerContext {
	key, err := keys.NewPrivateKey()
	require.NoError(t, err)

	l, err := logger.New(logger.WithTraceLevel("panic"))
	require.NoError(t, err)
	tp := mock.NewTestPool()

	testResolver := &resolver.BucketResolver{Name: "test_resolver"}
	testResolver.SetResolveFunc(func(ctx context.Context, name string) (*cid.ID, error) {
		for id, cnr := range tp.Containers {
			for _, attr := range cnr.Attributes() {
				if attr.Key() == container.AttributeName && attr.Value() == name {
					cnrID := cid.New()
					return cnrID, cnrID.Parse(id)
				}
			}
		}
		return nil, fmt.Errorf("couldn't resolve container name")
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
	cnr := container.New(container.WithAttribute(container.AttributeName, bktName))
	_, err := h.MockedPool().PutContainer(ctx, cnr)
	require.NoError(t, err)
}

func createTestBucketWithLock(ctx context.Context, t *testing.T, h *handlerContext, bktName string, conf *data.ObjectLockConfiguration) {
	cnr := container.New(container.WithAttribute(container.AttributeName, bktName),
		container.WithAttribute(layer.AttributeLockEnabled, strconv.FormatBool(true)))
	cnrID, err := h.MockedPool().PutContainer(ctx, cnr)
	require.NoError(t, err)

	sp := &layer.PutSettingsParams{
		BktInfo: &data.BucketInfo{
			CID:               cnrID,
			Name:              bktName,
			ObjectLockEnabled: true,
		},
		Settings: &data.BucketSettings{
			VersioningEnabled: true,
			LockConfiguration: conf,
		},
	}

	err = h.Layer().PutBucketSettings(ctx, sp)
	require.NoError(t, err)
}

func createTestObject(ctx context.Context, t *testing.T, h *handlerContext, bktName, objName string) {
	content := make([]byte, 1024)
	_, err := rand.Read(content)
	require.NoError(t, err)

	_, err = h.Layer().PutObject(ctx, &layer.PutObjectParams{
		Bucket: bktName,
		Object: objName,
		Size:   int64(len(content)),
		Reader: bytes.NewReader(content),
		Header: make(map[string]string),
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
