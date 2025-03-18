package layer

import (
	"context"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
)

type TreeServiceMock struct {
	settings map[string]*data.BucketSettings
}

func (t *TreeServiceMock) GetBucketTagging(_ context.Context, _ *data.BucketInfo) (map[string]string, error) {
	// TODO implement me
	panic("implement me")
}

func (t *TreeServiceMock) PutBucketTagging(_ context.Context, _ *data.BucketInfo, _ map[string]string, _ uint32) error {
	// TODO implement me
	panic("implement me")
}

func (t *TreeServiceMock) DeleteBucketTagging(_ context.Context, _ *data.BucketInfo) error {
	// TODO implement me
	panic("implement me")
}

func NewTreeService() *TreeServiceMock {
	return &TreeServiceMock{
		settings: make(map[string]*data.BucketSettings),
	}
}

func (t *TreeServiceMock) PutSettingsNode(_ context.Context, bktInfo *data.BucketInfo, settings *data.BucketSettings) error {
	t.settings[bktInfo.CID.EncodeToString()] = settings
	return nil
}

func (t *TreeServiceMock) GetSettingsNode(_ context.Context, bktInfo *data.BucketInfo) (*data.BucketSettings, error) {
	settings, ok := t.settings[bktInfo.CID.EncodeToString()]
	if !ok {
		return nil, ErrNodeNotFound
	}

	return settings, nil
}

func (t *TreeServiceMock) GetNotificationConfigurationNode(_ context.Context, _ *data.BucketInfo) (oid.ID, error) {
	panic("implement me")
}

func (t *TreeServiceMock) PutNotificationConfigurationNode(_ context.Context, _ *data.BucketInfo, _ oid.ID) (oid.ID, error) {
	panic("implement me")
}

func (t *TreeServiceMock) GetBucketCORS(_ context.Context, _ *data.BucketInfo) (oid.ID, error) {
	panic("implement me")
}

func (t *TreeServiceMock) PutBucketCORS(_ context.Context, _ *data.BucketInfo, _ oid.ID) (oid.ID, error) {
	panic("implement me")
}

func (t *TreeServiceMock) DeleteBucketCORS(_ context.Context, _ *data.BucketInfo) (oid.ID, error) {
	panic("implement me")
}
