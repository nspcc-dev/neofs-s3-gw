package layer

import (
	"context"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
)

type TreeServiceMock struct {
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
	return &TreeServiceMock{}
}
