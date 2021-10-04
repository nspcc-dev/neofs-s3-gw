package layer

import (
	"context"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
)

func (n *layer) PutBucketCORS(ctx context.Context, p *PutCORSParams) error {
	s := &PutSystemObjectParams{
		BktInfo:  p.BktInfo,
		ObjName:  p.BktInfo.CORSObjectName(),
		Metadata: map[string]string{},
		Prefix:   "",
		Payload:  p.CORSConfiguration,
	}

	_, err := n.putSystemObject(ctx, s)

	return err
}

func (n *layer) GetBucketCORS(ctx context.Context, bktInfo *data.BucketInfo) ([]byte, error) {
	obj, err := n.getSystemObject(ctx, bktInfo, bktInfo.CORSObjectName())
	if err != nil {
		if errors.IsS3Error(err, errors.ErrNoSuchKey) {
			return nil, errors.GetAPIError(errors.ErrNoSuchCORSConfiguration)
		}
		return nil, err
	}

	if obj.Payload() == nil {
		return nil, errors.GetAPIError(errors.ErrInternalError)
	}

	return obj.Payload(), nil
}

func (n *layer) DeleteBucketCORS(ctx context.Context, bktInfo *data.BucketInfo) error {
	return n.deleteSystemObject(ctx, bktInfo, bktInfo.CORSObjectName())
}
