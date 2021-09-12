package layer

import (
	"context"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/cache"
)

func (n *layer) PutBucketCORS(ctx context.Context, p *PutCORSParams) error {
	s := &PutSystemObjectParams{
		bktInfo:  p.BktInfo,
		objName:  p.BktInfo.CORSObjectName(),
		metadata: nil,
		prefix:   "",
		payload:  p.CORSConfigurationJSON,
	}

	if _, err := n.putSystemObject(ctx, s); err != nil {
		return err
	}

	return nil
}

func (n *layer) GetBucketCORS(ctx context.Context, bktInfo *api.BucketInfo) ([]byte, error) {
	obj, err := n.getSystemObject(ctx, bktInfo, bktInfo.CORSObjectName(), true)
	if err != nil {
		return nil, err
	}

	return obj.Payload(), nil
}

func (n *layer) DeleteBucketCORS(ctx context.Context, bktInfo *api.BucketInfo) error {
	oid, err := n.objectFindID(ctx, &findParams{cid: bktInfo.CID, attr: objectSystemAttributeName, val: bktInfo.CORSObjectName()})
	if err != nil {
		return err
	}

	if err := n.objectDelete(ctx, bktInfo.CID, oid); err != nil {
		return err
	}

	n.systemCache.Delete(cache.SystemObjectKey(bktInfo.Name, bktInfo.CORSObjectName()))

	return nil
}
