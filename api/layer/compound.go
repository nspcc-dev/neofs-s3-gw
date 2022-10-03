package layer

import (
	"context"
	errorsStd "errors"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
)

func (n *layer) GetObjectTaggingAndLock(ctx context.Context, objVersion *ObjectVersion, nodeVersion *data.NodeVersion) (map[string]string, *data.LockInfo, error) {
	var (
		err  error
		tags map[string]string
	)

	tags = n.cache.GetTagging(objectTaggingCacheKey(objVersion))
	lockInfo := n.cache.GetLockInfo(lockObjectKey(objVersion))

	if tags != nil && lockInfo != nil {
		return tags, lockInfo, nil
	}

	if nodeVersion == nil {
		nodeVersion, err = n.getNodeVersion(ctx, objVersion)
		if err != nil {
			return nil, nil, err
		}
	}

	tags, lockInfo, err = n.treeService.GetObjectTaggingAndLock(ctx, objVersion.BktInfo, nodeVersion)
	if err != nil {
		if errorsStd.Is(err, ErrNodeNotFound) {
			return nil, nil, errors.GetAPIError(errors.ErrNoSuchKey)
		}
		return nil, nil, err
	}

	n.cache.PutTagging(objectTaggingCacheKey(objVersion), tags)
	n.cache.PutLockInfo(lockObjectKey(objVersion), lockInfo)

	return tags, lockInfo, nil
}
