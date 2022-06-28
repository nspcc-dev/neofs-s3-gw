package layer

import (
	"context"
	errorsStd "errors"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"go.uber.org/zap"
)

func (n *layer) GetObjectTaggingAndLock(ctx context.Context, objVersion *ObjectVersion, nodeVersion *data.NodeVersion) (map[string]string, *data.LockInfo, error) {
	var (
		err  error
		tags map[string]string
	)

	tags = n.systemCache.GetTagging(objectTaggingCacheKey(objVersion))
	lockInfo := n.systemCache.GetLockInfo(lockObjectKey(objVersion))

	if tags != nil && lockInfo != nil {
		return tags, lockInfo, nil
	}

	if nodeVersion == nil {
		nodeVersion, err = n.getNodeVersion(ctx, objVersion)
		if err != nil {
			return nil, nil, err
		}
	}

	tags, lockInfo, err = n.treeService.GetObjectTaggingAndLock(ctx, objVersion.BktInfo.CID, nodeVersion)
	if err != nil {
		if errorsStd.Is(err, ErrNodeNotFound) {
			return nil, nil, errors.GetAPIError(errors.ErrNoSuchKey)
		}
		return nil, nil, err
	}

	if err = n.systemCache.PutTagging(objectTaggingCacheKey(objVersion), tags); err != nil {
		n.log.Error("couldn't cache system object", zap.Error(err))
	}

	if err = n.systemCache.PutLockInfo(lockObjectKey(objVersion), lockInfo); err != nil {
		n.log.Error("couldn't cache system object", zap.Error(err))
	}

	return tags, lockInfo, nil
}
