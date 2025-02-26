package layer

import (
	"context"
	errorsStd "errors"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3errors"
)

func (n *layer) GetObjectTaggingAndLock(ctx context.Context, objVersion *ObjectVersion) (map[string]string, *data.LockInfo, error) {
	var err error
	owner := n.Owner(ctx)

	tags := n.cache.GetTagging(owner, objectTaggingCacheKey(objVersion))
	lockInfo := n.cache.GetLockInfo(owner, lockObjectKey(objVersion))

	if tags != nil && lockInfo != nil {
		return tags, lockInfo, nil
	}

	var p = GetObjectTaggingParams{
		ObjectVersion: objVersion,
	}

	_, tags, err = n.GetObjectTagging(ctx, &p)
	if err != nil {
		if errorsStd.Is(err, ErrNodeNotFound) {
			return nil, nil, s3errors.GetAPIError(s3errors.ErrNoSuchKey)
		}
		return nil, nil, err
	}

	lockInfo, err = n.getLockDataFromObjects(ctx, objVersion.BktInfo, objVersion.ObjectName, objVersion.VersionID)
	if err != nil {
		// lock info can be missed - OK. Despite it some tags above may appear, and we should return them.
		if !errorsStd.Is(err, ErrNodeNotFound) {
			return nil, nil, err
		}
	}

	n.cache.PutTagging(owner, objectTaggingCacheKey(objVersion), tags)
	if lockInfo != nil {
		if !lockInfo.LegalHold().IsZero() || lockInfo.Retention().IsZero() {
			n.cache.PutLockInfo(owner, lockObjectKey(objVersion), lockInfo)
		}
	} else {
		lockInfo = &data.LockInfo{}
	}

	return tags, lockInfo, nil
}
