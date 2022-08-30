package layer

import (
	"context"
	errorsStd "errors"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"go.uber.org/zap"
)

func (n *layer) GetObjectTagging(ctx context.Context, p *ObjectVersion) (string, map[string]string, error) {
	var (
		err  error
		tags map[string]string
	)

	if len(p.VersionID) != 0 && p.VersionID != data.UnversionedObjectVersionID {
		tags = n.systemCache.GetTagging(objectTaggingCacheKey(p))
		if tags != nil {
			return p.VersionID, tags, nil
		}
	}

	version, err := n.getNodeVersion(ctx, p)
	if err != nil {
		return "", nil, err
	}
	p.VersionID = version.OID.EncodeToString()

	tags = n.systemCache.GetTagging(objectTaggingCacheKey(p))
	if tags != nil {
		return p.VersionID, tags, nil
	}

	tags, err = n.treeService.GetObjectTagging(ctx, p.BktInfo.CID, version)
	if err != nil {
		if errorsStd.Is(err, ErrNodeNotFound) {
			return "", nil, errors.GetAPIError(errors.ErrNoSuchKey)
		}
		return "", nil, err
	}

	if err = n.systemCache.PutTagging(objectTaggingCacheKey(p), tags); err != nil {
		n.log.Error("couldn't cache system object", zap.Error(err))
	}

	return p.VersionID, tags, nil
}

func (n *layer) PutObjectTagging(ctx context.Context, p *ObjectVersion, tagSet map[string]string) (*data.NodeVersion, error) {
	version, err := n.getNodeVersion(ctx, p)
	if err != nil {
		return nil, err
	}
	p.VersionID = version.OID.EncodeToString()

	err = n.treeService.PutObjectTagging(ctx, p.BktInfo.CID, version, tagSet)
	if err != nil {
		if errorsStd.Is(err, ErrNodeNotFound) {
			return nil, errors.GetAPIError(errors.ErrNoSuchKey)
		}
		return nil, err
	}

	if err = n.systemCache.PutTagging(objectTaggingCacheKey(p), tagSet); err != nil {
		n.log.Error("couldn't cache system object", zap.Error(err))
	}

	return version, nil
}

func (n *layer) DeleteObjectTagging(ctx context.Context, p *ObjectVersion) (*data.NodeVersion, error) {
	version, err := n.getNodeVersion(ctx, p)
	if err != nil {
		return nil, err
	}

	err = n.treeService.DeleteObjectTagging(ctx, p.BktInfo.CID, version)
	if err != nil {
		if errorsStd.Is(err, ErrNodeNotFound) {
			return nil, errors.GetAPIError(errors.ErrNoSuchKey)
		}
		return nil, err
	}

	p.VersionID = version.OID.EncodeToString()

	n.systemCache.Delete(objectTaggingCacheKey(p))

	return version, nil
}

func (n *layer) GetBucketTagging(ctx context.Context, cnrID cid.ID) (map[string]string, error) {
	var (
		err  error
		tags map[string]string
	)

	tags = n.systemCache.GetTagging(bucketTaggingCacheKey(cnrID))
	if tags != nil {
		return tags, nil
	}

	if tags, err = n.treeService.GetBucketTagging(ctx, cnrID); err != nil && !errorsStd.Is(err, ErrNodeNotFound) {
		return nil, err
	}

	if err := n.systemCache.PutTagging(bucketTaggingCacheKey(cnrID), tags); err != nil {
		n.log.Error("couldn't cache system object", zap.Error(err))
	}

	return tags, nil
}

func (n *layer) PutBucketTagging(ctx context.Context, cnrID cid.ID, tagSet map[string]string) error {
	if err := n.treeService.PutBucketTagging(ctx, cnrID, tagSet); err != nil {
		return err
	}
	if err := n.systemCache.PutTagging(bucketTaggingCacheKey(cnrID), tagSet); err != nil {
		n.log.Error("couldn't cache system object", zap.Error(err))
	}

	return nil
}

func (n *layer) DeleteBucketTagging(ctx context.Context, cnrID cid.ID) error {
	n.systemCache.Delete(bucketTaggingCacheKey(cnrID))

	return n.treeService.DeleteBucketTagging(ctx, cnrID)
}

func objectTaggingCacheKey(p *ObjectVersion) string {
	return ".tagset." + p.BktInfo.CID.EncodeToString() + "." + p.ObjectName + "." + p.VersionID
}

func bucketTaggingCacheKey(cnrID cid.ID) string {
	return ".tagset." + cnrID.EncodeToString()
}

func (n *layer) getNodeVersion(ctx context.Context, objVersion *ObjectVersion) (*data.NodeVersion, error) {
	var err error
	var version *data.NodeVersion

	if objVersion.VersionID == data.UnversionedObjectVersionID {
		version, err = n.treeService.GetUnversioned(ctx, objVersion.BktInfo.CID, objVersion.ObjectName)
	} else if len(objVersion.VersionID) == 0 {
		version, err = n.treeService.GetLatestVersion(ctx, objVersion.BktInfo.CID, objVersion.ObjectName)
	} else {
		versions, err2 := n.treeService.GetVersions(ctx, objVersion.BktInfo.CID, objVersion.ObjectName)
		if err2 != nil {
			return nil, err2
		}
		for _, v := range versions {
			if v.OID.EncodeToString() == objVersion.VersionID {
				version = v
				break
			}
		}
		if version == nil {
			err = errors.GetAPIError(errors.ErrNoSuchVersion)
		}
	}

	if err == nil && version.IsDeleteMarker() && !objVersion.NoErrorOnDeleteMarker || errorsStd.Is(err, ErrNodeNotFound) {
		return nil, errors.GetAPIError(errors.ErrNoSuchKey)
	}

	return version, err
}

func (n *layer) getNodeVersionFromCache(o *ObjectVersion) *data.NodeVersion {
	if len(o.VersionID) == 0 || o.VersionID == data.UnversionedObjectVersionID {
		return nil
	}

	var objID oid.ID
	if objID.DecodeString(o.VersionID) != nil {
		return nil
	}

	var addr oid.Address
	addr.SetContainer(o.BktInfo.CID)
	addr.SetObject(objID)

	extObjectInfo := n.objCache.GetObject(addr)
	if extObjectInfo == nil {
		return nil
	}

	return extObjectInfo.NodeVersion
}
