package layer

import (
	"context"
	errorsStd "errors"
	"strings"

	"go.uber.org/zap"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
)

func (n *layer) GetObjectTagging(ctx context.Context, p *data.ObjectTaggingInfo) (map[string]string, error) {
	var (
		err  error
		tags map[string]string
	)
	tags = n.systemCache.GetObjectTagging(objectTaggingCacheKey(p))
	if tags != nil {
		return tags, nil
	}

	version, err := n.getTaggedObjectVersion(ctx, p)
	if err != nil {
		return nil, err
	}

	tags, err = n.treeService.GetObjectTagging(ctx, p.CnrID, version)
	if err != nil {
		if errorsStd.Is(err, ErrNodeNotFound) {
			return nil, errors.GetAPIError(errors.ErrNoSuchKey)
		}
		return nil, err
	}

	if err = n.systemCache.PutObjectTagging(objectTaggingCacheKey(p), tags); err != nil {
		n.log.Error("couldn't cache system object", zap.Error(err))
	}

	return tags, nil
}

func (n *layer) PutObjectTagging(ctx context.Context, p *data.ObjectTaggingInfo, tagSet map[string]string) error {
	version, err := n.getTaggedObjectVersion(ctx, p)
	if err != nil {
		return err
	}

	err = n.treeService.PutObjectTagging(ctx, p.CnrID, version, tagSet)
	if err != nil {
		if errorsStd.Is(err, ErrNodeNotFound) {
			return errors.GetAPIError(errors.ErrNoSuchKey)
		}
		return err
	}

	if err = n.systemCache.PutObjectTagging(objectTaggingCacheKey(p), tagSet); err != nil {
		n.log.Error("couldn't cache system object", zap.Error(err))
	}

	return nil
}

func (n *layer) DeleteObjectTagging(ctx context.Context, p *data.ObjectTaggingInfo) error {
	version, err := n.getTaggedObjectVersion(ctx, p)
	if err != nil {
		return err
	}

	err = n.treeService.DeleteObjectTagging(ctx, p.CnrID, version)
	if err != nil {
		if errorsStd.Is(err, ErrNodeNotFound) {
			return errors.GetAPIError(errors.ErrNoSuchKey)
		}
		return err
	}

	n.systemCache.Delete(objectTaggingCacheKey(p))

	return nil
}

func (n *layer) GetBucketTagging(ctx context.Context, bktInfo *data.BucketInfo) (map[string]string, error) {
	objInfo, err := n.HeadSystemObject(ctx, bktInfo, formBucketTagObjectName(bktInfo.Name))
	if err != nil && !errors.IsS3Error(err, errors.ErrNoSuchKey) {
		return nil, err
	}

	return formTagSet(objInfo), nil
}

func (n *layer) PutBucketTagging(ctx context.Context, bktInfo *data.BucketInfo, tagSet map[string]string) error {
	s := &PutSystemObjectParams{
		BktInfo:  bktInfo,
		ObjName:  formBucketTagObjectName(bktInfo.Name),
		Metadata: tagSet,
		Prefix:   tagPrefix,
		Reader:   nil,
	}

	_, err := n.PutSystemObject(ctx, s)
	return err
}

func (n *layer) DeleteBucketTagging(ctx context.Context, bktInfo *data.BucketInfo) error {
	return n.DeleteSystemObject(ctx, bktInfo, formBucketTagObjectName(bktInfo.Name))
}

func formTagSet(objInfo *data.ObjectInfo) map[string]string {
	var tagSet map[string]string
	if objInfo != nil {
		tagSet = make(map[string]string, len(objInfo.Headers))
		for k, v := range objInfo.Headers {
			if strings.HasPrefix(k, tagPrefix) {
				if v == tagEmptyMark {
					v = ""
				}
				tagSet[strings.TrimPrefix(k, tagPrefix)] = v
			}
		}
	}

	return tagSet
}

func objectTaggingCacheKey(p *data.ObjectTaggingInfo) string {
	return ".tagset." + p.CnrID.EncodeToString() + "." + p.ObjName + "." + p.VersionID
}

func (n *layer) getTaggedObjectVersion(ctx context.Context, p *data.ObjectTaggingInfo) (*data.NodeVersion, error) {
	var (
		err     error
		version *data.NodeVersion
	)

	if p.VersionID == "null" {
		if version, err = n.treeService.GetUnversioned(ctx, p.CnrID, p.ObjName); err != nil {
			if strings.Contains(err.Error(), "not found") {
				return nil, errors.GetAPIError(errors.ErrNoSuchKey)
			}
			return nil, err
		}
	} else if len(p.VersionID) == 0 {
		if version, err = n.treeService.GetLatestVersion(ctx, p.CnrID, p.ObjName); err != nil {
			if strings.Contains(err.Error(), "not found") {
				return nil, errors.GetAPIError(errors.ErrNoSuchKey)
			}
			return nil, err
		}
	} else {
		versions, err := n.treeService.GetVersions(ctx, p.CnrID, p.ObjName)
		if err != nil {
			return nil, err
		}
		for _, v := range versions {
			if v.OID.EncodeToString() == p.VersionID {
				version = v
				break
			}
		}
	}

	if version == nil || version.DeleteMarker != nil {
		return nil, errors.GetAPIError(errors.ErrNoSuchKey)
	}

	return version, nil
}
