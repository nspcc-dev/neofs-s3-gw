package layer

import (
	"bytes"
	"context"
	"encoding/json"
	errorsStd "errors"
	"fmt"
	"slices"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3errors"
	apistatus "github.com/nspcc-dev/neofs-sdk-go/client/status"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	"go.uber.org/zap"
)

type GetObjectTaggingParams struct {
	ObjectVersion *ObjectVersion

	// NodeVersion can be nil. If not nil we save one request to tree service.
	NodeVersion *data.NodeVersion // optional
}

type PutObjectTaggingParams struct {
	ObjectVersion *ObjectVersion
	TagSet        map[string]string

	CopiesNumber uint32

	// NodeVersion can be nil. If not nil we save one request to tree service.
	NodeVersion *data.NodeVersion // optional
}

const (
	attributeTagsMetaObject      = ".s3-tags-meta-object"
	attributeTagsMetaObjectValue = "true"
)

func (n *layer) PutObjectTagging(ctx context.Context, p *PutObjectTaggingParams) error {
	payload, err := json.Marshal(p.TagSet)
	if err != nil {
		return fmt.Errorf("could not marshal tag set: %w", err)
	}

	prm := PrmObjectCreate{
		Container:    p.ObjectVersion.BktInfo.CID,
		Creator:      p.ObjectVersion.BktInfo.Owner,
		CreationTime: TimeNow(ctx),
		CopiesNumber: p.CopiesNumber,
		Filepath:     p.ObjectVersion.ObjectName,
		Attributes:   make(map[string]string, 2),
		Payload:      bytes.NewBuffer(payload),
		PayloadSize:  uint64(len(payload)),
	}

	if p.ObjectVersion.VersionID != "" {
		prm.Attributes[AttributeObjectVersion] = p.ObjectVersion.VersionID
	}

	prm.Attributes[attributeTagsMetaObject] = attributeTagsMetaObjectValue

	if _, _, err = n.objectPutAndHash(ctx, prm, p.ObjectVersion.BktInfo); err != nil {
		return fmt.Errorf("create tagging object: %w", err)
	}

	n.cache.PutTagging(n.Owner(ctx), objectTaggingCacheKey(p.ObjectVersion), p.TagSet)

	return nil
}

func (n *layer) GetObjectTagging(ctx context.Context, p *GetObjectTaggingParams) (string, map[string]string, error) {
	var err error
	owner := n.Owner(ctx)

	if len(p.ObjectVersion.VersionID) != 0 && p.ObjectVersion.VersionID != data.UnversionedObjectVersionID {
		if tags := n.cache.GetTagging(owner, objectTaggingCacheKey(p.ObjectVersion)); tags != nil {
			return p.ObjectVersion.VersionID, tags, nil
		}
	}

	prmSearch := PrmObjectSearch{
		Container: p.ObjectVersion.BktInfo.CID,
		Filters:   make(object.SearchFilters, 0, 3),
	}

	n.prepareAuthParameters(ctx, &prmSearch.PrmAuth, p.ObjectVersion.BktInfo.Owner)
	prmSearch.Filters.AddFilter(object.AttributeFilePath, p.ObjectVersion.ObjectName, object.MatchStringEqual)
	prmSearch.Filters.AddFilter(attributeTagsMetaObject, attributeTagsMetaObjectValue, object.MatchStringEqual)
	prmSearch.Filters.AddTypeFilter(object.MatchStringEqual, object.TypeRegular)
	if p.ObjectVersion.VersionID != "" {
		prmSearch.Filters.AddFilter(AttributeObjectVersion, p.ObjectVersion.VersionID, object.MatchStringEqual)
	}

	ids, err := n.neoFS.SearchObjects(ctx, prmSearch)
	if err != nil {
		if errorsStd.Is(err, apistatus.ErrObjectAccessDenied) {
			return "", nil, s3errors.GetAPIError(s3errors.ErrAccessDenied)
		}

		return "", nil, fmt.Errorf("search object version: %w", err)
	}

	if len(ids) == 0 {
		return "", nil, nil
	}

	var (
		objects = make([]*object.Object, 0, len(ids))
	)

	for i := range ids {
		obj, err := n.objectGet(ctx, p.ObjectVersion.BktInfo, ids[i])
		if err != nil {
			n.log.Warn("couldn't obj object",
				zap.Stringer("oid", &ids[i]),
				zap.Stringer("cid", p.ObjectVersion.BktInfo.CID),
				zap.Error(err))

			return "", nil, fmt.Errorf("couldn't obj object: %w", err)
		}

		objects = append(objects, obj)
	}

	slices.SortFunc(objects, sortObjectsFunc)

	var (
		lastObj = objects[0]
		tags    = make(map[string]string)
	)

	if err = json.Unmarshal(lastObj.Payload(), &tags); err != nil {
		return "", nil, fmt.Errorf("couldn't unmarshal last object: %w", err)
	}

	return p.ObjectVersion.VersionID, tags, nil
}

func (n *layer) DeleteObjectTagging(ctx context.Context, p *ObjectVersion) error {
	prmSearch := PrmObjectSearch{
		Container: p.BktInfo.CID,
		Filters:   make(object.SearchFilters, 0, 3),
	}

	n.prepareAuthParameters(ctx, &prmSearch.PrmAuth, p.BktInfo.Owner)
	prmSearch.Filters.AddFilter(object.AttributeFilePath, p.ObjectName, object.MatchStringEqual)
	prmSearch.Filters.AddFilter(attributeTagsMetaObject, "true", object.MatchStringEqual)
	prmSearch.Filters.AddTypeFilter(object.MatchStringEqual, object.TypeRegular)
	if p.VersionID != "" {
		prmSearch.Filters.AddFilter(AttributeObjectVersion, p.VersionID, object.MatchStringEqual)
	}

	ids, err := n.neoFS.SearchObjects(ctx, prmSearch)
	if err != nil {
		if errorsStd.Is(err, apistatus.ErrObjectAccessDenied) {
			return s3errors.GetAPIError(s3errors.ErrAccessDenied)
		}

		return fmt.Errorf("search object version: %w", err)
	}

	if len(ids) == 0 {
		return nil
	}

	for _, id := range ids {
		if err = n.objectDelete(ctx, p.BktInfo, id); err != nil {
			return fmt.Errorf("couldn't delete object: %w", err)
		}
	}

	n.cache.DeleteTagging(objectTaggingCacheKey(p))

	return nil
}

func (n *layer) GetBucketTagging(ctx context.Context, bktInfo *data.BucketInfo) (map[string]string, error) {
	owner := n.Owner(ctx)

	if tags := n.cache.GetTagging(owner, bucketTaggingCacheKey(bktInfo.CID)); tags != nil {
		return tags, nil
	}

	tags, err := n.treeService.GetBucketTagging(ctx, bktInfo)
	if err != nil {
		if errorsStd.Is(err, ErrNodeNotFound) {
			return nil, s3errors.GetAPIError(s3errors.ErrBucketTaggingNotFound)
		}

		return nil, err
	}

	if len(tags) == 0 {
		return nil, s3errors.GetAPIError(s3errors.ErrBucketTaggingNotFound)
	}

	n.cache.PutTagging(owner, bucketTaggingCacheKey(bktInfo.CID), tags)

	return tags, nil
}

func (n *layer) PutBucketTagging(ctx context.Context, bktInfo *data.BucketInfo, tagSet map[string]string) error {
	if err := n.treeService.PutBucketTagging(ctx, bktInfo, tagSet); err != nil {
		return err
	}

	n.cache.PutTagging(n.Owner(ctx), bucketTaggingCacheKey(bktInfo.CID), tagSet)

	return nil
}

func (n *layer) DeleteBucketTagging(ctx context.Context, bktInfo *data.BucketInfo) error {
	n.cache.DeleteTagging(bucketTaggingCacheKey(bktInfo.CID))

	return n.treeService.DeleteBucketTagging(ctx, bktInfo)
}

func objectTaggingCacheKey(p *ObjectVersion) string {
	return ".tagset." + p.BktInfo.CID.EncodeToString() + "." + p.ObjectName + "." + p.VersionID
}

func bucketTaggingCacheKey(cnrID cid.ID) string {
	return ".tagset." + cnrID.EncodeToString()
}
