package layer

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3errors"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3headers"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	apistatus "github.com/nspcc-dev/neofs-sdk-go/client/status"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
)

type GetObjectTaggingParams struct {
	ObjectVersion *ObjectVersion
}

type PutObjectTaggingParams struct {
	ObjectVersion *ObjectVersion
	TagSet        map[string]string

	CopiesNumber uint32
}

type taggingSearchResult struct {
	ID                oid.ID
	FilePath          string
	CreationEpoch     uint64
	CreationTimestamp int64
}

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
		prm.Attributes[attrS3VersioningState] = data.VersioningEnabled
	}

	prm.Attributes[s3headers.MetaType] = s3headers.TypeTags

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

	var (
		filters             = make(object.SearchFilters, 0, 4)
		returningAttributes = []string{
			object.AttributeFilePath,
			object.FilterCreationEpoch,
			object.AttributeTimestamp,
		}

		opts client.SearchObjectsOptions
	)

	if bt := bearerTokenFromContext(ctx, owner); bt != nil {
		opts.WithBearerToken(*bt)
	}

	filters.AddFilter(object.AttributeFilePath, p.ObjectVersion.ObjectName, object.MatchStringEqual)
	filters.AddFilter(s3headers.MetaType, s3headers.TypeTags, object.MatchStringEqual)
	filters.AddTypeFilter(object.MatchStringEqual, object.TypeRegular)
	if p.ObjectVersion.VersionID != "" {
		filters.AddFilter(AttributeObjectVersion, p.ObjectVersion.VersionID, object.MatchStringEqual)
	}

	searchResultItems, err := n.neoFS.SearchObjectsV2(ctx, p.ObjectVersion.BktInfo.CID, filters, returningAttributes, opts)
	if err != nil {
		if errors.Is(err, apistatus.ErrObjectAccessDenied) {
			return "", nil, s3errors.GetAPIError(s3errors.ErrAccessDenied)
		}

		return "", nil, fmt.Errorf("search object version: %w", err)
	}

	if len(searchResultItems) == 0 {
		return "", nil, nil
	}

	var searchResults = make([]taggingSearchResult, 0, len(searchResultItems))

	for _, item := range searchResultItems {
		if len(item.Attributes) != len(returningAttributes) {
			return "", nil, fmt.Errorf("invalid attribute count returned, expected %d, got %d", len(returningAttributes), len(item.Attributes))
		}

		var psr = taggingSearchResult{
			ID:       item.ID,
			FilePath: item.Attributes[0],
		}

		if item.Attributes[1] != "" {
			psr.CreationEpoch, err = strconv.ParseUint(item.Attributes[1], 10, 64)
			if err != nil {
				return "", nil, fmt.Errorf("invalid creation epoch %s: %w", item.Attributes[1], err)
			}
		}

		if item.Attributes[2] != "" {
			psr.CreationTimestamp, err = strconv.ParseInt(item.Attributes[2], 10, 64)
			if err != nil {
				return "", nil, fmt.Errorf("invalid creation timestamp %s: %w", item.Attributes[2], err)
			}
		}

		searchResults = append(searchResults, psr)
	}

	sortFunc := func(a, b taggingSearchResult) int {
		if c := cmp.Compare(b.CreationEpoch, a.CreationEpoch); c != 0 { // reverse order.
			return c
		}

		if c := cmp.Compare(b.CreationTimestamp, a.CreationTimestamp); c != 0 { // reverse order.
			return c
		}

		// It is a temporary decision. We can't figure out what object was first and what the second right now.
		return bytes.Compare(b.ID[:], a.ID[:]) // reverse order.
	}

	slices.SortFunc(searchResults, sortFunc)

	tags, err := n.getObjectTagsByOID(ctx, p.ObjectVersion.BktInfo, searchResults[0].ID)
	if err != nil {
		return "", nil, err
	}

	return p.ObjectVersion.VersionID, tags, nil
}

func (n *layer) getObjectTagsByOID(ctx context.Context, bktInfo *data.BucketInfo, id oid.ID) (map[string]string, error) {
	lastObj, err := n.objectGet(ctx, bktInfo, id)
	if err != nil {
		if isErrObjectAlreadyRemoved(err) {
			return nil, nil
		}

		return nil, fmt.Errorf("get object: %w", err)
	}

	var (
		tags = make(map[string]string)
	)

	if err = json.Unmarshal(lastObj.Payload(), &tags); err != nil {
		return nil, fmt.Errorf("couldn't unmarshal last object: %w", err)
	}

	return tags, nil
}

func (n *layer) DeleteObjectTagging(ctx context.Context, p *ObjectVersion) error {
	fs := make(object.SearchFilters, 0, 4)
	fs.AddFilter(object.AttributeFilePath, p.ObjectName, object.MatchStringEqual)
	fs.AddFilter(s3headers.MetaType, s3headers.TypeTags, object.MatchStringEqual)
	fs.AddTypeFilter(object.MatchStringEqual, object.TypeRegular)
	if p.VersionID != "" {
		fs.AddFilter(AttributeObjectVersion, p.VersionID, object.MatchStringEqual)
	}

	var opts client.SearchObjectsOptions
	if bt := bearerTokenFromContext(ctx, p.BktInfo.Owner); bt != nil {
		opts.WithBearerToken(*bt)
	}

	res, err := n.neoFS.SearchObjectsV2(ctx, p.BktInfo.CID, fs, nil, opts)
	if err != nil {
		if errors.Is(err, apistatus.ErrObjectAccessDenied) {
			return s3errors.GetAPIError(s3errors.ErrAccessDenied)
		}

		return fmt.Errorf("search object version: %w", err)
	}

	if len(res) == 0 {
		return nil
	}

	for i := range res {
		if err = n.objectDelete(ctx, p.BktInfo, res[i].ID); err != nil {
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
		if errors.Is(err, ErrNodeNotFound) {
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
