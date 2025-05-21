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
	"strings"

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
	CreationTimestamp int64
	IsOriginalObject  bool
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
		Attributes:   make(map[string]string, 3+len(p.TagSet)),
		Payload:      bytes.NewBuffer(payload),
		PayloadSize:  uint64(len(payload)),
	}

	if p.ObjectVersion.VersionID != "" {
		prm.Attributes[s3headers.AttributeObjectVersion] = p.ObjectVersion.VersionID
		prm.Attributes[s3headers.AttributeVersioningState] = data.VersioningEnabled
	}

	prm.Attributes[s3headers.MetaType] = s3headers.TypeTags
	for k, v := range p.TagSet {
		prm.Attributes[s3headers.NeoFSSystemMetadataTagPrefix+k] = v
	}

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
			object.AttributeTimestamp,
			s3headers.MetaType,
		}

		opts client.SearchObjectsOptions
	)

	if bt := bearerTokenFromContext(ctx, owner); bt != nil {
		opts.WithBearerToken(*bt)
	}

	filters.AddFilter(object.AttributeFilePath, p.ObjectVersion.ObjectName, object.MatchStringEqual)
	filters.AddTypeFilter(object.MatchStringEqual, object.TypeRegular)
	if p.ObjectVersion.VersionID != "" {
		filters.AddFilter(s3headers.AttributeObjectVersion, p.ObjectVersion.VersionID, object.MatchStringEqual)
	}

	searchResultItems, err := n.neoFS.SearchObjectsV2(ctx, p.ObjectVersion.BktInfo.CID, filters, returningAttributes, opts)
	if err != nil {
		if errors.Is(err, apistatus.ErrObjectAccessDenied) {
			return "", nil, s3errors.GetAPIError(s3errors.ErrAccessDenied)
		}

		return "", nil, fmt.Errorf("search object version: %w", err)
	}

	if len(searchResultItems) == 0 {
		// Objects inside versioned container don't have s3headers.AttributeObjectVersion attribute.
		// This case means there are no separate attbute meta objects, let's try to get attributes from object itself.
		if p.ObjectVersion.VersionID != "" {
			var objID oid.ID
			if err = objID.DecodeString(p.ObjectVersion.VersionID); err != nil {
				return "", nil, fmt.Errorf("parse object version %s into oid: %w", p.ObjectVersion.VersionID, err)
			}

			tags, err := n.getTagsFromOriginalObject(ctx, p.ObjectVersion.BktInfo, objID)
			if err != nil {
				return "", nil, fmt.Errorf("get tags by oid: %w", err)
			}

			return p.ObjectVersion.VersionID, tags, nil
		}

		return "", nil, nil
	}

	var (
		tags                        map[string]string
		metaObjectSearchResults     = make([]taggingSearchResult, 0, len(searchResultItems))
		originalObjectSearchResults = make([]taggingSearchResult, 0, 1)
	)

	for _, item := range searchResultItems {
		var psr = taggingSearchResult{
			ID:       item.ID,
			FilePath: item.Attributes[0],
		}

		switch item.Attributes[2] {
		case "":
			psr.IsOriginalObject = true
		case s3headers.TypeTags:
			// is a tag meta object.
		default:
			// skip other meta types.
			continue
		}

		if item.Attributes[1] != "" {
			psr.CreationTimestamp, err = strconv.ParseInt(item.Attributes[1], 10, 64)
			if err != nil {
				return "", nil, fmt.Errorf("invalid creation timestamp %s: %w", item.Attributes[1], err)
			}
		}

		if psr.IsOriginalObject {
			originalObjectSearchResults = append(originalObjectSearchResults, psr)
		} else {
			metaObjectSearchResults = append(metaObjectSearchResults, psr)
		}
	}

	sortFunc := func(a, b taggingSearchResult) int {
		if c := cmp.Compare(b.CreationTimestamp, a.CreationTimestamp); c != 0 { // reverse order.
			return c
		}

		// It is a temporary decision. We can't figure out what object was first and what the second right now.
		return bytes.Compare(b.ID[:], a.ID[:]) // reverse order.
	}

	// There are not extra meta objects with tags.
	if len(metaObjectSearchResults) == 0 {
		slices.SortFunc(originalObjectSearchResults, sortFunc)

		tags, err = n.getTagsFromOriginalObject(ctx, p.ObjectVersion.BktInfo, originalObjectSearchResults[0].ID)
		if err != nil {
			return "", nil, err
		}
	} else {
		slices.SortFunc(metaObjectSearchResults, sortFunc)

		tags, err = n.getTagsByOID(ctx, p.ObjectVersion.BktInfo, metaObjectSearchResults[0].ID)
		if err != nil {
			return "", nil, err
		}
	}

	return p.ObjectVersion.VersionID, tags, nil
}

func (n *layer) getTagsFromOriginalObject(ctx context.Context, bktInfo *data.BucketInfo, id oid.ID) (map[string]string, error) {
	var tagSet = make(map[string]string)

	header, err := n.objectHead(ctx, bktInfo, id)
	if err != nil {
		return nil, fmt.Errorf("get object head: %w", err)
	}

	for _, attr := range header.Attributes() {
		if strings.HasPrefix(attr.Key(), s3headers.NeoFSSystemMetadataTagPrefix) {
			tagSet[strings.TrimPrefix(attr.Key(), s3headers.NeoFSSystemMetadataTagPrefix)] = attr.Value()
		}
	}

	return tagSet, nil
}

func (n *layer) getTagsByOID(ctx context.Context, bktInfo *data.BucketInfo, id oid.ID) (map[string]string, error) {
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

func (n *layer) DeleteObjectTagging(ctx context.Context, p *ObjectVersion, copiesNumber uint32) error {
	fs := make(object.SearchFilters, 0, 4)
	fs.AddFilter(object.AttributeFilePath, p.ObjectName, object.MatchStringEqual)
	fs.AddFilter(s3headers.MetaType, s3headers.TypeTags, object.MatchStringEqual)
	fs.AddTypeFilter(object.MatchStringEqual, object.TypeRegular)
	if p.VersionID != "" {
		fs.AddFilter(s3headers.AttributeObjectVersion, p.VersionID, object.MatchStringEqual)
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

	// Put an empty tag list to override tags inside the object itself.
	putObjectTaggingParams := PutObjectTaggingParams{
		ObjectVersion: p,
		TagSet:        make(map[string]string),
		CopiesNumber:  copiesNumber,
	}

	return n.PutObjectTagging(ctx, &putObjectTaggingParams)
}

func (n *layer) GetBucketTagging(ctx context.Context, bktInfo *data.BucketInfo) (map[string]string, error) {
	var (
		err   error
		owner = n.Owner(ctx)
	)

	if tags := n.cache.GetTagging(owner, bucketTaggingCacheKey(bktInfo.CID)); tags != nil {
		return tags, nil
	}

	id, err := n.searchBucketMetaObjects(ctx, bktInfo, s3headers.TypeBucketTags)
	if err != nil {
		return nil, fmt.Errorf("search: %w", err)
	}

	if id.IsZero() {
		return nil, s3errors.GetAPIError(s3errors.ErrBucketTaggingNotFound)
	}

	tags, err := n.getTagsByOID(ctx, bktInfo, id)
	if err != nil {
		return nil, err
	}

	n.cache.PutTagging(owner, bucketTaggingCacheKey(bktInfo.CID), tags)

	return tags, nil
}

func (n *layer) PutBucketTagging(ctx context.Context, bktInfo *data.BucketInfo, tagSet map[string]string, copiesNumber uint32) error {
	payload, err := json.Marshal(tagSet)
	if err != nil {
		return fmt.Errorf("could not marshal tag set: %w", err)
	}

	prm := PrmObjectCreate{
		Container:    bktInfo.CID,
		Creator:      bktInfo.Owner,
		CreationTime: TimeNow(ctx),
		CopiesNumber: copiesNumber,
		Attributes: map[string]string{
			s3headers.MetaType: s3headers.TypeBucketTags,
		},
		Payload:     bytes.NewBuffer(payload),
		PayloadSize: uint64(len(payload)),
	}

	if _, _, err = n.objectPutAndHash(ctx, prm, bktInfo); err != nil {
		return fmt.Errorf("create bucket tagging object: %w", err)
	}

	n.cache.PutTagging(n.Owner(ctx), bucketTaggingCacheKey(bktInfo.CID), tagSet)

	return nil
}

func (n *layer) DeleteBucketTagging(ctx context.Context, bktInfo *data.BucketInfo) error {
	fs := make(object.SearchFilters, 0, 1)
	fs.AddFilter(s3headers.MetaType, s3headers.TypeBucketTags, object.MatchStringEqual)

	var opts client.SearchObjectsOptions
	if bt := bearerTokenFromContext(ctx, bktInfo.Owner); bt != nil {
		opts.WithBearerToken(*bt)
	}

	res, err := n.neoFS.SearchObjectsV2(ctx, bktInfo.CID, fs, nil, opts)
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
		if err = n.objectDelete(ctx, bktInfo, res[i].ID); err != nil {
			return fmt.Errorf("couldn't delete bucket tags object: %w", err)
		}
	}

	n.cache.DeleteTagging(bucketTaggingCacheKey(bktInfo.CID))

	return nil
}

func objectTaggingCacheKey(p *ObjectVersion) string {
	return ".tagset." + p.BktInfo.CID.EncodeToString() + "." + p.ObjectName + "." + p.VersionID
}

func bucketTaggingCacheKey(cnrID cid.ID) string {
	return ".tagset." + cnrID.EncodeToString()
}
