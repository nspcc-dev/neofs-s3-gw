package layer

import (
	"context"
	"errors"
	"io"
	"net/url"
	"sort"
	"strconv"
	"time"

	"github.com/nspcc-dev/neofs-api-go/pkg/client"
	cid "github.com/nspcc-dev/neofs-api-go/pkg/container/id"
	"github.com/nspcc-dev/neofs-api-go/pkg/object"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"go.uber.org/zap"
)

type (
	findParams struct {
		val string
		cid *cid.ID
	}

	getParams struct {
		io.Writer
		*object.Range

		offset  int64
		length  int64
		address *object.Address
	}

	// ListObjectsParamsCommon contains common parameters for ListObjectsV1 and ListObjectsV2.
	ListObjectsParamsCommon struct {
		Bucket    string
		Delimiter string
		Encode    string
		MaxKeys   int
		Prefix    string
	}

	// ListObjectsParamsV1 contains params for ListObjectsV1.
	ListObjectsParamsV1 struct {
		ListObjectsParamsCommon
		Marker string
	}

	// ListObjectsParamsV2 contains params for ListObjectsV2.
	ListObjectsParamsV2 struct {
		ListObjectsParamsCommon
		ContinuationToken string
		StartAfter        string
		FetchOwner        bool
	}

	allObjectParams struct {
		Bucket     string
		Delimiter  string
		Prefix     string
		StartAfter string
	}
)

// objectSearch returns all available objects by search params.
func (n *layer) objectSearch(ctx context.Context, p *findParams) ([]*object.ID, error) {
	var opts object.SearchFilters

	opts.AddRootFilter()

	if filename, err := url.QueryUnescape(p.val); err != nil {
		return nil, err
	} else if filename != "" {
		opts.AddFilter(object.AttributeFileName, filename, object.MatchStringEqual)
	}
	return n.pool.SearchObject(ctx, new(client.SearchObjectParams).WithContainerID(p.cid).WithSearchFilters(opts), n.BearerOpt(ctx))
}

// objectFindID returns object id (uuid) based on it's nice name in s3. If
// nice name is uuid compatible, then function returns it.
func (n *layer) objectFindID(ctx context.Context, p *findParams) (*object.ID, error) {
	if result, err := n.objectSearch(ctx, p); err != nil {
		return nil, err
	} else if ln := len(result); ln == 0 {
		return nil, api.GetAPIError(api.ErrNoSuchKey)
	} else if ln == 1 {
		return result[0], nil
	}

	return nil, errors.New("several objects with the same name found")
}

// objectHead returns all object's headers.
func (n *layer) objectHead(ctx context.Context, address *object.Address) (*object.Object, error) {
	ops := new(client.ObjectHeaderParams).WithAddress(address).WithAllFields()
	return n.pool.GetObjectHeader(ctx, ops, n.BearerOpt(ctx))
}

// objectGet and write it into provided io.Reader.
func (n *layer) objectGet(ctx context.Context, p *getParams) (*object.Object, error) {
	// prepare length/offset writer
	w := newWriter(p.Writer, p.offset, p.length)
	ops := new(client.GetObjectParams).WithAddress(p.address).WithPayloadWriter(w)
	return n.pool.GetObject(ctx, ops, n.BearerOpt(ctx))
}

// objectRange gets object range and writes it into provided io.Writer.
func (n *layer) objectRange(ctx context.Context, p *getParams) ([]byte, error) {
	w := newWriter(p.Writer, p.offset, p.length)
	ops := new(client.RangeDataParams).WithAddress(p.address).WithDataWriter(w).WithRange(p.Range)
	return n.pool.ObjectPayloadRangeData(ctx, ops, n.BearerOpt(ctx))
}

// objectPut into NeoFS, took payload from io.Reader.
func (n *layer) objectPut(ctx context.Context, p *PutObjectParams) (*ObjectInfo, error) {
	var (
		err error
		obj string
		bkt *BucketInfo
		own = n.Owner(ctx)
	)

	if obj, err = url.QueryUnescape(p.Object); err != nil {
		return nil, err
	} else if bkt, err = n.GetBucketInfo(ctx, p.Bucket); err != nil {
		return nil, err
	} else if err = n.checkObject(ctx, bkt.CID, p.Object); err != nil {
		var errExist *api.ObjectAlreadyExists
		if ok := errors.As(err, &errExist); ok {
			errExist.Bucket = p.Bucket
			errExist.Object = p.Object
			return nil, errExist
		}

		if !api.IsS3Error(err, api.ErrNoSuchKey) {
			return nil, err
		}
	}

	attributes := make([]*object.Attribute, 0, len(p.Header)+1)

	unix := strconv.FormatInt(time.Now().UTC().Unix(), 10)

	filename := object.NewAttribute()
	filename.SetKey(object.AttributeFileName)
	filename.SetValue(obj)

	createdAt := object.NewAttribute()
	createdAt.SetKey(object.AttributeTimestamp)
	createdAt.SetValue(unix)

	attributes = append(attributes, filename, createdAt)

	for k, v := range p.Header {
		ua := object.NewAttribute()
		ua.SetKey(k)
		ua.SetValue(v)

		attributes = append(attributes, ua)
	}

	raw := object.NewRaw()
	raw.SetOwnerID(own)
	raw.SetContainerID(bkt.CID)
	raw.SetAttributes(attributes...)

	r := newDetector(p.Reader)

	ops := new(client.PutObjectParams).WithObject(raw.Object()).WithPayloadReader(r)
	oid, err := n.pool.PutObject(
		ctx,
		ops,
		n.BearerOpt(ctx),
	)
	if err != nil {
		return nil, err
	}

	addr := object.NewAddress()
	addr.SetObjectID(oid)
	addr.SetContainerID(bkt.CID)
	meta, err := n.objectHead(ctx, addr)
	if err != nil {
		return nil, err
	}

	return &ObjectInfo{
		id: oid,

		Owner:       own,
		Bucket:      p.Bucket,
		Name:        p.Object,
		Size:        p.Size,
		Created:     time.Now(),
		Headers:     p.Header,
		ContentType: r.contentType,
		HashSum:     meta.PayloadChecksum().String(),
	}, nil
}

// objectDelete puts tombstone object into neofs.
func (n *layer) objectDelete(ctx context.Context, address *object.Address) error {
	dop := new(client.DeleteObjectParams)
	dop.WithAddress(address)
	return n.pool.DeleteObject(ctx, dop, n.BearerOpt(ctx))
}

// ListObjectsV1 returns objects in a bucket for requests of Version 1.
func (n *layer) ListObjectsV1(ctx context.Context, p *ListObjectsParamsV1) (*ListObjectsInfoV1, error) {
	var (
		err    error
		result ListObjectsInfoV1
	)

	if p.MaxKeys == 0 {
		return &result, nil
	}

	allObjects, err := n.listSortedAllObjects(ctx, allObjectParams{
		Bucket:     p.Bucket,
		Prefix:     p.Prefix,
		Delimiter:  p.Delimiter,
		StartAfter: p.Marker,
	})
	if err != nil {
		return nil, err
	}

	if len(allObjects) > p.MaxKeys {
		result.IsTruncated = true

		nextObject := allObjects[p.MaxKeys-1]
		result.NextMarker = nextObject.Name

		allObjects = allObjects[:p.MaxKeys]
	}

	for _, ov := range allObjects {
		if ov.isDir {
			result.Prefixes = append(result.Prefixes, ov.Name)
		} else {
			result.Objects = append(result.Objects, ov)
		}
	}

	return &result, nil
}

// ListObjectsV2 returns objects in a bucket for requests of Version 2.
func (n *layer) ListObjectsV2(ctx context.Context, p *ListObjectsParamsV2) (*ListObjectsInfoV2, error) {
	var (
		err        error
		result     ListObjectsInfoV2
		allObjects []*ObjectInfo
	)

	if p.MaxKeys == 0 {
		return &result, nil
	}

	if p.ContinuationToken != "" {
		// find cache with continuation token
	} else {
		allObjects, err = n.listSortedAllObjects(ctx, allObjectParams{
			Bucket:     p.Bucket,
			Prefix:     p.Prefix,
			Delimiter:  p.Delimiter,
			StartAfter: p.StartAfter,
		})
		if err != nil {
			return nil, err
		}
	}

	if len(allObjects) > p.MaxKeys {
		result.IsTruncated = true

		allObjects = allObjects[:p.MaxKeys]
		// add  creating of cache here
	}

	for _, ov := range allObjects {
		if ov.isDir {
			result.Prefixes = append(result.Prefixes, ov.Name)
		} else {
			result.Objects = append(result.Objects, ov)
		}
	}
	return &result, nil
}

func (n *layer) listSortedAllObjects(ctx context.Context, p allObjectParams) ([]*ObjectInfo, error) {
	var (
		err       error
		bkt       *BucketInfo
		ids       []*object.ID
		uniqNames = make(map[string]bool)
	)

	if bkt, err = n.GetBucketInfo(ctx, p.Bucket); err != nil {
		return nil, err
	} else if ids, err = n.objectSearch(ctx, &findParams{cid: bkt.CID}); err != nil {
		return nil, err
	}

	objects := make([]*ObjectInfo, 0, len(ids))

	for _, id := range ids {
		addr := object.NewAddress()
		addr.SetObjectID(id)
		addr.SetContainerID(bkt.CID)

		meta, err := n.objectHead(ctx, addr)
		if err != nil {
			n.log.Warn("could not fetch object meta", zap.Error(err))
			continue
		}
		if oi := objectInfoFromMeta(bkt, meta, p.Prefix, p.Delimiter); oi != nil {
			// use only unique dir names
			if _, ok := uniqNames[oi.Name]; ok {
				continue
			}
			if len(p.StartAfter) > 0 && oi.Name <= p.StartAfter {
				continue
			}

			uniqNames[oi.Name] = oi.isDir

			objects = append(objects, oi)
		}
	}

	sort.Slice(objects, func(i, j int) bool {
		return objects[i].Name < objects[j].Name
	})

	return objects, nil
}
