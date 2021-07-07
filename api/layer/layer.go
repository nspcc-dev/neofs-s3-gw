package layer

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/nspcc-dev/neofs-api-go/pkg/client"
	cid "github.com/nspcc-dev/neofs-api-go/pkg/container/id"
	"github.com/nspcc-dev/neofs-api-go/pkg/netmap"
	"github.com/nspcc-dev/neofs-api-go/pkg/object"
	"github.com/nspcc-dev/neofs-api-go/pkg/owner"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/creds/accessbox"
	"github.com/nspcc-dev/neofs-sdk-go/pkg/pool"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type (
	layer struct {
		pool pool.Pool
		log  *zap.Logger
	}

	// Params stores basic API parameters.
	Params struct {
		Pool    pool.Pool
		Logger  *zap.Logger
		Timeout time.Duration
		Key     *ecdsa.PrivateKey
	}

	// GetObjectParams stores object get request parameters.
	GetObjectParams struct {
		Range  *RangeParams
		Bucket string
		Object string
		Offset int64
		Length int64
		Writer io.Writer
	}

	// RangeParams stores range header request parameters.
	RangeParams struct {
		Start uint64
		End   uint64
	}

	// PutObjectParams stores object put request parameters.
	PutObjectParams struct {
		Bucket string
		Object string
		Size   int64
		Reader io.Reader
		Header map[string]string
	}

	// CopyObjectParams stores object copy request parameters.
	CopyObjectParams struct {
		SrcBucket string
		DstBucket string
		SrcObject string
		DstObject string
		SrcSize   int64
		Header    map[string]string
	}
	// CreateBucketParams stores bucket create request parameters.
	CreateBucketParams struct {
		Name   string
		ACL    uint32
		Policy *netmap.PlacementPolicy
	}
	// DeleteBucketParams stores delete bucket request parameters.
	DeleteBucketParams struct {
		Name string
	}
	// ListObjectVersionsParams stores list objects versions parameters.
	ListObjectVersionsParams struct {
		Bucket          string
		Delimiter       string
		KeyMarker       string
		MaxKeys         int
		Prefix          string
		VersionIDMarker string
		Encode          string
	}

	// NeoFS provides basic NeoFS interface.
	NeoFS interface {
		Get(ctx context.Context, address *object.Address) (*object.Object, error)
	}

	// Client provides S3 API client interface.
	Client interface {
		NeoFS

		ListBuckets(ctx context.Context) ([]*BucketInfo, error)
		GetBucketInfo(ctx context.Context, name string) (*BucketInfo, error)
		CreateBucket(ctx context.Context, p *CreateBucketParams) (*cid.ID, error)
		DeleteBucket(ctx context.Context, p *DeleteBucketParams) error

		GetObject(ctx context.Context, p *GetObjectParams) error
		GetObjectInfo(ctx context.Context, bucketName, objectName string) (*ObjectInfo, error)

		PutObject(ctx context.Context, p *PutObjectParams) (*ObjectInfo, error)

		CopyObject(ctx context.Context, p *CopyObjectParams) (*ObjectInfo, error)

		ListObjects(ctx context.Context, p *ListObjectsParams) (*ListObjectsInfo, error)
		ListObjectVersions(ctx context.Context, p *ListObjectVersionsParams) (*ListObjectVersionsInfo, error)

		DeleteObject(ctx context.Context, bucket, object string) error
		DeleteObjects(ctx context.Context, bucket string, objects []string) []error
	}
)

var (
	// ErrObjectExists is returned on attempts to create already existing object.
	ErrObjectExists = errors.New("object exists")
	// ErrObjectNotExists is returned on attempts to work with non-existing object.
	ErrObjectNotExists = errors.New("object not exists")
	// ErrBucketAlreadyExists is returned on attempts to create already existing bucket.
	ErrBucketAlreadyExists = errors.New("bucket exists")
)

const (
	// ETag (hex encoded md5sum) of empty string.
	emptyETag                  = "d41d8cd98f00b204e9800998ecf8427e"
	unversionedObjectVersionID = "null"
)

// NewLayer creates instance of layer. It checks credentials
// and establishes gRPC connection with node.
func NewLayer(log *zap.Logger, conns pool.Pool) Client {
	return &layer{
		pool: conns,
		log:  log,
	}
}

// Owner returns owner id from BearerToken (context) or from client owner.
func (n *layer) Owner(ctx context.Context) *owner.ID {
	if data, ok := ctx.Value(api.GateData).(*accessbox.GateData); ok && data != nil {
		return data.BearerToken.Issuer()
	}

	return n.pool.OwnerID()
}

// BearerOpt returns client.WithBearer call option with token from context or with nil token.
func (n *layer) BearerOpt(ctx context.Context) client.CallOption {
	if data, ok := ctx.Value(api.GateData).(*accessbox.GateData); ok && data != nil {
		return client.WithBearer(data.BearerToken)
	}

	return client.WithBearer(nil)
}

// SessionOpt returns client.WithSession call option with token from context or with nil token.
func (n *layer) SessionOpt(ctx context.Context) client.CallOption {
	if data, ok := ctx.Value(api.GateData).(*accessbox.GateData); ok && data != nil {
		return client.WithSession(data.SessionToken)
	}

	return client.WithSession(nil)
}

// Get NeoFS Object by refs.Address (should be used by auth.Center).
func (n *layer) Get(ctx context.Context, address *object.Address) (*object.Object, error) {
	ops := new(client.GetObjectParams).WithAddress(address)
	return n.pool.GetObject(ctx, ops, n.BearerOpt(ctx))
}

// GetBucketInfo returns bucket info by name.
func (n *layer) GetBucketInfo(ctx context.Context, name string) (*BucketInfo, error) {
	name, err := url.QueryUnescape(name)
	if err != nil {
		return nil, err
	}

	containerID := new(cid.ID)
	if err := containerID.Parse(name); err != nil {
		list, err := n.containerList(ctx)
		if err != nil {
			return nil, err
		}
		for _, bkt := range list {
			if bkt.Name == name {
				return bkt, nil
			}
		}

		return nil, status.Error(codes.NotFound, "bucket not found")
	}

	return n.containerInfo(ctx, containerID)
}

// ListBuckets returns all user containers. Name of the bucket is a container
// id. Timestamp is omitted since it is not saved in neofs container.
func (n *layer) ListBuckets(ctx context.Context) ([]*BucketInfo, error) {
	return n.containerList(ctx)
}

// ListObjects returns objects from the container. It ignores tombstones and
// storage groups.
//                          ctx, bucket, prefix, continuationToken, delimiter, maxKeys
func (n *layer) ListObjects(ctx context.Context, p *ListObjectsParams) (*ListObjectsInfo, error) {
	// todo: make pagination when search response will be gRPC stream,
	//       pagination must be implemented with cache, because search results
	//       may be different between search calls
	var (
		err       error
		bkt       *BucketInfo
		ids       []*object.ID
		result    ListObjectsInfo
		uniqNames = make(map[string]bool)
	)

	if bkt, err = n.GetBucketInfo(ctx, p.Bucket); err != nil {
		return nil, err
	} else if ids, err = n.objectSearch(ctx, &findParams{cid: bkt.CID}); err != nil {
		return nil, err
	}

	ln := len(ids)
	// todo: check what happens if there is more than maxKeys objects
	if ln > p.MaxKeys {
		ln = p.MaxKeys
	}

	mostRecentModified := time.Time{}
	needDirectoryAsKey := p.Version == 2 && len(p.Prefix) > 0 && len(p.Delimiter) > 0 && strings.HasSuffix(p.Prefix, p.Delimiter)
	result.Objects = make([]*ObjectInfo, 0, ln)

	for _, id := range ids {
		addr := object.NewAddress()
		addr.SetObjectID(id)
		addr.SetContainerID(bkt.CID)

		meta, err := n.objectHead(ctx, addr)
		if err != nil {
			n.log.Warn("could not fetch object meta", zap.Error(err))
			continue
		}

		// // ignore tombstone objects
		// _, hdr := meta.LastHeader(object.HeaderType(object.TombstoneHdr))
		// if hdr != nil {
		// 	continue
		// }

		// ignore storage group objects
		// _, hdr = meta.LastHeader(object.HeaderType(object.StorageGroupHdr))
		// if hdr != nil {
		// 	continue
		// }

		// dirs don't exist in neofs, gateway stores full path to the file
		// in object header, e.g. `filename`:`/this/is/path/file.txt`

		// prefix argument contains full dir path from the root, e.g. `/this/is/`

		// to emulate dirs we take dirs in path, compare it with prefix
		// and look for entities after prefix. If entity does not have any
		// sub-entities, then it is a file, else directory.

		if oi := objectInfoFromMeta(bkt, meta, p.Prefix, p.Delimiter); oi != nil {
			if needDirectoryAsKey && oi.Created.After(mostRecentModified) {
				mostRecentModified = oi.Created
			}
			// use only unique dir names
			if _, ok := uniqNames[oi.Name]; ok {
				continue
			}
			if len(p.Marker) > 0 && oi.Name <= p.Marker {
				continue
			}

			uniqNames[oi.Name] = oi.isDir

			result.Objects = append(result.Objects, oi)
		}
	}

	sort.Slice(result.Objects, func(i, j int) bool {
		return result.Objects[i].Name < result.Objects[j].Name
	})

	if len(result.Objects) > p.MaxKeys {
		result.IsTruncated = true
		result.Objects = result.Objects[:p.MaxKeys]
		result.NextMarker = result.Objects[len(result.Objects)-1].Name
	}

	fillPrefixes(&result, uniqNames)
	if needDirectoryAsKey {
		res := []*ObjectInfo{{
			Name:    p.Prefix,
			Created: mostRecentModified,
			HashSum: emptyETag,
		}}
		result.Objects = append(res, result.Objects...)
	}

	return &result, nil
}

func fillPrefixes(result *ListObjectsInfo, directories map[string]bool) {
	index := 0
	for range result.Objects {
		name := result.Objects[index].Name
		if isDir := directories[name]; isDir {
			result.Objects = append(result.Objects[:index], result.Objects[index+1:]...)
			result.Prefixes = append(result.Prefixes, name)
		} else {
			index++
		}
	}
}

// GetObject from storage.
func (n *layer) GetObject(ctx context.Context, p *GetObjectParams) error {
	var (
		err error
		oid *object.ID
		bkt *BucketInfo
	)

	if bkt, err = n.GetBucketInfo(ctx, p.Bucket); err != nil {
		return fmt.Errorf("couldn't find bucket: %s : %w", p.Bucket, err)
	} else if oid, err = n.objectFindID(ctx, &findParams{cid: bkt.CID, val: p.Object}); err != nil {
		return fmt.Errorf("search of the object failed: cid: %s, val: %s : %w", bkt.CID, p.Object, err)
	}

	addr := object.NewAddress()
	addr.SetObjectID(oid)
	addr.SetContainerID(bkt.CID)

	params := &getParams{
		Writer:  p.Writer,
		address: addr,
		offset:  p.Offset,
		length:  p.Length,
	}

	if p.Range != nil {
		objRange := object.NewRange()
		objRange.SetOffset(p.Range.Start)
		// Range header is inclusive
		objRange.SetLength(p.Range.End - p.Range.Start + 1)
		params.Range = objRange
		_, err = n.objectRange(ctx, params)
	} else {
		_, err = n.objectGet(ctx, params)
	}

	if err != nil {
		return fmt.Errorf("couldn't get object, cid: %s : %w", bkt.CID, err)
	}

	return nil
}

func (n *layer) checkObject(ctx context.Context, cid *cid.ID, filename string) error {
	var err error

	if _, err = n.objectFindID(ctx, &findParams{cid: cid, val: filename}); err == nil {
		return ErrObjectExists
	} else if state, ok := status.FromError(err); !ok || state == nil {
		return err
	} else if state.Code() == codes.NotFound {
		return ErrObjectNotExists
	}

	return err
}

// GetObjectInfo returns meta information about the object.
func (n *layer) GetObjectInfo(ctx context.Context, bucketName, filename string) (*ObjectInfo, error) {
	var (
		err  error
		oid  *object.ID
		bkt  *BucketInfo
		meta *object.Object
	)

	if bkt, err = n.GetBucketInfo(ctx, bucketName); err != nil {
		n.log.Error("could not fetch bucket info", zap.Error(err))
		return nil, err
	} else if oid, err = n.objectFindID(ctx, &findParams{cid: bkt.CID, val: filename}); err != nil {
		n.log.Error("could not find object id", zap.Error(err))
		return nil, err
	}

	addr := object.NewAddress()
	addr.SetObjectID(oid)
	addr.SetContainerID(bkt.CID)

	if meta, err = n.objectHead(ctx, addr); err != nil {
		n.log.Error("could not fetch object head", zap.Error(err))
		return nil, err
	}

	return objectInfoFromMeta(bkt, meta, "", ""), nil
}

// PutObject into storage.
func (n *layer) PutObject(ctx context.Context, p *PutObjectParams) (*ObjectInfo, error) {
	return n.objectPut(ctx, p)
}

// CopyObject from one bucket into another bucket.
func (n *layer) CopyObject(ctx context.Context, p *CopyObjectParams) (*ObjectInfo, error) {
	pr, pw := io.Pipe()

	go func() {
		err := n.GetObject(ctx, &GetObjectParams{
			Bucket: p.SrcBucket,
			Object: p.SrcObject,
			Writer: pw,
		})

		if err = pw.CloseWithError(err); err != nil {
			n.log.Error("could not get object", zap.Error(err))
		}
	}()

	return n.PutObject(ctx, &PutObjectParams{
		Bucket: p.DstBucket,
		Object: p.DstObject,
		Size:   p.SrcSize,
		Reader: pr,
		Header: p.Header,
	})
}

// DeleteObject removes all objects with passed nice name.
func (n *layer) DeleteObject(ctx context.Context, bucket, filename string) error {
	var (
		err error
		ids []*object.ID
		bkt *BucketInfo
	)

	if bkt, err = n.GetBucketInfo(ctx, bucket); err != nil {
		return &api.DeleteError{
			Err:    err,
			Object: filename,
		}
	} else if ids, err = n.objectSearch(ctx, &findParams{cid: bkt.CID, val: filename}); err != nil {
		return &api.DeleteError{
			Err:    err,
			Object: filename,
		}
	}

	for _, id := range ids {
		addr := object.NewAddress()
		addr.SetObjectID(id)
		addr.SetContainerID(bkt.CID)

		if err = n.objectDelete(ctx, addr); err != nil {
			return &api.DeleteError{
				Err:    err,
				Object: filename,
			}
		}
	}

	return nil
}

// DeleteObjects from the storage.
func (n *layer) DeleteObjects(ctx context.Context, bucket string, objects []string) []error {
	var errs = make([]error, 0, len(objects))

	for i := range objects {
		if err := n.DeleteObject(ctx, bucket, objects[i]); err != nil {
			errs = append(errs, err)
		}
	}

	return errs
}

func (n *layer) CreateBucket(ctx context.Context, p *CreateBucketParams) (*cid.ID, error) {
	_, err := n.GetBucketInfo(ctx, p.Name)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "bucket not found") ||
			strings.Contains(errMsg, "container not found") {
			return n.createContainer(ctx, p)
		}
		return nil, err
	}

	return nil, ErrBucketAlreadyExists
}

func (n *layer) DeleteBucket(ctx context.Context, p *DeleteBucketParams) error {
	bucketInfo, err := n.GetBucketInfo(ctx, p.Name)
	if err != nil {
		return err
	}

	return n.deleteContainer(ctx, bucketInfo.CID)
}

func (n *layer) ListObjectVersions(ctx context.Context, p *ListObjectVersionsParams) (*ListObjectVersionsInfo, error) {
	var (
		res       = ListObjectVersionsInfo{}
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

	versions := make([]*ObjectVersionInfo, 0, len(ids))
	// todo: deletemarkers is empty now, we will use it after proper realization of versioning
	deleted := make([]*DeletedObjectInfo, 0, len(ids))
	res.DeleteMarker = deleted

	for _, id := range ids {
		addr := object.NewAddress()
		addr.SetObjectID(id)
		addr.SetContainerID(bkt.CID)

		meta, err := n.objectHead(ctx, addr)
		if err != nil {
			n.log.Warn("could not fetch object meta", zap.Error(err))
			continue
		}
		if ov := objectVersionInfoFromMeta(bkt, meta, p.Prefix, p.Delimiter); ov != nil {
			if _, ok := uniqNames[ov.Object.Name]; ok {
				continue
			}
			if len(p.KeyMarker) > 0 && ov.Object.Name <= p.KeyMarker {
				continue
			}
			uniqNames[ov.Object.Name] = ov.Object.isDir
			versions = append(versions, ov)
		}
	}

	sort.Slice(versions, func(i, j int) bool {
		return versions[i].Object.Name < versions[j].Object.Name
	})

	if len(versions) > p.MaxKeys {
		res.IsTruncated = true

		lastVersion := versions[p.MaxKeys-1]
		res.KeyMarker = lastVersion.Object.Name
		res.VersionIDMarker = lastVersion.VersionID

		nextVersion := versions[p.MaxKeys]
		res.NextKeyMarker = nextVersion.Object.Name
		res.NextVersionIDMarker = nextVersion.VersionID

		versions = versions[:p.MaxKeys]
	}

	for _, ov := range versions {
		if isDir := uniqNames[ov.Object.Name]; isDir {
			res.CommonPrefixes = append(res.CommonPrefixes, &ov.Object.Name)
		} else {
			res.Version = append(res.Version, ov)
		}
	}
	return &res, nil
}
