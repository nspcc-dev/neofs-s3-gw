package layer

import (
	"context"
	"crypto/ecdsa"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/nspcc-dev/neofs-api-go/pkg"
	"github.com/nspcc-dev/neofs-api-go/pkg/client"
	"github.com/nspcc-dev/neofs-api-go/pkg/object"
	"github.com/nspcc-dev/neofs-api-go/pkg/owner"
	"github.com/nspcc-dev/neofs-api-go/pkg/token"
	"github.com/nspcc-dev/neofs-s3-gate/api"
	"github.com/nspcc-dev/neofs-s3-gate/api/pool"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type (
	layer struct {
		uid *owner.ID
		log *zap.Logger
		cli pool.Client
		key *ecdsa.PrivateKey

		reqTimeout time.Duration
	}

	Params struct {
		Pool    pool.Client
		Logger  *zap.Logger
		Timeout time.Duration
		NFKey   *ecdsa.PrivateKey
	}

	GetObjectParams struct {
		Bucket string
		Object string
		Offset int64
		Length int64
		Writer io.Writer
	}

	PutObjectParams struct {
		Bucket string
		Object string
		Size   int64
		Reader io.Reader
		Header map[string]string
	}

	CopyObjectParams struct {
		SrcBucket string
		DstBucket string
		SrcObject string
		DstObject string
		Header    map[string]string
	}

	NeoFS interface {
		Get(ctx context.Context, address *object.Address) (*object.Object, error)
	}

	Client interface {
		NeoFS

		ListBuckets(ctx context.Context) ([]*BucketInfo, error)
		GetBucketInfo(ctx context.Context, name string) (*BucketInfo, error)

		GetObject(ctx context.Context, p *GetObjectParams) error
		GetObjectInfo(ctx context.Context, bucketName, objectName string) (*ObjectInfo, error)

		PutObject(ctx context.Context, p *PutObjectParams) (*ObjectInfo, error)

		CopyObject(ctx context.Context, p *CopyObjectParams) (*ObjectInfo, error)

		ListObjects(ctx context.Context, p *ListObjectsParams) (*ListObjectsInfo, error)

		DeleteObject(ctx context.Context, bucket, object string) error
		DeleteObjects(ctx context.Context, bucket string, objects []string) []error
	}
)

// NewGatewayLayer creates instance of layer. It checks credentials
// and establishes gRPC connection with node.
func NewLayer(p *Params) (Client, error) {
	wallet, err := owner.NEO3WalletFromPublicKey(&p.NFKey.PublicKey)
	if err != nil {
		return nil, err
	}

	uid := owner.NewID()
	uid.SetNeo3Wallet(wallet)

	return &layer{
		uid: uid,
		cli: p.Pool,
		key: p.NFKey,
		log: p.Logger,

		reqTimeout: p.Timeout,
	}, nil
}

// Get NeoFS Object by refs.Address (should be used by auth.Center)
func (n *layer) Get(ctx context.Context, address *object.Address) (*object.Object, error) {
	cli, tkn, err := n.prepareClient(ctx)
	if err != nil {
		return nil, err
	}

	gop := new(client.GetObjectParams)
	gop.WithAddress(address)

	return cli.GetObject(ctx, gop, client.WithSession(tkn))
}

// GetBucketInfo returns bucket name.
func (n *layer) GetBucketInfo(ctx context.Context, name string) (*BucketInfo, error) {
	name, err := url.QueryUnescape(name)
	if err != nil {
		return nil, err
	}

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
		uniqNames = make(map[string]struct{})
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
		result.IsTruncated = true
	}

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

		_, dirname := nameFromObject(meta)
		if strings.HasPrefix(dirname, p.Prefix) {
			var (
				oi   *ObjectInfo
				tail = strings.TrimLeft(dirname, p.Prefix)
				ind  = strings.Index(tail, pathSeparator)
			)

			if ind < 0 { // if there are not sub-entities in tail - file
				oi = objectInfoFromMeta(bkt, meta)
			} else { // if there are sub-entities in tail - dir
				oi = &ObjectInfo{
					id: meta.GetID(),

					Owner:  meta.GetOwnerID(),
					Bucket: bkt.Name,
					Name:   tail[:ind+1], // dir MUST have slash symbol in the end
					// IsDir:  true,
				}
			}

			// use only unique dir names
			if _, ok := uniqNames[oi.Name]; !ok {
				uniqNames[oi.Name] = struct{}{}

				result.Objects = append(result.Objects, oi)
			}
		}
	}

	return &result, nil
}

// GetObject from storage.
func (n *layer) GetObject(ctx context.Context, p *GetObjectParams) error {
	var (
		err error
		oid *object.ID
		bkt *BucketInfo
	)

	if bkt, err = n.GetBucketInfo(ctx, p.Bucket); err != nil {
		return errors.Wrapf(err, "bucket = %s", p.Bucket)
	} else if oid, err = n.objectFindID(ctx, &findParams{cid: bkt.CID, val: p.Object}); err != nil {
		return err
	}

	addr := object.NewAddress()
	addr.SetObjectID(oid)
	addr.SetContainerID(bkt.CID)

	_, err = n.objectGet(ctx, &getParams{
		Writer: p.Writer,

		addr: addr,

		offset: p.Offset,
		length: p.Length,
	})

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
		return nil, err
	} else if oid, err = n.objectFindID(ctx, &findParams{cid: bkt.CID, val: filename}); err != nil {
		return nil, err
	}

	addr := object.NewAddress()
	addr.SetObjectID(oid)
	addr.SetContainerID(bkt.CID)

	if meta, err = n.objectHead(ctx, addr); err != nil {
		return nil, err
	}

	return objectInfoFromMeta(bkt, meta), nil
}

func GetOwnerID(tkn *token.BearerToken) (*owner.ID, error) {

	switch pkg.SDKVersion().GetMajor() {
	case 2:
		id := tkn.ToV2().GetBody().GetOwnerID()
		return owner.NewIDFromV2(id), nil
	default:
		return nil, errors.New("unknown version")
	}
}

// PutObject into storage.
func (n *layer) PutObject(ctx context.Context, p *PutObjectParams) (*ObjectInfo, error) {
	return n.objectPut(ctx, p)
}

// CopyObject from one bucket into another bucket.
func (n *layer) CopyObject(ctx context.Context, p *CopyObjectParams) (*ObjectInfo, error) {
	info, err := n.GetObjectInfo(ctx, p.SrcBucket, p.SrcObject)
	if err != nil {
		return nil, errors.Wrap(err, "get-object-info")
	}

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

	// set custom headers
	for k, v := range p.Header {
		info.Headers[k] = v
	}

	return n.PutObject(ctx, &PutObjectParams{
		Bucket: p.DstBucket,
		Object: p.DstObject,
		Size:   info.Size,
		Reader: pr,
		Header: info.Headers,
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
