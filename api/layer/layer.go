package layer

import (
	"context"
	"crypto/ecdsa"
	"io"
	"strings"
	"time"

	"github.com/nspcc-dev/neofs-api-go/object"
	"github.com/nspcc-dev/neofs-api-go/refs"
	"github.com/nspcc-dev/neofs-api-go/service"
	"github.com/nspcc-dev/neofs-s3-gate/api/pool"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type (
	layer struct {
		log *zap.Logger
		cli pool.Client
		uid refs.OwnerID
		key *ecdsa.PrivateKey
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
	}

	NeoFS interface {
		Get(ctx context.Context, address refs.Address) (*object.Object, error)
	}

	Client interface {
		NeoFS

		ListBuckets(ctx context.Context) ([]BucketInfo, error)
		GetBucketInfo(ctx context.Context, name string) (*BucketInfo, error)

		GetObject(ctx context.Context, p *GetObjectParams) error
		GetObjectInfo(ctx context.Context, bucketName, objectName string) (*ObjectInfo, error)

		PutObject(ctx context.Context, p *PutObjectParams) (*ObjectInfo, error)

		CopyObject(ctx context.Context, p *CopyObjectParams) (*ObjectInfo, error)

		ListObjects(ctx context.Context, p *ListObjectsParams) (*ListObjectsInfo, error)

		DeleteObject(ctx context.Context, bucket, object string) error
		DeleteObjects(ctx context.Context, bucket string, objects []string) ([]error, error)
	}
)

// AWS3NameHeader key in the object neofs.
const AWS3NameHeader = "filename"

// NewGatewayLayer creates instance of layer. It checks credentials
// and establishes gRPC connection with node.
func NewLayer(log *zap.Logger, cli pool.Client, key *ecdsa.PrivateKey) (Client, error) {
	uid, err := refs.NewOwnerID(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &layer{
		cli: cli,
		key: key,
		log: log,
		uid: uid,
	}, nil
}

// Get NeoFS Object by refs.Address (should be used by auth.Center)
func (n *layer) Get(ctx context.Context, address refs.Address) (*object.Object, error) {
	conn, err := n.cli.GetConnection(ctx)
	if err != nil {
		return nil, err
	}

	token, err := n.cli.SessionToken(ctx, &pool.SessionParams{
		Conn: conn,
		Addr: address,
		Verb: service.Token_Info_Get,
	})

	if err != nil {
		return nil, err
	}

	req := new(object.GetRequest)
	req.Address = address
	req.SetTTL(service.SingleForwardingTTL)
	req.SetToken(token)

	err = service.SignRequestData(n.key, req)
	if err != nil {
		return nil, err
	}

	// todo: think about timeout
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cli, err := object.NewServiceClient(conn).Get(ctx, req)
	if err != nil {
		return nil, err
	}

	return receiveObject(cli)
}

// GetBucketInfo returns bucket name.
func (n *layer) GetBucketInfo(ctx context.Context, name string) (*BucketInfo, error) {
	list, err := n.containerList(ctx)
	if err != nil {
		return nil, err
	}

	for _, bkt := range list {
		if bkt.Name == name {
			return &bkt, nil
		}
	}

	return nil, errors.New("bucket not found")
}

// ListBuckets returns all user containers. Name of the bucket is a container
// id. Timestamp is omitted since it is not saved in neofs container.
func (n *layer) ListBuckets(ctx context.Context) ([]BucketInfo, error) {
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
		result    ListObjectsInfo
		uniqNames = make(map[string]struct{})
	)

	bkt, err := n.GetBucketInfo(ctx, p.Bucket)
	if err != nil {
		return nil, err
	}

	objectIDs, err := n.objectSearchContainer(ctx, bkt.CID)
	if err != nil {
		return nil, err
	}

	ln := len(objectIDs)
	// todo: check what happens if there is more than maxKeys objects
	if ln > p.MaxKeys {
		result.IsTruncated = true
		ln = p.MaxKeys
	}

	result.Objects = make([]ObjectInfo, 0, ln)

	for i := 0; i < ln; i++ {
		addr := refs.Address{ObjectID: objectIDs[i], CID: bkt.CID}

		meta, err := n.objectHead(ctx, addr)
		if err != nil {
			n.log.Warn("could not fetch object meta", zap.Error(err))
			continue
		}

		// ignore tombstone objects
		_, hdr := meta.LastHeader(object.HeaderType(object.TombstoneHdr))
		if hdr != nil {
			continue
		}

		// ignore storage group objects
		_, hdr = meta.LastHeader(object.HeaderType(object.StorageGroupHdr))
		if hdr != nil {
			continue
		}

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
				oi = objectInfoFromMeta(meta)
			} else { // if there are sub-entities in tail - dir
				oi = &ObjectInfo{
					Bucket: meta.SystemHeader.CID.String(),
					Name:   tail[:ind+1], // dir MUST have slash symbol in the end
					// IsDir:  true,
				}
			}

			// use only unique dir names
			if _, ok := uniqNames[oi.Name]; !ok {
				uniqNames[oi.Name] = struct{}{}

				result.Objects = append(result.Objects, *oi)
			}
		}
	}

	return &result, nil
}

// GetObject from storage.
func (n *layer) GetObject(ctx context.Context, p *GetObjectParams) error {
	cid, err := refs.CIDFromString(p.Bucket)
	if err != nil {
		return err
	}

	oid, err := n.objectFindID(ctx, cid, p.Object, false)
	if err != nil {
		return err
	}

	addr := refs.Address{
		ObjectID: oid,
		CID:      cid,
	}
	_, err = n.objectGet(ctx, getParams{
		addr:   addr,
		start:  p.Offset,
		length: p.Length,
		writer: p.Writer,
	})

	return err
}

// GetObjectInfo returns meta information about the object.
func (n *layer) GetObjectInfo(ctx context.Context, bucketName, objectName string) (*ObjectInfo, error) {
	var meta *object.Object
	if cid, err := refs.CIDFromString(bucketName); err != nil {
		return nil, err
	} else if oid, err := n.objectFindID(ctx, cid, objectName, false); err != nil {
		return nil, err
	} else if meta, err = n.objectHead(ctx, refs.Address{CID: cid, ObjectID: oid}); err != nil {
		return nil, err
	}
	return objectInfoFromMeta(meta), nil
}

// PutObject into storage.
func (n *layer) PutObject(ctx context.Context, p *PutObjectParams) (*ObjectInfo, error) {
	cid, err := refs.CIDFromString(p.Bucket)
	if err != nil {
		return nil, err
	}

	_, err = n.objectFindID(ctx, cid, p.Object, true)
	if err == nil {
		return nil, err
	}

	oid, err := refs.NewObjectID()
	if err != nil {
		return nil, err
	}

	sgid, err := refs.NewSGID()
	if err != nil {
		return nil, err
	}

	addr := refs.Address{
		ObjectID: oid,
		CID:      cid,
	}

	meta, err := n.objectPut(ctx, putParams{
		addr:        addr,
		size:        p.Size,
		name:        p.Object,
		r:           p.Reader,
		userHeaders: p.Header,
	})
	if err != nil {
		return nil, err
	}

	oi := objectInfoFromMeta(meta)

	// for every object create storage group, otherwise object will be deleted
	addr.ObjectID = sgid

	_, err = n.storageGroupPut(ctx, sgParams{
		addr:    addr,
		objects: []refs.ObjectID{oid},
	})
	if err != nil {
		return nil, err
	}

	return oi, nil
}

// CopyObject from one bucket into another bucket.
func (n *layer) CopyObject(ctx context.Context, p *CopyObjectParams) (*ObjectInfo, error) {
	info, err := n.GetObjectInfo(ctx, p.SrcBucket, p.SrcObject)
	if err != nil {
		return nil, err
	}

	pr, pw := io.Pipe()

	go func() {
		err := n.GetObject(ctx, &GetObjectParams{
			Bucket: p.SrcBucket,
			Object: p.SrcObject,
			Writer: pw,
		})

		_ = pw.CloseWithError(err)
	}()

	return n.PutObject(ctx, &PutObjectParams{
		Bucket: p.DstBucket,
		Object: p.DstObject,
		Size:   info.Size,
		Reader: pr,
		Header: info.Headers,
	})
}

// DeleteObject from the storage.
func (n *layer) DeleteObject(ctx context.Context, bucket, object string) error {
	cid, err := refs.CIDFromString(bucket)
	if err != nil {
		return err
	}

	oid, err := n.objectFindID(ctx, cid, object, false)
	if err != nil {
		return err
	}

	return n.objectDelete(ctx, delParams{addr: refs.Address{CID: cid, ObjectID: oid}})
}

// DeleteObjects from the storage.
func (n *layer) DeleteObjects(ctx context.Context, bucket string, objects []string) ([]error, error) {
	var errs = make([]error, 0, len(objects))

	for i := range objects {
		errs = append(errs, n.DeleteObject(ctx, bucket, objects[i]))
	}

	return errs, nil
}
