package layer

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"

	minio "github.com/minio/minio/legacy"
	"github.com/minio/minio/pkg/hash"
	"github.com/nspcc-dev/neofs-api-go/object"
	"github.com/nspcc-dev/neofs-api-go/refs"
	"google.golang.org/grpc/connectivity"
)

const (
	// AWS3NameHeader key in the object neofs.
	AWS3NameHeader = "filename"

	// SlashSeparator to find dirs in object path.
	SlashSeparator = "/"
)

// Shutdown called when minio remote client closed.
func (n *neofsObject) Shutdown(context.Context) error {
	return nil
}

// StorageInfo is not relevant in NeoFS the same way as in B2.
func (n *neofsObject) StorageInfo(ctx context.Context, local bool) (minio.StorageInfo, []error) {
	var si minio.StorageInfo

	si.Backend.Type = minio.BackendGateway
	si.Backend.GatewayOnline = n.statusHealth(ctx)

	return si, nil
}

// MakeBucketWithLocation is not supported in neofs gateway.
func (n *neofsObject) MakeBucketWithLocation(ctx context.Context, bucket, location string, lockEnabled bool) error {
	// ATTENTION
	// We do not support new bucket creation, because NeoFS does not support
	// nice names for containers (buckets in s3). Nice name support might me
	// implemented with external NNS which can be smart-contract in NEO
	// blockchain.
	return errors.New("neofs gateway doesn't support bucket creation")
}

// GetBucketInfo returns bucket name.
func (n *neofsObject) GetBucketInfo(ctx context.Context, bucket string) (minio.BucketInfo, error) {
	var result = minio.BucketInfo{Name: bucket}

	return result, nil
}

// ListBuckets returns all user containers. Name of the bucket is a container
// id. Timestamp is omitted since it is not saved in neofs container.
func (n *neofsObject) ListBuckets(ctx context.Context) ([]minio.BucketInfo, error) {
	containerIDs, err := n.containerList(ctx)
	if err != nil {
		return nil, err
	}

	buckets := make([]minio.BucketInfo, 0, len(containerIDs))

	for i := range containerIDs {
		buckets = append(buckets, minio.BucketInfo{
			Name: containerIDs[i].String(),
		})
	}

	return buckets, nil
}

// DeleteBucket is not supported in neofs gateway
func (n *neofsObject) DeleteBucket(ctx context.Context, bucket string, force bool) error {
	// ATTENTION
	// We do not support bucket removal, because NeoFS does not support
	// bucket creation, therefore it is not consistent. With NNS it may
	// be implemented later, see `MakeBucketWithLocation()` function.
	return errors.New("neofs gateway doesn't support bucket removal")
}

// ListObjects returns objects from the container. It ignores tombstones and
// storage groups.
func (n *neofsObject) ListObjects(ctx context.Context, bucket, prefix, marker, delimiter string, maxKeys int) (minio.ListObjectsInfo, error) {
	// todo: make pagination when search response will be gRPC stream,
	//       pagination must be implemented with cache, because search results
	//       may be different between search calls
	var (
		result    minio.ListObjectsInfo
		uniqNames = make(map[string]struct{})
	)

	containerID, err := refs.CIDFromString(bucket)
	if err != nil {
		return result, err
	}

	objectIDs, err := n.objectSearchContainer(ctx, containerID)
	if err != nil {
		return result, err
	}

	ln := len(objectIDs)
	// todo: check what happens if there is more than maxKeys objects
	if ln > maxKeys {
		result.IsTruncated = true
		ln = maxKeys
	}

	result.Objects = make([]minio.ObjectInfo, 0, ln)

	for i := 0; i < ln; i++ {
		addr := refs.Address{ObjectID: objectIDs[i], CID: containerID}

		meta, err := n.objectHead(ctx, addr)
		if err != nil {
			// todo: log there
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

		_, filedir := nameFromObject(meta)
		if strings.HasPrefix(filedir, prefix) {
			var (
				oi   minio.ObjectInfo
				tail = strings.TrimLeft(filedir, prefix)
				ind  = strings.Index(tail, SlashSeparator)
			)

			if ind < 0 { // if there are not sub-entities in tail - file
				oi = objectInfoFromMeta(meta)
			} else { // if there are sub-entities in tail - dir
				oi = minio.ObjectInfo{
					Bucket: meta.SystemHeader.CID.String(),
					Name:   tail[:ind+1], // dir MUST have slash symbol in the end
					IsDir:  true,
				}
			}

			// use only unique dir names
			if _, ok := uniqNames[oi.Name]; !ok {
				uniqNames[oi.Name] = struct{}{}

				result.Objects = append(result.Objects, oi)
			}
		}
	}

	return result, nil
}

// ListObjectsV2 returns objects from the container. It ignores tombstones and
// storage groups.
func (n *neofsObject) ListObjectsV2(ctx context.Context, bucket, prefix, continuationToken, delimiter string, maxKeys int, fetchOwner bool, startAfter string) (minio.ListObjectsV2Info, error) {
	// todo: make pagination when search response will be gRPC stream
	//       pagination must be implemented via cache, because search results
	//       may be different between search queries. Also use startAfter
	//       param in the answer
	//
	var result minio.ListObjectsV2Info

	list, err := n.ListObjects(ctx, bucket, prefix, continuationToken, delimiter, maxKeys)
	if err != nil {
		return result, err
	}

	result.IsTruncated = list.IsTruncated
	result.Prefixes = list.Prefixes
	result.ContinuationToken = continuationToken
	result.NextContinuationToken = list.NextMarker
	result.Objects = list.Objects

	return result, nil
}

// GetObjectNInfo performs two operations within one call.
func (n *neofsObject) GetObjectNInfo(ctx context.Context, bucket, object string, rs *minio.HTTPRangeSpec, h http.Header, lockType minio.LockType, opts minio.ObjectOptions) (*minio.GetObjectReader, error) {
	oi, err := n.GetObjectInfo(ctx, bucket, object, opts)
	if err != nil {
		return nil, err
	}

	var startOffset, length int64

	startOffset, length, err = rs.GetOffsetLength(oi.Size)
	if err != nil {
		return nil, err
	}

	pr, pw := io.Pipe()

	go func() {
		err = n.GetObject(ctx, bucket, object, startOffset, length, pw, oi.ETag, opts)
		_ = pw.CloseWithError(err)
	}()

	pipeCloser := func() { _ = pr.Close() }

	return minio.NewGetObjectReaderFromReader(pr, oi, opts, pipeCloser)
}

// GetObject from storage.
func (n *neofsObject) GetObject(ctx context.Context, bucket, object string, startOffset int64, length int64, writer io.Writer, etag string, opts minio.ObjectOptions) error {
	var (
		notFoundError = minio.ObjectNotFound{
			Bucket: bucket,
			Object: object,
		}
	)

	containerID, err := refs.CIDFromString(bucket)
	if err != nil {
		return err
	}

	objectID, err := n.objectFindID(ctx, containerID, object, false)
	if err != nil {
		return notFoundError
	}

	addr := refs.Address{
		ObjectID: objectID,
		CID:      containerID,
	}
	_, err = n.objectGet(ctx, getParams{
		addr:   addr,
		start:  startOffset,
		length: length,
		writer: writer,
	})

	return err
}

// GetObjectInfo returns meta information about the object.
func (n *neofsObject) GetObjectInfo(ctx context.Context, bucket, object string, opts minio.ObjectOptions) (minio.ObjectInfo, error) {
	var (
		err           error
		result        minio.ObjectInfo
		notFoundError = minio.ObjectNotFound{
			Bucket: bucket,
			Object: object,
		}
	)

	containerID, err := refs.CIDFromString(bucket)
	if err != nil {
		return result, err
	}

	objectID, err := n.objectFindID(ctx, containerID, object, false)
	if err != nil {
		return result, notFoundError
	}

	addr := refs.Address{
		ObjectID: objectID,
		CID:      containerID,
	}

	meta, err := n.objectHead(ctx, addr)
	if err != nil {
		return result, err
	}

	return objectInfoFromMeta(meta), nil
}

// PutObject into storage.
func (n *neofsObject) PutObject(ctx context.Context, bucket, object string, data *minio.PutObjReader, opts minio.ObjectOptions) (minio.ObjectInfo, error) {
	var (
		result            minio.ObjectInfo
		objectExistsError = minio.ObjectAlreadyExists{
			Bucket: bucket,
			Object: object,
		}
	)

	containerID, err := refs.CIDFromString(bucket)
	if err != nil {
		return result, err
	}

	// check if object with such name already exists in the bucket
	_, err = n.objectFindID(ctx, containerID, object, true)
	if err == nil {
		return result, objectExistsError
	}

	objectID, err := refs.NewObjectID()
	if err != nil {
		return result, err
	}

	storageGroupID, err := refs.NewObjectID()
	if err != nil {
		return result, err
	}

	addr := refs.Address{
		ObjectID: objectID,
		CID:      containerID,
	}

	meta, err := n.objectPut(ctx, putParams{
		addr:        addr,
		name:        object,
		size:        data.Size(),
		r:           data.Reader,
		userHeaders: opts.UserDefined,
	})
	if err != nil {
		return result, err
	}

	oi := objectInfoFromMeta(meta)

	// for every object create storage group, otherwise object will be deleted
	addr.ObjectID = storageGroupID

	_, err = n.storageGroupPut(ctx, sgParams{
		addr:    addr,
		objects: []refs.ObjectID{objectID},
	})
	if err != nil {
		return result, err
	}

	return oi, nil
}

// CopyObject from one bucket into another bucket.
func (n *neofsObject) CopyObject(ctx context.Context, srcBucket, srcObject, destBucket, destObject string, srcInfo minio.ObjectInfo, srcOpts, dstOpts minio.ObjectOptions) (minio.ObjectInfo, error) {
	objInfo, err := n.GetObjectInfo(ctx, srcBucket, srcObject, srcOpts)
	if err != nil {
		return objInfo, err
	}

	pr, pw := io.Pipe()

	go func() {
		err := n.GetObject(ctx, srcBucket, srcObject, 0, 0, pw, "", srcOpts)
		_ = pw.CloseWithError(err)
	}()

	data := new(minio.PutObjReader)

	// ignore hex
	data.Reader, err = hash.NewReader(pr, objInfo.Size, "", "", objInfo.Size, false)
	if err != nil {
		return objInfo, err
	}

	_, err = n.PutObject(ctx, destBucket, destObject, data, dstOpts)

	return objInfo, err
}

// DeleteObject from the storage.
func (n *neofsObject) DeleteObject(ctx context.Context, bucket, object string) error {
	containerID, err := refs.CIDFromString(bucket)
	if err != nil {
		return err
	}

	objectID, err := n.objectFindID(ctx, containerID, object, false)
	if err != nil {
		return err
	}

	addr := refs.Address{
		ObjectID: objectID,
		CID:      containerID,
	}

	// maybe we need to wait some time after objectDelete() to propagate
	// tombstone before return from function, e.g. validate delete by
	// performing head operation
	return n.objectDelete(ctx, delParams{
		addr: addr,
	})
}

// DeleteObjects from the storage.
func (n *neofsObject) DeleteObjects(ctx context.Context, bucket string, objects []string) ([]error, error) {
	var errs = make([]error, 0, len(objects))

	for i := range objects {
		errs = append(errs, n.DeleteObject(ctx, bucket, objects[i]))
	}

	return errs, nil
}

// IsNotificationSupported - no
func (n *neofsObject) IsNotificationSupported() bool {
	return false
}

// IsListenBucketSupported - no
func (n *neofsObject) IsListenBucketSupported() bool {
	return false
}

// IsEncryptionSupported - no
func (n *neofsObject) IsEncryptionSupported() bool {
	return false
}

// IsCompressionSupported - no
func (n *neofsObject) IsCompressionSupported() bool {
	return false
}

// IsReady returns whether the layer is ready to take requests.
func (n *neofsObject) IsReady(ctx context.Context) bool {
	if conn, err := n.cli.GetConnection(ctx); err == nil {
		return conn.GetState() == connectivity.Ready
	}

	return false
}
