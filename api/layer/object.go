package layer

import (
	"context"
	"io"
	"net/url"
	"strconv"
	"time"

	sdk "github.com/nspcc-dev/cdn-sdk"
	"github.com/nspcc-dev/neofs-api-go/pkg/container"
	"github.com/nspcc-dev/neofs-api-go/pkg/object"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type (
	findParams struct {
		val string
		cid *container.ID
	}

	getParams struct {
		io.Writer

		offset  int64
		length  int64
		address *object.Address
	}
)

// objectSearch returns all available objects by search params.
func (n *layer) objectSearch(ctx context.Context, p *findParams) ([]*object.ID, error) {
	opts := []sdk.ObjectSearchOption{
		sdk.SearchRootObjects(),
	}

	if filename, err := url.QueryUnescape(p.val); err != nil {
		return nil, err
	} else if filename != "" {
		opts = append(opts, sdk.SearchByFilename(filename))
	}
	return n.cli.Object().Search(ctx, p.cid, opts...)
}

// objectFindID returns object id (uuid) based on it's nice name in s3. If
// nice name is uuid compatible, then function returns it.
func (n *layer) objectFindID(ctx context.Context, p *findParams) (*object.ID, error) {
	if result, err := n.objectSearch(ctx, p); err != nil {
		return nil, err
	} else if ln := len(result); ln == 0 {
		return nil, status.Error(codes.NotFound, "object not found")
	} else if ln == 1 {
		return result[0], nil
	}

	return nil, errors.New("several objects with the same name found")
}

// objectHead returns all object's headers.
func (n *layer) objectHead(ctx context.Context, address *object.Address) (*object.Object, error) {
	return n.cli.Object().Head(ctx, address, sdk.WithFullHeaders())
}

// objectGet and write it into provided io.Reader.
func (n *layer) objectGet(ctx context.Context, p *getParams) (*object.Object, error) {
	// prepare length/offset writer
	w := newWriter(p.Writer, p.offset, p.length)
	return n.cli.Object().Get(ctx, p.address, sdk.WithGetWriter(w))
}

// objectPut into NeoFS, took payload from io.Reader.
func (n *layer) objectPut(ctx context.Context, p *PutObjectParams) (*ObjectInfo, error) {
	var (
		err error
		obj string
		bkt *BucketInfo
		own = n.Owner(ctx)

		address *object.Address
	)

	if obj, err = url.QueryUnescape(p.Object); err != nil {
		return nil, err
	} else if bkt, err = n.GetBucketInfo(ctx, p.Bucket); err != nil {
		return nil, err
	} else if err = n.checkObject(ctx, bkt.CID, p.Object); err != nil && err != ErrObjectNotExists {
		return nil, err
	} else if err == ErrObjectExists {
		return nil, &api.ObjectAlreadyExists{
			Bucket: p.Bucket,
			Object: p.Object,
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
	if address, err = n.cli.Object().Put(ctx, raw.Object(), sdk.WithPutReader(r)); err != nil {
		return nil, err
	}

	return &ObjectInfo{
		id: address.ObjectID(),

		Owner:       own,
		Bucket:      p.Bucket,
		Name:        p.Object,
		Size:        p.Size,
		Created:     time.Now(),
		Headers:     p.Header,
		ContentType: r.contentType,
	}, nil
}

// objectDelete puts tombstone object into neofs.
func (n *layer) objectDelete(ctx context.Context, address *object.Address) error {
	return n.cli.Object().Delete(ctx, address)
}
