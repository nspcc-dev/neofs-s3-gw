package layer

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	sdk "github.com/nspcc-dev/cdn-neofs-sdk"
	"github.com/nspcc-dev/neofs-api-go/pkg/container"
	"github.com/nspcc-dev/neofs-api-go/pkg/object"
	"github.com/nspcc-dev/neofs-api-go/pkg/token"
	"github.com/nspcc-dev/neofs-s3-gate/api"
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

	filename, err := url.QueryUnescape(p.val)
	if err != nil {
		return nil, err
	}

	if p.val != "" {
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
	b := bufio.NewWriter(p.Writer)
	w := newWriter(b, p.offset, p.length)
	writer := newWriter(w, p.offset, p.length)

	return n.cli.Object().Get(ctx, p.address, sdk.WithGetWriter(writer))
}

// objectPut into NeoFS, took payload from io.Reader.
func (n *layer) objectPut(ctx context.Context, p *PutObjectParams) (*ObjectInfo, error) {
	var (
		err error
		obj string
		bkt *BucketInfo
		brt *token.BearerToken

		address *object.Address
	)

	if brt, err = sdk.BearerToken(ctx); err != nil {
		return nil, err
	} else if obj, err = url.QueryUnescape(p.Object); err != nil {
		return nil, err
	} else if bkt, err = n.GetBucketInfo(ctx, p.Bucket); err != nil {
		return nil, err
	} else if _, err = n.objectFindID(ctx, &findParams{cid: bkt.CID, val: p.Object}); err == nil {
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

	b := new(bytes.Buffer)

	raw := object.NewRaw()
	raw.SetOwnerID(brt.Issuer())
	raw.SetContainerID(bkt.CID)
	raw.SetAttributes(attributes...)

	r := io.TeeReader(p.Reader, b)
	if address, err = n.cli.Object().Put(ctx, raw.Object(), sdk.WithPutReader(r)); err != nil {
		return nil, err
	}

	return &ObjectInfo{
		id: address.ObjectID(),

		Bucket:      p.Bucket,
		Name:        p.Object,
		Size:        p.Size,
		Created:     time.Now(),
		ContentType: http.DetectContentType(b.Bytes()),
		Owner:       brt.Issuer(),
		Headers:     p.Header,
	}, nil
}

// objectDelete puts tombstone object into neofs.
func (n *layer) objectDelete(ctx context.Context, address *object.Address) error {
	return n.cli.Object().Delete(ctx, address)
}
