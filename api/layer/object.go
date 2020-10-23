package layer

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/nspcc-dev/neofs-api-go/pkg/client"
	"github.com/nspcc-dev/neofs-api-go/pkg/container"
	"github.com/nspcc-dev/neofs-api-go/pkg/object"
	"github.com/nspcc-dev/neofs-api-go/pkg/owner"
	"github.com/nspcc-dev/neofs-api-go/pkg/token"
	"github.com/nspcc-dev/neofs-s3-gate/api"
	"github.com/nspcc-dev/neofs-s3-gate/auth"
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

		addr *object.Address

		offset int64
		length int64
	}
)

func (n *layer) prepareClient(ctx context.Context) (*client.Client, *token.SessionToken, error) {
	conn, err := n.cli.Connection(ctx)
	if err != nil {
		return nil, nil, err
	}

	tkn, err := n.cli.Token(ctx, conn)
	if err != nil {
		return nil, nil, err
	}

	cli, err := client.New(n.key, client.WithGRPCConnection(conn))
	if err != nil {
		return nil, nil, err
	}

	return cli, tkn, nil
}

// objectSearch returns all available objects by search params.
func (n *layer) objectSearch(ctx context.Context, p *findParams) ([]*object.ID, error) {
	cli, tkn, err := n.prepareClient(ctx)
	if err != nil {
		return nil, err
	}

	filter := object.NewSearchFilters()
	filter.AddRootFilter()

	sop := new(client.SearchObjectParams)
	sop.WithContainerID(p.cid)

	if p.val != "" {
		filter.AddFilter(object.AttributeFileName, p.val, object.MatchStringEqual)
	}

	sop.WithSearchFilters(filter)

	return cli.SearchObject(ctx, sop, client.WithSession(tkn))
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
func (n *layer) objectHead(ctx context.Context, addr *object.Address) (*object.Object, error) {
	cli, tkn, err := n.prepareClient(ctx)
	if err != nil {
		return nil, err
	}

	ohp := new(client.ObjectHeaderParams)
	ohp.WithAddress(addr)
	ohp.WithAllFields()

	return cli.GetObjectHeader(ctx, ohp, client.WithSession(tkn))
}

// objectGet and write it into provided io.Reader.
func (n *layer) objectGet(ctx context.Context, p *getParams) (*object.Object, error) {
	cli, tkn, err := n.prepareClient(ctx)
	if err != nil {
		return nil, err
	}

	// prepare length/offset writer
	writer := newWriter(p.Writer, p.offset, p.length)

	gop := new(client.GetObjectParams)
	gop.WithAddress(p.addr)
	gop.WithPayloadWriter(writer)

	return cli.GetObject(ctx, gop, client.WithSession(tkn))
}

// objectPut into NeoFS, took payload from io.Reader.
func (n *layer) objectPut(ctx context.Context, p *PutObjectParams) (*ObjectInfo, error) {
	var (
		err error
		own *owner.ID
		bkt *BucketInfo
		brt *token.BearerToken
	)

	if brt, err = auth.GetBearerToken(ctx); err != nil {
		return nil, err
	} else if own, err = GetOwnerID(brt); err != nil {
		return nil, err
	}

	_ = own

	if bkt, err = n.GetBucketInfo(ctx, p.Bucket); err != nil {
		return nil, err
	} else if _, err = n.objectFindID(ctx, &findParams{cid: bkt.CID, val: p.Object}); err == nil {
		return nil, &api.ObjectAlreadyExists{
			Bucket: p.Bucket,
			Object: p.Object,
		}
	}

	cli, tkn, err := n.prepareClient(ctx)
	if err != nil {
		return nil, err
	}

	attributes := make([]*object.Attribute, 0, len(p.Header)+1)

	unix := strconv.FormatInt(time.Now().UTC().Unix(), 64)

	filename := object.NewAttribute()
	filename.SetKey(object.AttributeFileName)
	filename.SetValue(p.Object)

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
	r := io.TeeReader(p.Reader, b)

	raw := object.NewRaw()
	raw.SetOwnerID(tkn.OwnerID()) // should be replaced with BearerToken.Issuer()
	raw.SetContainerID(bkt.CID)
	raw.SetAttributes(attributes...)

	pop := new(client.PutObjectParams)
	pop.WithPayloadReader(r)
	pop.WithObject(raw.Object())

	if _, err = cli.PutObject(ctx, pop, client.WithSession(tkn)); err != nil {
		return nil, errors.Wrapf(err, "owner_id = %s", tkn.OwnerID())
	}

	return &ObjectInfo{
		Bucket:      p.Bucket,
		Name:        p.Object,
		Size:        p.Size,
		Created:     time.Now(),
		ContentType: http.DetectContentType(b.Bytes()),
		Owner:       own,
		Headers:     p.Header,
	}, nil
}

// objectDelete puts tombstone object into neofs.
func (n *layer) objectDelete(ctx context.Context, address *object.Address) error {
	cli, tkn, err := n.prepareClient(ctx)
	if err != nil {
		return err
	}

	dob := new(client.DeleteObjectParams)
	dob.WithAddress(address)

	return cli.DeleteObject(ctx, dob, client.WithSession(tkn))
}
