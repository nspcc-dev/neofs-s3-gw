package bearer

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"sync"
	"time"

	sdk "github.com/nspcc-dev/cdn-sdk"
	"github.com/nspcc-dev/neofs-api-go/pkg/container"
	"github.com/nspcc-dev/neofs-api-go/pkg/object"
	"github.com/nspcc-dev/neofs-api-go/pkg/token"
	"github.com/nspcc-dev/neofs-s3-gw/creds/hcs"
	"github.com/nspcc-dev/neofs-s3-gw/creds/accessbox"
)

type (
	Credentials interface {
		Get(context.Context, *object.Address) (*token.BearerToken, error)
		Put(context.Context, *container.ID, *token.BearerToken, ...hcs.PublicKey) (*object.Address, error)
	}

	cred struct {
		key hcs.PrivateKey
		obj sdk.ObjectClient
	}
)

var (
	ErrEmptyPublicKeys  = errors.New("HCS public keys could not be empty")
	ErrEmptyBearerToken = errors.New("Bearer token could not be empty")
)

var bufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

var _ = New

func New(cli sdk.ObjectClient, key hcs.PrivateKey) Credentials {
	return &cred{obj: cli, key: key}
}

func (c *cred) acquireBuffer() *bytes.Buffer {
	return bufferPool.Get().(*bytes.Buffer)
}

func (c *cred) releaseBuffer(buf *bytes.Buffer) {
	buf.Reset()
	bufferPool.Put(buf)
}

func (c *cred) Get(ctx context.Context, address *object.Address) (*token.BearerToken, error) {
	buf := c.acquireBuffer()
	defer c.releaseBuffer(buf)

	box := accessbox.NewBearerBox(nil)

	if _, err := c.obj.Get(ctx, address, sdk.WithGetWriter(buf)); err != nil {
		return nil, err
	} else if err = accessbox.NewDecoder(buf, c.key).Decode(box); err != nil {
		return nil, err
	}

	return box.Token(), nil
}

func (c *cred) Put(ctx context.Context, cid *container.ID, tkn *token.BearerToken, keys ...hcs.PublicKey) (*object.Address, error) {
	var (
		err error
		buf = c.acquireBuffer()
		box = accessbox.NewBearerBox(tkn)

		created = strconv.FormatInt(time.Now().Unix(), 10)
	)

	defer c.releaseBuffer(buf)

	if len(keys) == 0 {
		return nil, ErrEmptyPublicKeys
	} else if tkn == nil {
		return nil, ErrEmptyBearerToken
	} else if err = accessbox.NewEncoder(buf, c.key, keys...).Encode(box); err != nil {
		return nil, err
	}

	timestamp := object.NewAttribute()
	timestamp.SetKey(object.AttributeTimestamp)
	timestamp.SetValue(created)

	filename := object.NewAttribute()
	filename.SetKey(object.AttributeFileName)
	filename.SetValue(created + "_access.box")

	raw := object.NewRaw()
	raw.SetContainerID(cid)
	raw.SetOwnerID(tkn.Issuer())
	raw.SetAttributes(filename, timestamp)

	return c.obj.Put(ctx, raw.Object(), sdk.WithPutReader(buf))
}
