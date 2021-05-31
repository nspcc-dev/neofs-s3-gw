package bearer

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/nspcc-dev/neofs-api-go/pkg/client"
	"github.com/nspcc-dev/neofs-api-go/pkg/container"
	"github.com/nspcc-dev/neofs-api-go/pkg/object"
	"github.com/nspcc-dev/neofs-api-go/pkg/token"
	"github.com/nspcc-dev/neofs-s3-gw/creds/accessbox"
	"github.com/nspcc-dev/neofs-s3-gw/creds/hcs"
	"github.com/nspcc-dev/neofs-sdk-go/pkg/pool"
)

type (
	// Credentials is a bearer token get/put interface.
	Credentials interface {
		Get(context.Context, *object.Address) (*token.BearerToken, error)
		Put(context.Context, *container.ID, *token.BearerToken, ...hcs.PublicKey) (*object.Address, error)
	}

	cred struct {
		key  hcs.PrivateKey
		pool pool.Pool
	}
)

var (
	// ErrEmptyPublicKeys is returned when no HCS keys are provided.
	ErrEmptyPublicKeys = errors.New("HCS public keys could not be empty")
	// ErrEmptyBearerToken is returned when no bearer token is provided.
	ErrEmptyBearerToken = errors.New("Bearer token could not be empty")
)

var bufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

var _ = New

// New creates new Credentials instance using given cli and key.
func New(conns pool.Pool, key hcs.PrivateKey) Credentials {
	return &cred{pool: conns, key: key}
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

	conn, tok, err := c.pool.Connection()
	if err != nil {
		return nil, err
	}
	ops := new(client.GetObjectParams).WithAddress(address).WithPayloadWriter(buf)

	_, err = conn.GetObject(
		ctx,
		ops,
		client.WithSession(tok),
	)
	if err != nil {
		return nil, err
	}

	err = accessbox.NewDecoder(buf, c.key).Decode(box)
	if err != nil {
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

	conn, tok, err := c.pool.Connection()
	if err != nil {
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

	ops := new(client.PutObjectParams).WithObject(raw.Object()).WithPayloadReader(buf)
	oid, err := conn.PutObject(
		ctx,
		ops,
		client.WithSession(tok),
	)
	if err != nil {
		return nil, err
	}
	address := object.NewAddress()
	address.SetObjectID(oid)
	address.SetContainerID(cid)
	return address, nil
}
