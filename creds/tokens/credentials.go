package tokens

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/api/cache"
	"github.com/nspcc-dev/neofs-s3-gw/creds/accessbox"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	"github.com/nspcc-dev/neofs-sdk-go/object/address"
	"github.com/nspcc-dev/neofs-sdk-go/owner"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
)

type (
	// Credentials is a bearer token get/put interface.
	Credentials interface {
		GetBox(context.Context, *address.Address) (*accessbox.Box, error)
		Put(context.Context, *cid.ID, *owner.ID, *accessbox.AccessBox, uint64, ...*keys.PublicKey) (*address.Address, error)
	}

	cred struct {
		key   *keys.PrivateKey
		pool  pool.Pool
		cache *cache.AccessBoxCache
	}
)

var (
	// ErrEmptyPublicKeys is returned when no HCS keys are provided.
	ErrEmptyPublicKeys = errors.New("HCS public keys could not be empty")
	// ErrEmptyBearerToken is returned when no bearer token is provided.
	ErrEmptyBearerToken = errors.New("Bearer token could not be empty")
)

var _ = New

// New creates new Credentials instance using given cli and key.
func New(conns pool.Pool, key *keys.PrivateKey, config *cache.Config) Credentials {
	return &cred{pool: conns, key: key, cache: cache.NewAccessBoxCache(config)}
}

func (c *cred) GetBox(ctx context.Context, addr *address.Address) (*accessbox.Box, error) {
	cachedBox := c.cache.Get(addr)
	if cachedBox != nil {
		return cachedBox, nil
	}

	box, err := c.getAccessBox(ctx, addr)
	if err != nil {
		return nil, err
	}

	cachedBox, err = box.GetBox(c.key)
	if err != nil {
		return nil, err
	}

	if err = c.cache.Put(addr, cachedBox); err != nil {
		return nil, err
	}

	return cachedBox, nil
}

func (c *cred) getAccessBox(ctx context.Context, addr *address.Address) (*accessbox.AccessBox, error) {
	// init payload reader
	res, err := c.pool.GetObject(ctx, *addr)
	if err != nil {
		return nil, fmt.Errorf("client pool failure: %w", err)
	}

	defer res.Payload.Close()

	// read payload
	var data []byte

	if sz := res.Header.PayloadSize(); sz > 0 {
		data = make([]byte, sz)

		_, err = io.ReadFull(res.Payload, data)
		if err != nil {
			return nil, fmt.Errorf("read payload: %w", err)
		}
	}

	// decode access box
	var box accessbox.AccessBox
	if err = box.Unmarshal(data); err != nil {
		return nil, err
	}

	return &box, nil
}

func (c *cred) Put(ctx context.Context, cid *cid.ID, issuer *owner.ID, box *accessbox.AccessBox, expiration uint64, keys ...*keys.PublicKey) (*address.Address, error) {
	var (
		err     error
		created = strconv.FormatInt(time.Now().Unix(), 10)
	)

	if len(keys) == 0 {
		return nil, ErrEmptyPublicKeys
	} else if box == nil {
		return nil, ErrEmptyBearerToken
	}
	data, err := box.Marshal()
	if err != nil {
		return nil, err
	}

	timestamp := object.NewAttribute()
	timestamp.SetKey(object.AttributeTimestamp)
	timestamp.SetValue(created)

	filename := object.NewAttribute()
	filename.SetKey(object.AttributeFileName)
	filename.SetValue(created + "_access.box")

	expirationAttr := object.NewAttribute()
	expirationAttr.SetKey("__NEOFS__EXPIRATION_EPOCH")
	expirationAttr.SetValue(strconv.FormatUint(expiration, 10))

	raw := object.NewRaw()
	raw.SetContainerID(cid)
	raw.SetOwnerID(issuer)
	raw.SetAttributes(filename, timestamp, expirationAttr)
	raw.SetPayload(data)

	oid, err := c.pool.PutObject(ctx, *raw.Object(), nil)
	if err != nil {
		return nil, err
	}

	addr := address.NewAddress()
	addr.SetObjectID(oid)
	addr.SetContainerID(cid)
	return addr, nil
}
