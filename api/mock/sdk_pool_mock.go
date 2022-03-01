package mock

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"

	"github.com/nspcc-dev/neofs-sdk-go/accounting"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	"github.com/nspcc-dev/neofs-sdk-go/container"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	"github.com/nspcc-dev/neofs-sdk-go/owner"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-sdk-go/session"
)

type TestPool struct {
	Objects      map[string]*object.Object
	Containers   map[string]*container.Container
	CurrentEpoch uint64
}

func NewTestPool() *TestPool {
	return &TestPool{
		Objects:    make(map[string]*object.Object),
		Containers: make(map[string]*container.Container),
	}
}

func (t *TestPool) PutObject(ctx context.Context, params *client.PutObjectParams, option ...pool.CallOption) (*object.ID, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}

	oid := object.NewID()
	oid.SetSHA256(sha256.Sum256(b))

	raw := object.NewRawFrom(params.Object())
	raw.SetID(oid)
	raw.SetCreationEpoch(t.CurrentEpoch)
	t.CurrentEpoch++

	if params.PayloadReader() != nil {
		all, err := io.ReadAll(params.PayloadReader())
		if err != nil {
			return nil, err
		}
		raw.SetPayload(all)
	}
	raw.SetPayloadSize(uint64(len(raw.Payload())))

	addr := newAddress(raw.ContainerID(), raw.ID())
	t.Objects[addr.String()] = raw.Object()
	return raw.ID(), nil
}

func (t *TestPool) DeleteObject(ctx context.Context, params *client.DeleteObjectParams, option ...pool.CallOption) error {
	delete(t.Objects, params.Address().String())
	return nil
}

func (t *TestPool) GetObject(ctx context.Context, params *client.GetObjectParams, option ...pool.CallOption) (*object.Object, error) {
	if obj, ok := t.Objects[params.Address().String()]; ok {
		if params.PayloadWriter() != nil {
			_, err := params.PayloadWriter().Write(obj.Payload())
			if err != nil {
				return nil, err
			}
		}
		return obj, nil
	}

	return nil, fmt.Errorf("object not found " + params.Address().String())
}

func (t *TestPool) GetObjectHeader(ctx context.Context, params *client.ObjectHeaderParams, option ...pool.CallOption) (*object.Object, error) {
	p := new(client.GetObjectParams).WithAddress(params.Address())
	return t.GetObject(ctx, p)
}

func (t *TestPool) ObjectPayloadRangeData(ctx context.Context, params *client.RangeDataParams, option ...pool.CallOption) ([]byte, error) {
	panic("implement me")
}

func (t *TestPool) ObjectPayloadRangeSHA256(ctx context.Context, params *client.RangeChecksumParams, option ...pool.CallOption) ([][32]byte, error) {
	panic("implement me")
}

func (t *TestPool) ObjectPayloadRangeTZ(ctx context.Context, params *client.RangeChecksumParams, option ...pool.CallOption) ([][64]byte, error) {
	panic("implement me")
}

func (t *TestPool) SearchObject(ctx context.Context, params *client.SearchObjectParams, option ...pool.CallOption) ([]*object.ID, error) {
	cidStr := params.ContainerID().String()

	var res []*object.ID

	if len(params.SearchFilters()) == 1 {
		for k, v := range t.Objects {
			if strings.Contains(k, cidStr) {
				res = append(res, v.ID())
			}
		}
		return res, nil
	}

	filter := params.SearchFilters()[1]
	if len(params.SearchFilters()) != 2 || filter.Operation() != object.MatchStringEqual ||
		(filter.Header() != object.AttributeFileName && filter.Header() != "S3-System-name") {
		return nil, fmt.Errorf("usupported filters")
	}

	for k, v := range t.Objects {
		if strings.Contains(k, cidStr) && isMatched(v.Attributes(), filter) {
			res = append(res, v.ID())
		}
	}

	return res, nil
}

func isMatched(attributes []*object.Attribute, filter object.SearchFilter) bool {
	for _, attr := range attributes {
		if attr.Key() == filter.Header() && attr.Value() == filter.Value() {
			return true
		}
	}

	return false
}

func (t *TestPool) PutContainer(ctx context.Context, container *container.Container, option ...pool.CallOption) (*cid.ID, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}

	id := cid.New()
	id.SetSHA256(sha256.Sum256(b))
	t.Containers[id.String()] = container

	return id, nil
}

func (t *TestPool) GetContainer(ctx context.Context, id *cid.ID, option ...pool.CallOption) (*container.Container, error) {
	for k, v := range t.Containers {
		if k == id.String() {
			return v, nil
		}
	}

	return nil, fmt.Errorf("container not found " + id.String())
}

func (t *TestPool) ListContainers(ctx context.Context, id *owner.ID, option ...pool.CallOption) ([]*cid.ID, error) {
	var res []*cid.ID
	for k := range t.Containers {
		cID := cid.New()
		if err := cID.Parse(k); err != nil {
			return nil, err
		}
		res = append(res, cID)
	}

	return res, nil
}

func (t *TestPool) DeleteContainer(ctx context.Context, id *cid.ID, option ...pool.CallOption) error {
	delete(t.Containers, id.String())
	return nil
}

func (t *TestPool) GetEACL(ctx context.Context, id *cid.ID, option ...pool.CallOption) (*eacl.Table, error) {
	panic("implement me")
}

func (t *TestPool) Balance(ctx context.Context, owner *owner.ID, opts ...pool.CallOption) (*accounting.Decimal, error) {
	panic("implement me")
}

func (t *TestPool) SetEACL(ctx context.Context, table *eacl.Table, option ...pool.CallOption) error {
	panic("implement me")
}

func (t *TestPool) AnnounceContainerUsedSpace(ctx context.Context, announcements []container.UsedSpaceAnnouncement, option ...pool.CallOption) error {
	panic("implement me")
}

func (t *TestPool) Connection() (pool.Client, *session.Token, error) {
	panic("implement me")
}

func (t *TestPool) Close() {
	panic("implement me")
}

func (t *TestPool) OwnerID() *owner.ID {
	return nil
}

func (t *TestPool) WaitForContainerPresence(ctx context.Context, id *cid.ID, params *pool.ContainerPollingParams) error {
	return nil
}

func newAddress(cid *cid.ID, oid *object.ID) *object.Address {
	address := object.NewAddress()
	address.SetContainerID(cid)
	address.SetObjectID(oid)
	return address
}
