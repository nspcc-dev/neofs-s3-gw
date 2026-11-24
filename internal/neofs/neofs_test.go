package neofs

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3headers"
	"github.com/nspcc-dev/neofs-s3-gw/creds/tokens"
	"github.com/nspcc-dev/neofs-s3-gw/internal/limits"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	apistatus "github.com/nspcc-dev/neofs-sdk-go/client/status"
	"github.com/nspcc-dev/neofs-sdk-go/container"
	"github.com/nspcc-dev/neofs-sdk-go/container/acl"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	cidtest "github.com/nspcc-dev/neofs-sdk-go/container/id/test"
	neofscryptotest "github.com/nspcc-dev/neofs-sdk-go/crypto/test"
	"github.com/nspcc-dev/neofs-sdk-go/netmap"
	netmaptest "github.com/nspcc-dev/neofs-sdk-go/netmap/test"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"github.com/stretchr/testify/require"
)

func TestErrorChecking(t *testing.T) {
	reason := "some reason"
	err := new(apistatus.ObjectAccessDenied)
	err.WriteReason(reason)

	var wrappedError error

	if fetchedReason, ok := isErrAccessDenied(err); ok {
		wrappedError = fmt.Errorf("%w: %s", layer.ErrAccessDenied, fetchedReason)
	}

	require.ErrorIs(t, wrappedError, layer.ErrAccessDenied)
	require.Contains(t, wrappedError.Error(), reason)
}

func Benchmark(b *testing.B) {
	b.Skip("Required connection to NeoFS cluster")

	ctx := context.Background()

	pk, err := keys.NewPrivateKey()
	require.NoError(b, err)
	signer := user.NewAutoIDSignerRFC6979(pk.PrivateKey)

	anonPk, err := keys.NewPrivateKey()
	require.NoError(b, err)
	anonSigner := user.NewAutoIDSignerRFC6979(anonPk.PrivateKey)

	var prm pool.InitParameters
	prm.SetSigner(signer)
	prm.AddNode(pool.NewNodeParam(1, "localhost:8080", 1))

	p, err := pool.NewPool(prm)
	require.NoError(b, err)

	require.NoError(b, p.Dial(ctx))

	ni, err := p.NetworkInfo(ctx, client.PrmNetworkInfo{})
	require.NoError(b, err)

	neofsCfg := Config{
		MaxObjectSize:   int64(ni.MaxObjectSize()),
		IsSlicerEnabled: false,
	}

	neo := NewNeoFS(p, signer, anonSigner, neofsCfg, ni)

	var createParams layer.PrmObjectCreate
	createParams.Creator = signer.UserID()

	for i := 128; i <= 512; i += 128 {
		b.Run("object upload "+strconv.Itoa(i), func(b *testing.B) {
			b.StopTimer()
			payload := make([]byte, i*1024)
			_, _ = rand.Read(payload)

			id, err := createContainer(ctx, signer, p)
			require.NoError(b, err)
			createParams.Container = id

			defer func() {
				_ = deleteContainer(ctx, id, signer, p)
			}()

			b.ReportAllocs()
			b.ResetTimer()
			b.StartTimer()

			for b.Loop() {
				b.StopTimer()
				createParams.Payload = bytes.NewReader(payload)
				createParams.CreationTime = time.Now()
				b.StartTimer()

				_, err = neo.CreateObject(ctx, createParams)
				b.StopTimer()
				require.NoError(b, err)
				b.StartTimer()
			}
		})
	}
}

func createContainer(ctx context.Context, signer user.Signer, p *pool.Pool) (cid.ID, error) {
	var cnr container.Container
	cnr.Init()
	cnr.SetOwner(signer.UserID())

	var rd netmap.ReplicaDescriptor
	rd.SetNumberOfObjects(1)

	var pp netmap.PlacementPolicy
	pp.SetContainerBackupFactor(1)
	pp.SetReplicas([]netmap.ReplicaDescriptor{rd})

	cnr.SetPlacementPolicy(pp)
	cnr.SetBasicACL(acl.PublicRW)

	var prm client.PrmContainerPut

	return p.ContainerPut(ctx, cnr, signer, prm)
}

func deleteContainer(ctx context.Context, id cid.ID, signer user.Signer, p *pool.Pool) error {
	var prm client.PrmContainerDelete
	return p.ContainerDelete(ctx, id, signer, prm)
}

func TestConcurrencyAndConsistency(t *testing.T) {
	t.Skip("Required connection to NeoFS cluster")

	ctx, cancel := context.WithCancel(context.Background())

	pk, err := keys.NewPrivateKey()
	require.NoError(t, err)
	signer := user.NewAutoIDSignerRFC6979(pk.PrivateKey)

	anonPk, err := keys.NewPrivateKey()
	require.NoError(t, err)
	anonSigner := user.NewAutoIDSignerRFC6979(anonPk.PrivateKey)

	var prm pool.InitParameters
	prm.SetSigner(signer)
	prm.AddNode(pool.NewNodeParam(1, "localhost:8080", 1))

	p, err := pool.NewPool(prm)
	require.NoError(t, err)

	require.NoError(t, p.Dial(ctx))

	ni, err := p.NetworkInfo(ctx, client.PrmNetworkInfo{})
	require.NoError(t, err)

	gorutines := runtime.GOMAXPROCS(0)

	neofsCfg := Config{
		MaxObjectSize:   int64(ni.MaxObjectSize()),
		IsSlicerEnabled: false,
	}

	neo := NewNeoFS(p, signer, anonSigner, neofsCfg, ni)

	var createParams layer.PrmObjectCreate
	createParams.Creator = signer.UserID()

	wg := sync.WaitGroup{}

	for range gorutines {
		wg.Go(func() {
			uploadDownload(ctx, t, neo, p, signer, createParams)
		})
	}

	<-time.After(30 * time.Second)
	cancel()
	wg.Wait()
}

func uploadDownload(ctx context.Context, t *testing.T, neo *NeoFS, p *pool.Pool, signer user.Signer, createParams layer.PrmObjectCreate) {
	payload := make([]byte, 32*1024)

	id, err := createContainer(ctx, signer, p)
	require.NoError(t, err)
	createParams.Container = id

	defer func() {
		_ = deleteContainer(ctx, id, signer, p)
	}()

	// separate context to operations to catch ContextCanceled only in Select.
	opContext := context.Background()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		_, _ = rand.Read(payload)

		createParams.Payload = bytes.NewReader(payload)
		createParams.CreationTime = time.Now()

		objID, err := neo.CreateObject(opContext, createParams) //nolint:contextcheck // It's intentional, see above
		require.NoError(t, err)

		var objReadPrm layer.PrmObjectRead
		objReadPrm.Object = objID
		objReadPrm.Container = id

		op, err := neo.ReadObject(opContext, objReadPrm) //nolint:contextcheck // It's intentional, see above
		require.NoError(t, err)

		pl, err := io.ReadAll(op.Payload)
		require.NoError(t, err)

		require.True(t, bytes.Equal(payload, pl))
	}
}

func TestCheckPlacement(t *testing.T) {
	var nm netmap.NetMap
	nm.SetNodes([]netmap.NodeInfo{netmaptest.NodeInfo()})

	t.Run("applicable", func(t *testing.T) {
		var policy netmap.PlacementPolicy
		require.NoError(t, policy.DecodeString("REP 1"))

		require.NoError(t, checkPlacement(nm, policy, cidtest.ID()))
	})

	t.Run("not enough nodes", func(t *testing.T) {
		var policy netmap.PlacementPolicy
		require.NoError(t, policy.DecodeString("REP 3"))

		err := checkPlacement(nm, policy, cidtest.ID())
		require.ErrorIs(t, err, layer.ErrInapplicablePolicy)
		require.ErrorIs(t, err, netmap.ErrNotEnoughNodes)
	})
}

func TestObjectNonce(t *testing.T) {
	var (
		signer  = user.NewAutoIDSignerRFC6979(neofscryptotest.Signer().ECDSAPrivateKey)
		cnrID   = cidtest.ID()
		payload = []byte{1, 2, 3, 4, 5}
		uid     = signer.UserID()
		m       = make(map[string]int)
		ts      = time.Now().Unix()
		attrTS  = object.NewAttribute(object.AttributeTimestamp, strconv.FormatInt(ts, 10))
	)

	for range 10 {
		var (
			obj   object.Object
			nonce = make([]byte, objectNonceSize)
		)

		_, _ = rand.Read(nonce)

		obj.SetContainerID(cnrID)
		obj.SetOwner(uid)
		obj.SetPayloadSize(uint64(len(payload)))
		obj.SetPayload(payload)

		var (
			attr  = object.NewAttribute(s3headers.AttributeObjectNonce, base64.StdEncoding.EncodeToString(nonce))
			attrs = []object.Attribute{attrTS, attr}
		)

		obj.SetAttributes(attrs...)
		require.NoError(t, obj.CalculateAndSetID())

		m[obj.GetID().String()]++
	}

	// each ID is uniq
	for _, v := range m {
		require.Equal(t, 1, v)
	}
}

type authmateNeoFSStub struct {
	layer.NeoFS
	res *layer.ObjectPart
	err error
}

func (s *authmateNeoFSStub) ReadObject(context.Context, layer.PrmObjectRead) (*layer.ObjectPart, error) {
	return s.res, s.err
}

type payloadStub struct {
	io.Reader
}

func (payloadStub) Close() error { return nil }

func (p payloadStub) WriteTo(w io.Writer) (int64, error) { return io.Copy(w, p.Reader) }

func TestAuthmateNeoFSReadObject(t *testing.T) {
	var (
		errDenied = fmt.Errorf("%w: some reason", layer.ErrAccessDenied)
		errOther  = errors.New("connection refused")
		payload   = []byte("payload")
	)

	newPart := func(size uint64, r io.Reader) *layer.ObjectPart {
		var hdr object.Object
		hdr.SetPayloadSize(size)
		return &layer.ObjectPart{Head: &hdr, Payload: payloadStub{r}}
	}

	t.Run("valid", func(t *testing.T) {
		neoFS := NewAuthmateNeoFS(&authmateNeoFSStub{res: newPart(uint64(len(payload)), bytes.NewReader(payload))})

		data, hdr, err := neoFS.ReadObject(context.Background(), oid.Address{})
		require.NoError(t, err)
		require.Equal(t, payload, data)
		require.EqualValues(t, len(payload), hdr.PayloadSize())
	})

	for _, tc := range []struct {
		name    string
		stub    authmateNeoFSStub
		invalid bool
	}{
		{name: "access denied", stub: authmateNeoFSStub{err: errDenied}, invalid: true},
		{name: "access denied on payload read", stub: authmateNeoFSStub{res: newPart(1, iotest.ErrReader(errDenied))}, invalid: true},
		{name: "too big", stub: authmateNeoFSStub{res: newPart(limits.MaxAccessBoxSize+1, bytes.NewReader(nil))}, invalid: true},
		{name: "other failure", stub: authmateNeoFSStub{err: errOther}},
		{name: "other failure on payload read", stub: authmateNeoFSStub{res: newPart(1, iotest.ErrReader(errOther))}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := NewAuthmateNeoFS(&tc.stub).ReadObject(context.Background(), oid.Address{})
			require.Error(t, err)
			require.Equal(t, tc.invalid, errors.Is(err, tokens.ErrInvalidAccessBox), err)
		})
	}
}
