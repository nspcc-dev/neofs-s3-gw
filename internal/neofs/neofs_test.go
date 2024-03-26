package neofs

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	apistatus "github.com/nspcc-dev/neofs-sdk-go/client/status"
	"github.com/nspcc-dev/neofs-sdk-go/container"
	"github.com/nspcc-dev/neofs-sdk-go/container/acl"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/netmap"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"github.com/nspcc-dev/neofs-sdk-go/waiter"
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
		MaxObjectSize:        int64(ni.MaxObjectSize()),
		IsSlicerEnabled:      false,
		IsHomomorphicEnabled: !ni.HomomorphicHashingDisabled(),
	}

	neo := NewNeoFS(p, signer, anonSigner, neofsCfg, ni)

	var createParams layer.PrmObjectCreate
	createParams.Creator = signer.UserID()

	for i := 128; i <= 512; i += 128 {
		b.Run("object upload "+strconv.Itoa(i), func(b *testing.B) {
			b.StopTimer()
			payload := make([]byte, i*1024)
			_, err = rand.Read(payload)
			require.NoError(b, err)

			id, err := createContainer(ctx, signer, p)
			require.NoError(b, err)
			createParams.Container = id

			defer func() {
				_ = deleteContainer(ctx, id, signer, p)
			}()

			b.ReportAllocs()
			b.ResetTimer()
			b.StartTimer()

			for i := 0; i < b.N; i++ {
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

	w := waiter.NewContainerPutWaiter(p, waiter.DefaultPollInterval)
	return w.ContainerPut(ctx, cnr, signer, prm)
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
		MaxObjectSize:        int64(ni.MaxObjectSize()),
		IsSlicerEnabled:      false,
		IsHomomorphicEnabled: !ni.HomomorphicHashingDisabled(),
	}

	neo := NewNeoFS(p, signer, anonSigner, neofsCfg, ni)

	var createParams layer.PrmObjectCreate
	createParams.Creator = signer.UserID()

	wg := sync.WaitGroup{}
	wg.Add(gorutines)

	for i := 0; i < gorutines; i++ {
		go func() {
			uploadDownload(ctx, t, neo, p, signer, createParams, &wg)
		}()
	}

	<-time.After(30 * time.Second)
	cancel()
	wg.Wait()
}

func uploadDownload(ctx context.Context, t *testing.T, neo *NeoFS, p *pool.Pool, signer user.Signer, createParams layer.PrmObjectCreate, wg *sync.WaitGroup) {
	defer wg.Done()

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

		_, err = rand.Read(payload)
		require.NoError(t, err)

		createParams.Payload = bytes.NewReader(payload)
		createParams.CreationTime = time.Now()

		objID, err := neo.CreateObject(opContext, createParams)
		require.NoError(t, err)

		var objReadPrm layer.PrmObjectRead
		objReadPrm.Object = objID
		objReadPrm.Container = id

		op, err := neo.ReadObject(opContext, objReadPrm)
		require.NoError(t, err)

		pl, err := io.ReadAll(op.Payload)
		require.NoError(t, err)

		require.True(t, bytes.Equal(payload, pl))
	}
}
