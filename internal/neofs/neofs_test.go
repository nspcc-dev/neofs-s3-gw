package neofs

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"strconv"
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
	pp.AddReplicas(rd)

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
