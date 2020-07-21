package layer

import (
	"context"
	"crypto/ecdsa"
	"math"
	"time"

	s3auth "github.com/minio/minio/auth"
	minio "github.com/minio/minio/legacy"
	"github.com/minio/minio/neofs/pool"
	"github.com/nspcc-dev/neofs-api-go/refs"
	"github.com/nspcc-dev/neofs-api-go/service"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type (
	// neofsObjects implements gateway for MinIO and S3
	// compatible object storage server.
	neofsObject struct {
		minio.GatewayUnsupported // placeholder for unimplemented functions

		log         *zap.Logger
		cli         pool.Client
		key         *ecdsa.PrivateKey
		owner       refs.OwnerID
		token       *service.Token
		bearerToken *service.BearerTokenMsg

		// Concurrency must be resolved by creating one lock per object, but
		// it may be unnecessary in neofs, because objects are immutable. So
		// there are no any mutexes and locks right now but it might be
		// useful during parallel execution from one client (different clients
		// have different `neofsObject` instances).

		// todo: add fast expired cache to store list of containers or
		//       even short objects during sequential reading
	}
)

// NewGatewayLayer creates instance of neofsObject. It checks credentials
// and establishes gRPC connection with node.
func NewLayer(log *zap.Logger, cli pool.Client, center *s3auth.Center) (minio.ObjectLayer, error) {
	// setup gRPC connection
	// todo: think about getting timeout parameters from cli args
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	token, err := generateToken(ctx, tokenParams{
		cli:   cli,
		key:   center.GetNeoFSPrivateKey(),
		until: math.MaxInt64,
	})
	if err != nil {
		return nil, errors.Wrap(err, "can't establish neofs session with remote host")
	}
	return &neofsObject{
		cli:   cli,
		key:   center.GetNeoFSPrivateKey(),
		log:   log,
		owner: center.GetOwnerID(),
		token: token,
	}, nil
}
