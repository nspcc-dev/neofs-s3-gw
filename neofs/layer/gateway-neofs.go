package layer

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"math"
	"time"

	minio "github.com/minio/minio/cmd"
	"github.com/minio/minio/neofs/pool"
	"github.com/minio/minio/pkg/auth"
	"github.com/nspcc-dev/neofs-api-go/chain"
	"github.com/nspcc-dev/neofs-api-go/refs"
	"github.com/nspcc-dev/neofs-api-go/service"
	crypto "github.com/nspcc-dev/neofs-crypto"
)

type (
	// neofsObjects implements gateway for MinIO and S3
	// compatible object storage server.
	neofsObject struct {
		minio.GatewayUnsupported // placeholder for unimplemented functions

		cli   pool.Client
		key   *ecdsa.PrivateKey
		owner refs.OwnerID
		token *service.Token

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
func NewLayer(cli pool.Client, cred auth.Credentials) (minio.ObjectLayer, error) {
	// check if wif is correct
	key, err := crypto.WIFDecode(cred.SecretKey)
	if err != nil {
		return nil, errors.New("can't decode secret key, it must be WIF")
	}
	// check if wif corresponds wallet address
	if cred.AccessKey != chain.KeysToAddress(&key.PublicKey) {
		return nil, errors.New("wif and wallet are not corresponded")
	}
	// format public key into owner
	owner, err := refs.NewOwnerID(&key.PublicKey)
	if err != nil {
		return nil, errors.New("can't create owner id from key")
	}

	// setup gRPC connection
	// todo: think about getting timeout parameters from cli args
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	token, err := generateToken(ctx, tokenParams{
		cli:   cli,
		key:   key,
		until: math.MaxInt64,
	})
	if err != nil {
		return nil, errors.New("can't establish neofs session with remote host")
	}

	return &neofsObject{
		cli:   cli,
		key:   key,
		owner: owner,
		token: token,
	}, nil
}
