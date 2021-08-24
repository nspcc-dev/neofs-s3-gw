package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-api-go/pkg/container"
	"github.com/nspcc-dev/neofs-node/pkg/policy"
	"github.com/nspcc-dev/neofs-s3-gw/internal/wallet"
	"github.com/nspcc-dev/neofs-sdk-go/pkg/pool"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestTest(t *testing.T) {
	ctx := context.Background()

	workDir, err := os.Getwd()
	require.NoError(t, err)

	pwd := "one"
	key, err := wallet.GetKeyFromPath("../../aio/morph/node-wallet.json", "", &pwd)
	require.NoError(t, err)

	tag := "nspcc/aio-test:0.1.0"
	req := testcontainers.ContainerRequest{
		FromDockerfile: testcontainers.FromDockerfile{
			Context:    "../../aio",
			Dockerfile: "Dockerfile",
			BuildArgs: map[string]*string{
				"-t": &tag,
			},
			PrintBuildLog: true,
		},
		Entrypoint: nil,
		Env: map[string]string{
			"ACC": "/config/morph_chain.gz",
		},
		BindMounts: map[string]string{
			workDir + "/../../aio/sn/wallet.key":              "/config/wallet-node.key",
			workDir + "/../../aio/sn/config.yaml":             "/config/config-node.yaml",
			workDir + "/../../aio/ir/wallet.key":              "/config/wallet-ir.key",
			workDir + "/../../aio/ir/config.yaml":             "/config/config-ir.yaml",
			workDir + "/../../aio/vendor/locode_db":           "/config/locode.db",
			workDir + "/../../aio/vendor/morph_chain.gz":      "/config/morph_chain.gz",
			workDir + "/../../aio/morph/protocol.privnet.yml": "/config/protocol.privnet.yml",
			workDir + "/../../aio/morph/node-wallet.json":     "/config/node-wallet.json",
		},
		WaitingFor:  wait.NewLogStrategy("neofs-node/main.go:98").WithStartupTimeout(10 * time.Second),
		Name:        "aio",
		Hostname:    "aio",
		NetworkMode: "host",
	}
	aioC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)

	defer func() {
		err = aioC.Terminate(ctx)
		require.NoError(t, err)
	}()

	createContainer(ctx, t, key)
}

func createContainer(ctx context.Context, t *testing.T, key *keys.PrivateKey) {
	pb := new(pool.Builder)
	pb.AddNode("localhost:8080", 1)

	opts := &pool.BuilderOptions{
		Key:                   &key.PrivateKey,
		NodeConnectionTimeout: 5 * time.Second,
		NodeRequestTimeout:    5 * time.Second,
	}
	client, err := pb.Build(ctx, opts)
	require.NoError(t, err)

	pp, err := policy.Parse("REP 1")
	require.NoError(t, err)

	cnr := container.New(
		container.WithPolicy(pp),
		container.WithCustomBasicACL(0x0FFFFFFF),
		container.WithAttribute(container.AttributeName, "friendlyName"),
		container.WithAttribute(container.AttributeTimestamp, strconv.FormatInt(time.Now().Unix(), 10)))
	cnr.SetOwnerID(client.OwnerID())

	cid, err := client.PutContainer(ctx, cnr)
	require.NoError(t, err)
	fmt.Println(cid.String())

	err = client.WaitForContainerPresence(ctx, cid, &pool.ContainerPollingParams{
		CreationTimeout: 15 * time.Second,
		PollInterval:    3 * time.Second,
	})
	require.NoError(t, err)

	info, err := client.GetContainer(ctx, cid)
	require.NoError(t, err)
	for _, a := range info.Attributes() {
		fmt.Println(a.Key(), a.Value())
	}
}
