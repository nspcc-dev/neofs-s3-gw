package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	cid "github.com/nspcc-dev/neofs-api-go/pkg/container/id"
	crypto "github.com/nspcc-dev/neofs-crypto"
	"github.com/nspcc-dev/neofs-s3-gw/authmate"
	"github.com/nspcc-dev/neofs-s3-gw/creds/hcs"
	"github.com/nspcc-dev/neofs-s3-gw/internal/version"
	"github.com/nspcc-dev/neofs-sdk-go/pkg/pool"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type gateKey struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

const (
	poolConnectTimeout = 5 * time.Second
	poolRequestTimeout = 5 * time.Second
)

var (
	neoFSKeyPathFlag      string
	peerAddressFlag       string
	eaclRulesFlag         string
	contextRulesFlag      string
	gatePrivateKeyFlag    string
	accessKeyIDFlag       string
	ownerPrivateKeyFlag   string
	containerIDFlag       string
	containerFriendlyName string
	gatesPublicKeysFlag   cli.StringSlice
	gatesKeysCountFlag    int
	logEnabledFlag        bool
	logDebugEnabledFlag   bool
	sessionTokenFlag      bool
)

var zapConfig = zap.Config{
	Development: true,
	Encoding:    "console",
	Level:       zap.NewAtomicLevelAt(zapcore.FatalLevel),
	OutputPaths: []string{"stdout"},
	EncoderConfig: zapcore.EncoderConfig{
		MessageKey:   "message",
		LevelKey:     "level",
		EncodeLevel:  zapcore.CapitalLevelEncoder,
		TimeKey:      "time",
		EncodeTime:   zapcore.ISO8601TimeEncoder,
		CallerKey:    "caller",
		EncodeCaller: zapcore.ShortCallerEncoder,
	},
}

func prepare() (context.Context, *zap.Logger) {
	var (
		err    error
		log    = zap.NewNop()
		ctx, _ = signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	)

	if !logEnabledFlag {
		return ctx, log
	} else if logDebugEnabledFlag {
		zapConfig.Level = zap.NewAtomicLevelAt(zapcore.DebugLevel)
	}

	if log, err = zapConfig.Build(); err != nil {
		panic(err)
	}

	return ctx, log
}

func main() {
	app := &cli.App{
		Name:     "NeoFS gate authentication manager",
		Usage:    "Helps manage delegated access via gates to data stored in NeoFS network",
		Version:  version.Version,
		Flags:    appFlags(),
		Commands: appCommands(),
	}

	if err := app.Run(os.Args); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(100)
	}
}

func appFlags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:        "with-log",
			Usage:       "Enable logger",
			Destination: &logEnabledFlag,
		},
		&cli.BoolFlag{
			Name:        "debug",
			Usage:       "Enable debug logger level",
			Destination: &logDebugEnabledFlag,
		},
	}
}

func appCommands() []*cli.Command {
	return []*cli.Command{
		issueSecret(),
		obtainSecret(),
		generateKeys(),
	}
}

func generateGatesKeys(count int) ([]hcs.Credentials, error) {
	var (
		err error
		res = make([]hcs.Credentials, count)
	)

	for i := 0; i < count; i++ {
		if res[i], err = hcs.Generate(rand.Reader); err != nil {
			return nil, err
		}
	}

	return res, nil
}

func generateKeys() *cli.Command {
	return &cli.Command{
		Name:  "generate-keys",
		Usage: "Generate key pairs for gates",
		Flags: []cli.Flag{
			&cli.IntFlag{
				Name:        "count",
				Usage:       "number of x25519 key pairs to generate",
				Value:       1,
				Destination: &gatesKeysCountFlag,
			},
		},
		Action: func(c *cli.Context) error {
			_, log := prepare()

			log.Info("start generating x25519 keys")

			csl, err := generateGatesKeys(gatesKeysCountFlag)
			if err != nil {
				return cli.Exit(fmt.Sprintf("failed to create key pairs of gates: %s", err), 1)
			}

			log.Info("generated x25519 keys")

			gatesKeys := make([]gateKey, len(csl))
			for i, cs := range csl {
				privateKey, publicKey := cs.PrivateKey().String(), cs.PublicKey().String()
				gatesKeys[i] = gateKey{PrivateKey: privateKey, PublicKey: publicKey}
			}

			keys, err := json.MarshalIndent(gatesKeys, "", "  ")
			if err != nil {
				return cli.Exit(fmt.Sprintf("failed to marshal key pairs of gates: %s", err), 2)
			}

			fmt.Println(string(keys))
			return nil
		},
	}
}

func issueSecret() *cli.Command {
	return &cli.Command{
		Name:  "issue-secret",
		Usage: "Issue a secret in NeoFS network",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "neofs-key",
				Value:       "",
				Usage:       "path to owner's neofs private ecdsa key",
				Required:    true,
				Destination: &neoFSKeyPathFlag,
			},
			&cli.StringFlag{
				Name:        "peer",
				Value:       "",
				Usage:       "address of a neofs peer to connect to",
				Required:    true,
				Destination: &peerAddressFlag,
			},
			&cli.StringFlag{
				Name:        "bearer-rules",
				Usage:       "rules for bearer token as plain json string",
				Required:    false,
				Destination: &eaclRulesFlag,
			},
			&cli.StringFlag{
				Name:        "session-rules",
				Usage:       "rules for session token as plain json string",
				Required:    false,
				Destination: &contextRulesFlag,
			},
			&cli.StringSliceFlag{
				Name:        "gate-public-key",
				Usage:       "public x25519 key of a gate (use flags repeatedly for multiple gates)",
				Required:    true,
				Destination: &gatesPublicKeysFlag,
			},
			&cli.StringFlag{
				Name:        "owner-private-key",
				Usage:       "owner's private x25519 key",
				Required:    false,
				Destination: &ownerPrivateKeyFlag,
			},
			&cli.StringFlag{
				Name:        "container-id",
				Usage:       "auth container id to put the secret into",
				Required:    false,
				Destination: &containerIDFlag,
			},
			&cli.StringFlag{
				Name:        "container-friendly-name",
				Usage:       "friendly name of auth container to put the secret into",
				Required:    false,
				Destination: &containerFriendlyName,
				Value:       "auth-container",
			},
			&cli.BoolFlag{
				Name:        "create-session-token",
				Usage:       "create session token",
				Required:    false,
				Destination: &sessionTokenFlag,
				Value:       false,
			},
		},
		Action: func(c *cli.Context) error {
			ctx, log := prepare()

			key, err := crypto.LoadPrivateKey(neoFSKeyPathFlag)
			if err != nil {
				return cli.Exit(fmt.Sprintf("failed to load neofs private key: %s", err), 1)
			}

			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			client, err := createSDKClient(ctx, log, key, peerAddressFlag)
			if err != nil {
				return cli.Exit(fmt.Sprintf("failed to create sdk client: %s", err), 2)
			}

			agent := authmate.New(log, client)
			var containerID *cid.ID
			if len(containerIDFlag) > 0 {
				containerID = cid.New()
				if err := containerID.Parse(containerIDFlag); err != nil {
					return cli.Exit(fmt.Sprintf("failed to parse auth container id: %s", err), 3)
				}
			}

			var owner hcs.Credentials
			if owner, err = fetchHCSCredentials(ownerPrivateKeyFlag); err != nil {
				return cli.Exit(fmt.Sprintf("failed to create owner's private key: %s", err), 4)
			}

			var gatesPublicKeys []hcs.PublicKey
			for _, key := range gatesPublicKeysFlag.Value() {
				gpk, err := hcs.LoadPublicKey(key)
				if err != nil {
					return cli.Exit(fmt.Sprintf("failed to load gate's public key: %s", err), 5)
				}
				gatesPublicKeys = append(gatesPublicKeys, gpk)
			}

			issueSecretOptions := &authmate.IssueSecretOptions{
				ContainerID:           containerID,
				ContainerFriendlyName: containerFriendlyName,
				NeoFSKey:              key,
				OwnerPrivateKey:       owner.PrivateKey(),
				GatesPublicKeys:       gatesPublicKeys,
				EACLRules:             []byte(eaclRulesFlag),
				ContextRules:          []byte(contextRulesFlag),
				SessionTkn:            sessionTokenFlag,
			}

			if err = agent.IssueSecret(ctx, os.Stdout, issueSecretOptions); err != nil {
				return cli.Exit(fmt.Sprintf("failed to issue secret: %s", err), 6)
			}

			return nil
		},
	}
}

func obtainSecret() *cli.Command {
	command := &cli.Command{
		Name:  "obtain-secret",
		Usage: "Obtain a secret from NeoFS network",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "neofs-key",
				Value:       "",
				Usage:       "path to owner's neofs private ecdsa key",
				Required:    true,
				Destination: &neoFSKeyPathFlag,
			},
			&cli.StringFlag{
				Name:        "peer",
				Value:       "",
				Usage:       "address of neofs peer to connect to",
				Required:    true,
				Destination: &peerAddressFlag,
			},
			&cli.StringFlag{
				Name:        "gate-private-key",
				Usage:       "gate's private x25519 key",
				Required:    true,
				Destination: &gatePrivateKeyFlag,
			},
			&cli.StringFlag{
				Name:        "access-key-id",
				Usage:       "access key id for s3",
				Required:    true,
				Destination: &accessKeyIDFlag,
			},
		},
		Action: func(c *cli.Context) error {
			ctx, log := prepare()

			key, err := crypto.LoadPrivateKey(neoFSKeyPathFlag)
			if err != nil {
				return cli.Exit(fmt.Sprintf("failed to load neofs private key: %s", err), 1)
			}

			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			client, err := createSDKClient(ctx, log, key, peerAddressFlag)
			if err != nil {
				return cli.Exit(fmt.Sprintf("failed to create sdk client: %s", err), 2)
			}

			agent := authmate.New(log, client)

			var _ = agent

			gateCreds, err := hcs.NewCredentials(gatePrivateKeyFlag)
			if err != nil {
				return cli.Exit(fmt.Sprintf("failed to create owner's private key: %s", err), 4)
			}

			secretAddress := strings.Replace(accessKeyIDFlag, "_", "/", 1)

			obtainSecretOptions := &authmate.ObtainSecretOptions{
				SecretAddress:  secretAddress,
				GatePrivateKey: gateCreds.PrivateKey(),
			}

			if err = agent.ObtainSecret(ctx, os.Stdout, obtainSecretOptions); err != nil {
				return cli.Exit(fmt.Sprintf("failed to obtain secret: %s", err), 5)
			}

			return nil
		},
	}
	return command
}

func fetchHCSCredentials(val string) (hcs.Credentials, error) {
	if val == "" {
		return hcs.Generate(rand.Reader)
	}

	return hcs.NewCredentials(val)
}

func createSDKClient(ctx context.Context, log *zap.Logger, key *ecdsa.PrivateKey, peerAddress string) (pool.Pool, error) {
	log.Debug("prepare connection pool")

	pb := new(pool.Builder)
	pb.AddNode(peerAddress, 1)

	opts := &pool.BuilderOptions{
		Key:                   key,
		NodeConnectionTimeout: poolConnectTimeout,
		NodeRequestTimeout:    poolRequestTimeout,
	}
	return pb.Build(ctx, opts)
}
