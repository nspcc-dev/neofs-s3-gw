package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/authmate"
	"github.com/nspcc-dev/neofs-s3-gw/internal/version"
	"github.com/nspcc-dev/neofs-s3-gw/internal/wallet"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/spf13/viper"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	poolConnectTimeout = 5 * time.Second
	poolRequestTimeout = 5 * time.Second
	// a number of 1-hour epochs in a month.
	defaultLifetime = 720
)

var (
	walletPathFlag         string
	accountAddressFlag     string
	peerAddressFlag        string
	eaclRulesFlag          string
	contextRulesFlag       string
	gateWalletPathFlag     string
	gateAccountAddressFlag string
	accessKeyIDFlag        string
	containerIDFlag        string
	containerFriendlyName  string
	gatesPublicKeysFlag    cli.StringSlice
	logEnabledFlag         bool
	logDebugEnabledFlag    bool
	sessionTokenFlag       bool
	lifetimeFlag           time.Duration
	containerPolicies      string
	awcCliCredFile         string
)

const (
	envWalletPassphrase     = "wallet.passphrase"
	envWalletGatePassphrase = "wallet.gate.passphrase"
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

	viper.AutomaticEnv()
	viper.SetEnvPrefix("AUTHMATE")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AllowEmptyEnv(true)

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
	}
}

func issueSecret() *cli.Command {
	return &cli.Command{
		Name:  "issue-secret",
		Usage: "Issue a secret in NeoFS network",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "wallet",
				Value:       "",
				Usage:       "path to the wallet",
				Required:    true,
				Destination: &walletPathFlag,
			},
			&cli.StringFlag{
				Name:        "address",
				Value:       "",
				Usage:       "address of wallet account",
				Required:    false,
				Destination: &accountAddressFlag,
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
				Usage:       "public 256r1 key of a gate (use flags repeatedly for multiple gates)",
				Required:    true,
				Destination: &gatesPublicKeysFlag,
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
			&cli.DurationFlag{
				Name:        "lifetime",
				Usage:       "Lifetime of tokens (e.g. 1d2h30m, it will be ceil rounded to the nearest amount of epoch)",
				Required:    false,
				Destination: &lifetimeFlag,
				Value:       defaultLifetime,
			},
			&cli.StringFlag{
				Name:        "container-policy",
				Usage:       "mapping AWS storage class to NeoFS storage policy as plain json string or path to json file",
				Required:    false,
				Destination: &containerPolicies,
			},
			&cli.StringFlag{
				Name:        "aws-cli-credentials",
				Usage:       "path to the aws cli credential file",
				Required:    false,
				Destination: &awcCliCredFile,
			},
		},
		Action: func(c *cli.Context) error {
			ctx, log := prepare()

			password := wallet.GetPassword(viper.GetViper(), envWalletPassphrase)
			key, err := wallet.GetKeyFromPath(walletPathFlag, accountAddressFlag, password)
			if err != nil {
				return cli.Exit(fmt.Sprintf("failed to load neofs private key: %s", err), 1)
			}

			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			client, err := createSDKClient(ctx, log, &key.PrivateKey, peerAddressFlag)
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

			var gatesPublicKeys []*keys.PublicKey
			for _, key := range gatesPublicKeysFlag.Value() {
				gpk, err := keys.NewPublicKeyFromString(key)
				if err != nil {
					return cli.Exit(fmt.Sprintf("failed to load gate's public key: %s", err), 4)
				}
				gatesPublicKeys = append(gatesPublicKeys, gpk)
			}

			if lifetimeFlag <= 0 {
				return cli.Exit(fmt.Sprintf("lifetime must be greater 0, current value: %d", lifetimeFlag), 5)
			}

			policies, err := parsePolicies(containerPolicies)
			if err != nil {
				return cli.Exit(fmt.Sprintf("couldn't parse container policy: %s", err.Error()), 6)
			}

			issueSecretOptions := &authmate.IssueSecretOptions{
				ContainerID:           containerID,
				ContainerFriendlyName: containerFriendlyName,
				NeoFSKey:              key,
				GatesPublicKeys:       gatesPublicKeys,
				EACLRules:             getJSONRules(eaclRulesFlag),
				ContextRules:          getJSONRules(contextRulesFlag),
				ContainerPolicies:     policies,
				SessionTkn:            sessionTokenFlag,
				Lifetime:              lifetimeFlag,
				AwsCliCredentialsFile: awcCliCredFile,
			}

			if err = agent.IssueSecret(ctx, os.Stdout, issueSecretOptions); err != nil {
				return cli.Exit(fmt.Sprintf("failed to issue secret: %s", err), 6)
			}

			return nil
		},
	}
}

func parsePolicies(val string) (authmate.ContainerPolicies, error) {
	if val == "" {
		return nil, nil
	}
	data, err := os.ReadFile(val)
	if err != nil {
		data = []byte(val)
	}

	var policies authmate.ContainerPolicies
	if err = json.Unmarshal(data, &policies); err != nil {
		return nil, err
	}

	return policies, nil
}

func getJSONRules(val string) []byte {
	if data, err := os.ReadFile(val); err == nil {
		return data
	}

	return []byte(val)
}

func obtainSecret() *cli.Command {
	command := &cli.Command{
		Name:  "obtain-secret",
		Usage: "Obtain a secret from NeoFS network",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "wallet",
				Value:       "",
				Usage:       "path to the wallet",
				Required:    true,
				Destination: &walletPathFlag,
			},
			&cli.StringFlag{
				Name:        "address",
				Value:       "",
				Usage:       "address of wallet account",
				Required:    false,
				Destination: &accountAddressFlag,
			},
			&cli.StringFlag{
				Name:        "peer",
				Value:       "",
				Usage:       "address of neofs peer to connect to",
				Required:    true,
				Destination: &peerAddressFlag,
			},
			&cli.StringFlag{
				Name:        "gate-wallet",
				Value:       "",
				Usage:       "path to the wallet",
				Required:    true,
				Destination: &gateWalletPathFlag,
			},
			&cli.StringFlag{
				Name:        "gate-address",
				Value:       "",
				Usage:       "address of wallet account",
				Required:    false,
				Destination: &gateAccountAddressFlag,
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

			password := wallet.GetPassword(viper.GetViper(), envWalletPassphrase)
			key, err := wallet.GetKeyFromPath(walletPathFlag, accountAddressFlag, password)
			if err != nil {
				return cli.Exit(fmt.Sprintf("failed to load neofs private key: %s", err), 1)
			}

			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			client, err := createSDKClient(ctx, log, &key.PrivateKey, peerAddressFlag)
			if err != nil {
				return cli.Exit(fmt.Sprintf("failed to create sdk client: %s", err), 2)
			}

			agent := authmate.New(log, client)

			var _ = agent

			password = wallet.GetPassword(viper.GetViper(), envWalletGatePassphrase)
			gateCreds, err := wallet.GetKeyFromPath(gateWalletPathFlag, gateAccountAddressFlag, password)
			if err != nil {
				return cli.Exit(fmt.Sprintf("failed to create owner's private key: %s", err), 4)
			}

			secretAddress := strings.Replace(accessKeyIDFlag, "_", "/", 1)

			obtainSecretOptions := &authmate.ObtainSecretOptions{
				SecretAddress:  secretAddress,
				GatePrivateKey: gateCreds,
			}

			if err = agent.ObtainSecret(ctx, os.Stdout, obtainSecretOptions); err != nil {
				return cli.Exit(fmt.Sprintf("failed to obtain secret: %s", err), 5)
			}

			return nil
		},
	}
	return command
}

func createSDKClient(ctx context.Context, log *zap.Logger, key *ecdsa.PrivateKey, peerAddress string) (pool.Pool, error) {
	log.Debug("prepare connection pool")

	pb := new(pool.Builder)
	pb.AddNode(peerAddress, 1)

	opts := &pool.BuilderOptions{
		Key:                    key,
		NodeConnectionTimeout:  poolConnectTimeout,
		NodeRequestTimeout:     poolRequestTimeout,
		SessionExpirationEpoch: math.MaxUint32,
	}
	return pb.Build(ctx, opts)
}
