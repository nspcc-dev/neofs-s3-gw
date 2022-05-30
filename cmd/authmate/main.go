package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/authmate"
	"github.com/nspcc-dev/neofs-s3-gw/internal/neofs"
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
	// a month.
	defaultLifetime = 30 * 24 * time.Hour
)

var (
	walletPathFlag           string
	accountAddressFlag       string
	peerAddressFlag          string
	eaclRulesFlag            string
	gateWalletPathFlag       string
	gateAccountAddressFlag   string
	accessKeyIDFlag          string
	containerIDFlag          string
	containerFriendlyName    string
	containerPlacementPolicy string
	gatesPublicKeysFlag      cli.StringSlice
	logEnabledFlag           bool
	logDebugEnabledFlag      bool
	sessionTokenFlag         string
	lifetimeFlag             time.Duration
	containerPolicies        string
	awcCliCredFile           string
	timeoutFlag              time.Duration
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
		&cli.DurationFlag{
			Name: "timeout",
			Usage: "timeout of processing of the command, for example 2m " +
				"(note: max time unit is an hour so to set a day you should use 24h)",
			Destination: &timeoutFlag,
			Value:       1 * time.Minute,
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
			},
			&cli.StringFlag{
				Name:        "container-placement-policy",
				Usage:       "placement policy of auth container to put the secret into",
				Required:    false,
				Destination: &containerPlacementPolicy,
				Value:       "REP 2 IN X CBF 3 SELECT 2 FROM * AS X",
			},
			&cli.StringFlag{
				Name:        "session-tokens",
				Usage:       "create session tokens with rules, if the rules are set as 'none', no session tokens will be created",
				Required:    false,
				Destination: &sessionTokenFlag,
				Value:       "",
			},
			&cli.DurationFlag{
				Name: "lifetime",
				Usage: `Lifetime of tokens. For example 50h30m (note: max time unit is an hour so to set a day you should use 24h). 
It will be ceil rounded to the nearest amount of epoch.`,
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

			neoFS, err := createNeoFS(ctx, log, &key.PrivateKey, peerAddressFlag)
			if err != nil {
				return cli.Exit(fmt.Sprintf("failed to create NeoFS component: %s", err), 2)
			}

			agent := authmate.New(log, neoFS)
			var containerID *cid.ID // keep nil value if container flag is not set
			if len(containerIDFlag) > 0 {
				containerID = new(cid.ID)
				if err = containerID.DecodeString(containerIDFlag); err != nil {
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

			bearerRules, err := getJSONRules(eaclRulesFlag)
			if err != nil {
				return cli.Exit(fmt.Sprintf("couldn't parse 'bearer-rules' flag: %s", err.Error()), 7)
			}

			sessionRules, skipSessionRules, err := getSessionRules(sessionTokenFlag)
			if err != nil {
				return cli.Exit(fmt.Sprintf("couldn't parse 'session-tokens' flag: %s", err.Error()), 8)
			}

			issueSecretOptions := &authmate.IssueSecretOptions{
				Container: authmate.ContainerOptions{
					ID:              containerID,
					FriendlyName:    containerFriendlyName,
					PlacementPolicy: containerPlacementPolicy,
				},
				NeoFSKey:              key,
				GatesPublicKeys:       gatesPublicKeys,
				EACLRules:             bearerRules,
				SessionTokenRules:     sessionRules,
				SkipSessionRules:      skipSessionRules,
				ContainerPolicies:     policies,
				Lifetime:              lifetimeFlag,
				AwsCliCredentialsFile: awcCliCredFile,
			}

			var tcancel context.CancelFunc
			ctx, tcancel = context.WithTimeout(ctx, timeoutFlag)
			defer tcancel()

			if err = agent.IssueSecret(ctx, os.Stdout, issueSecretOptions); err != nil {
				return cli.Exit(fmt.Sprintf("failed to issue secret: %s", err), 7)
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
	if _, ok := policies[api.DefaultLocationConstraint]; ok {
		return nil, fmt.Errorf("config overrides %s location constraint", api.DefaultLocationConstraint)
	}

	return policies, nil
}

func getJSONRules(val string) ([]byte, error) {
	if val == "" {
		return nil, nil
	}
	data := []byte(val)
	if json.Valid(data) {
		return data, nil
	}

	if data, err := os.ReadFile(val); err == nil {
		if json.Valid(data) {
			return data, nil
		}
	}

	return nil, fmt.Errorf("coudln't read json file or its content is invalid")
}

// getSessionRules reads json session rules.
// It returns true if rules must be skipped.
func getSessionRules(r string) ([]byte, bool, error) {
	if r == "none" {
		return nil, true, nil
	}

	data, err := getJSONRules(r)
	return data, false, err
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

			neoFS, err := createNeoFS(ctx, log, &key.PrivateKey, peerAddressFlag)
			if err != nil {
				return cli.Exit(fmt.Sprintf("failed to create NeoFS component: %s", err), 2)
			}

			agent := authmate.New(log, neoFS)

			var _ = agent

			password = wallet.GetPassword(viper.GetViper(), envWalletGatePassphrase)
			gateCreds, err := wallet.GetKeyFromPath(gateWalletPathFlag, gateAccountAddressFlag, password)
			if err != nil {
				return cli.Exit(fmt.Sprintf("failed to create owner's private key: %s", err), 4)
			}

			secretAddress := strings.Replace(accessKeyIDFlag, "0", "/", 1)

			obtainSecretOptions := &authmate.ObtainSecretOptions{
				SecretAddress:  secretAddress,
				GatePrivateKey: gateCreds,
			}

			var tcancel context.CancelFunc
			ctx, tcancel = context.WithTimeout(ctx, timeoutFlag)
			defer tcancel()

			if err = agent.ObtainSecret(ctx, os.Stdout, obtainSecretOptions); err != nil {
				return cli.Exit(fmt.Sprintf("failed to obtain secret: %s", err), 5)
			}

			return nil
		},
	}
	return command
}

func createNeoFS(ctx context.Context, log *zap.Logger, key *ecdsa.PrivateKey, peerAddress string) (authmate.NeoFS, error) {
	log.Debug("prepare connection pool")

	var prm pool.InitParameters
	prm.SetKey(key)
	prm.SetNodeDialTimeout(poolConnectTimeout)
	prm.SetHealthcheckTimeout(poolRequestTimeout)
	prm.AddNode(pool.NewNodeParam(1, peerAddress, 1))

	p, err := pool.NewPool(prm)
	if err != nil {
		return nil, err
	}

	if err = p.Dial(ctx); err != nil {
		return nil, err
	}

	return neofs.NewAuthmateNeoFS(p), nil
}
