package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/handler"
	"github.com/nspcc-dev/neofs-s3-gw/api/resolver"
	"github.com/nspcc-dev/neofs-s3-gw/authmate"
	"github.com/nspcc-dev/neofs-s3-gw/internal/neofs"
	"github.com/nspcc-dev/neofs-s3-gw/internal/version"
	"github.com/nspcc-dev/neofs-s3-gw/internal/wallet"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"github.com/spf13/viper"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	poolDialTimeout        = 5 * time.Second
	poolHealthcheckTimeout = 5 * time.Second
	poolRebalanceInterval  = 30 * time.Second
	poolStreamTimeout      = 10 * time.Second

	// a month.
	defaultLifetime          = 30 * 24 * time.Hour
	defaultPresignedLifetime = 12 * time.Hour
)

type PoolConfig struct {
	Key                *ecdsa.PrivateKey
	Address            string
	DialTimeout        time.Duration
	HealthcheckTimeout time.Duration
	StreamTimeout      time.Duration
	RebalanceInterval  time.Duration
}

var (
	walletPathFlag           string
	accountAddressFlag       string
	peerAddressFlag          string
	rpcAddressFlag           string
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
	slicerEnabledFlag        bool
	applyFlag                bool

	// pool timeouts flag.
	poolDialTimeoutFlag        time.Duration
	poolHealthcheckTimeoutFlag time.Duration
	poolRebalanceIntervalFlag  time.Duration
	poolStreamTimeoutFlag      time.Duration
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
		panic(fmt.Errorf("create logger: %w", err))
	}

	return ctx, log
}

func main() {
	app := &cli.App{
		Name:     "NeoFS S3 Authmate",
		Usage:    "Helps manage delegated access via gates to data stored in NeoFS network",
		Version:  version.Version,
		Flags:    appFlags(),
		Commands: appCommands(),
	}
	cli.VersionPrinter = func(c *cli.Context) {
		fmt.Printf("%s\nVersion: %s\nGoVersion: %s\n", c.App.Name, c.App.Version, runtime.Version())
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
		resetBucketEACL(),
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
				Usage:       "rules for bearer token (filepath or a plain json string are allowed)",
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
			&cli.DurationFlag{
				Name:        "pool-dial-timeout",
				Usage:       `Timeout for connection to the node in pool to be established`,
				Required:    false,
				Destination: &poolDialTimeoutFlag,
				Value:       poolDialTimeout,
			},
			&cli.DurationFlag{
				Name:        "pool-healthcheck-timeout",
				Usage:       `Timeout for request to node to decide if it is alive`,
				Required:    false,
				Destination: &poolHealthcheckTimeoutFlag,
				Value:       poolHealthcheckTimeout,
			},
			&cli.DurationFlag{
				Name:        "pool-rebalance-interval",
				Usage:       `Interval for updating nodes health status`,
				Required:    false,
				Destination: &poolRebalanceIntervalFlag,
				Value:       poolRebalanceInterval,
			},
			&cli.DurationFlag{
				Name:        "pool-stream-timeout",
				Usage:       `Timeout for individual operation in streaming RPC`,
				Required:    false,
				Destination: &poolStreamTimeoutFlag,
				Value:       poolStreamTimeout,
			},
			&cli.BoolFlag{
				Name:        "internal-slicer",
				Usage:       "Enable slicer for object uploading",
				Destination: &slicerEnabledFlag,
			},
		},
		Action: func(_ *cli.Context) error {
			ctx, log := prepare()

			password := wallet.GetPassword(viper.GetViper(), envWalletPassphrase)
			key, err := wallet.GetKeyFromPath(walletPathFlag, accountAddressFlag, password)
			if err != nil {
				return cli.Exit(fmt.Sprintf("failed to load neofs private key: %s", err), 1)
			}

			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			poolCfg := PoolConfig{
				Key:                &key.PrivateKey,
				Address:            peerAddressFlag,
				DialTimeout:        poolDialTimeoutFlag,
				HealthcheckTimeout: poolHealthcheckTimeoutFlag,
				StreamTimeout:      poolStreamTimeoutFlag,
				RebalanceInterval:  poolRebalanceIntervalFlag,
			}

			// authmate doesn't require anonKey for work, but let's create random one.
			anonKey, err := keys.NewPrivateKey()
			if err != nil {
				log.Fatal("issueSecret: couldn't generate random key", zap.Error(err))
			}
			anonSigner := user.NewAutoIDSignerRFC6979(anonKey.PrivateKey)

			neoFS, err := createNeoFS(ctx, log, poolCfg, anonSigner, slicerEnabledFlag)
			if err != nil {
				return cli.Exit(fmt.Sprintf("failed to create NeoFS component: %s", err), 2)
			}

			agent := authmate.New(log, neoFS)

			var containerID cid.ID
			if len(containerIDFlag) > 0 {
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

	var (
		data = []byte(val)
		err  error
	)

	if !json.Valid(data) {
		if data, err = os.ReadFile(val); err != nil {
			return nil, fmt.Errorf("coudln't read json file or provided json is invalid")
		}
	}

	var policies authmate.ContainerPolicies
	if err = json.Unmarshal(data, &policies); err != nil {
		return nil, fmt.Errorf("unmarshal policies: %w", err)
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

	return nil, fmt.Errorf("coudln't read json file or provided json is invalid")
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
			&cli.DurationFlag{
				Name:        "pool-dial-timeout",
				Usage:       `Timeout for connection to the node in pool to be established`,
				Required:    false,
				Destination: &poolDialTimeoutFlag,
				Value:       poolDialTimeout,
			},
			&cli.DurationFlag{
				Name:        "pool-healthcheck-timeout",
				Usage:       `Timeout for request to node to decide if it is alive`,
				Required:    false,
				Destination: &poolHealthcheckTimeoutFlag,
				Value:       poolHealthcheckTimeout,
			},
			&cli.DurationFlag{
				Name:        "pool-rebalance-interval",
				Usage:       `Interval for updating nodes health status`,
				Required:    false,
				Destination: &poolRebalanceIntervalFlag,
				Value:       poolRebalanceInterval,
			},
			&cli.DurationFlag{
				Name:        "pool-stream-timeout",
				Usage:       `Timeout for individual operation in streaming RPC`,
				Required:    false,
				Destination: &poolStreamTimeoutFlag,
				Value:       poolStreamTimeout,
			},
		},
		Action: func(_ *cli.Context) error {
			ctx, log := prepare()

			password := wallet.GetPassword(viper.GetViper(), envWalletPassphrase)
			key, err := wallet.GetKeyFromPath(walletPathFlag, accountAddressFlag, password)
			if err != nil {
				return cli.Exit(fmt.Sprintf("failed to load neofs private key: %s", err), 1)
			}

			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			poolCfg := PoolConfig{
				Key:                &key.PrivateKey,
				Address:            peerAddressFlag,
				DialTimeout:        poolDialTimeoutFlag,
				HealthcheckTimeout: poolHealthcheckTimeoutFlag,
				StreamTimeout:      poolStreamTimeoutFlag,
				RebalanceInterval:  poolRebalanceIntervalFlag,
			}

			// authmate doesn't require anonKey for work, but let's create random one.
			anonKey, err := keys.NewPrivateKey()
			if err != nil {
				log.Fatal("obtainSecret: couldn't generate random key", zap.Error(err))
			}
			anonSigner := user.NewAutoIDSignerRFC6979(anonKey.PrivateKey)

			neoFS, err := createNeoFS(ctx, log, poolCfg, anonSigner, slicerEnabledFlag)
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

			or, err := agent.ObtainSecret(ctx, obtainSecretOptions)
			if err != nil {
				return cli.Exit(fmt.Sprintf("failed to obtain secret: %s", err), 5)
			}

			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(or)
		},
	}
	return command
}

func createNeoFS(ctx context.Context, log *zap.Logger, cfg PoolConfig, anonSigner user.Signer, isSlicerEnabled bool) (authmate.NeoFS, error) {
	log.Debug("prepare connection pool")

	signer := user.NewAutoIDSignerRFC6979(*cfg.Key)

	var prm pool.InitParameters
	prm.SetSigner(signer)
	prm.SetNodeDialTimeout(cfg.DialTimeout)
	prm.SetHealthcheckTimeout(cfg.HealthcheckTimeout)
	prm.SetNodeStreamTimeout(cfg.StreamTimeout)
	prm.SetClientRebalanceInterval(cfg.RebalanceInterval)
	prm.AddNode(pool.NewNodeParam(1, cfg.Address, 1))

	p, err := pool.NewPool(prm)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}

	if err = p.Dial(ctx); err != nil {
		return nil, fmt.Errorf("dial pool: %w", err)
	}

	ni, err := p.NetworkInfo(ctx, client.PrmNetworkInfo{})
	if err != nil {
		return nil, fmt.Errorf("networkInfo: %w", err)
	}

	neofsCfg := neofs.Config{
		MaxObjectSize:        int64(ni.MaxObjectSize()),
		IsSlicerEnabled:      isSlicerEnabled,
		IsHomomorphicEnabled: !ni.HomomorphicHashingDisabled(),
	}

	neoFS := neofs.NewNeoFS(p, signer, anonSigner, neofsCfg, ni)

	return neofs.NewAuthmateNeoFS(neoFS), nil
}

func resetBucketEACL() *cli.Command {
	command := &cli.Command{
		Name:  "reset-bucket-acl",
		Usage: "Reset bucket ACL to default state",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "access-key-id",
				Usage:       "access key id for s3",
				Required:    true,
				Destination: &accessKeyIDFlag,
			},
			&cli.StringFlag{
				Name:        "gate-wallet",
				Value:       "",
				Usage:       "path to the gate wallet",
				Required:    true,
				Destination: &gateWalletPathFlag,
			},
			&cli.StringFlag{
				Name:        "peer",
				Value:       "",
				Usage:       "address of neofs peer to connect to. localhost:8080 (without schema)",
				Required:    true,
				Destination: &peerAddressFlag,
			},
			&cli.StringFlag{
				Name:        "rpc-endpoint",
				Value:       "",
				Usage:       "address of neofs RPC endpoint to connect to. https://localhost:30333 (with schema)",
				Required:    true,
				Destination: &rpcAddressFlag,
			},
			&cli.StringFlag{
				Name:        "container-name",
				Usage:       "s3 container name to update eacl",
				Required:    true,
				Destination: &containerIDFlag,
			},
			&cli.BoolFlag{
				Name:        "apply",
				Usage:       "apply EACL changes to container",
				Required:    false,
				Destination: &applyFlag,
			},
		},
		Action: func(_ *cli.Context) error {
			ctx, log := prepare()

			v := viper.New()
			v.AutomaticEnv()
			v.SetConfigType("env")
			v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

			password := wallet.GetPassword(v, envWalletGatePassphrase)
			if password == nil {
				var empty string
				password = &empty
			}
			gateCreds, err := wallet.GetKeyFromPath(gateWalletPathFlag, gateAccountAddressFlag, password)
			if err != nil {
				return cli.Exit(fmt.Sprintf("failed to get gate's private key: %s", err), 4)
			}

			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			poolCfg := PoolConfig{
				Key:     &gateCreds.PrivateKey,
				Address: peerAddressFlag,
			}

			anonKey, err := keys.NewPrivateKey()
			if err != nil {
				log.Fatal("obtainSecret: couldn't generate random key", zap.Error(err))
			}
			anonSigner := user.NewAutoIDSignerRFC6979(anonKey.PrivateKey)

			neoFS, err := createNeoFS(ctx, log, poolCfg, anonSigner, slicerEnabledFlag)
			if err != nil {
				return cli.Exit(fmt.Sprintf("failed to create NeoFS component: %s", err), 1)
			}

			secretAddress := strings.Replace(accessKeyIDFlag, "0", "/", 1)

			obtainSecretOptions := &authmate.ObtainSecretOptions{
				SecretAddress:  secretAddress,
				GatePrivateKey: gateCreds,
			}

			agent := authmate.New(log, neoFS)
			or, err := agent.ObtainSecret(ctx, obtainSecretOptions)
			if err != nil {
				return cli.Exit(fmt.Sprintf("failed to obtain secret: %s", err), 5)
			}

			containerResolver, err := resolver.NewResolver(ctx, []string{rpcAddressFlag})
			if err != nil {
				return cli.Exit(fmt.Sprintf("create resolver: %s", err), 5)
			}

			containerID, err := containerResolver.ResolveCID(ctx, containerIDFlag)
			if err != nil {
				return cli.Exit(fmt.Sprintf("resolve container: %s", err), 5)
			}

			if _, err = fmt.Fprintln(os.Stdout, "Resolved CID:", containerID); err != nil {
				return cli.Exit(fmt.Sprintf("write resolved CID: %s", err), 5)
			}

			var (
				newEACLTable eacl.Table
				targetOwner  eacl.Target
				records      []eacl.Record
			)

			newEACLTable.SetCID(containerID)
			targetOwner.SetAccounts([]user.ID{or.BearerToken.Issuer()})

			for op := eacl.OperationGet; op <= eacl.OperationRangeHash; op++ {
				records = append(records,
					eacl.ConstructRecord(eacl.ActionAllow, op, []eacl.Target{targetOwner}),
				)
			}

			for op := eacl.OperationGet; op <= eacl.OperationRangeHash; op++ {
				record := eacl.ConstructRecord(eacl.ActionDeny, op,
					[]eacl.Target{eacl.NewTargetByRole(eacl.RoleOthers)},
				)

				records = append(records, record)
			}

			oldEacl, err := neoFS.ContainerEACL(ctx, containerID)
			if err != nil {
				return cli.Exit(fmt.Sprintf("failed to obtain old neofs EACL: %s", err), 1)
			}

			if handler.IsBucketOwnerForced(oldEacl) {
				records = append(records, *handler.BucketOwnerEnforcedRecord())
			}

			if handler.IsBucketOwnerPreferred(oldEacl) {
				records = append(records, *handler.BucketOwnerPreferredRecord())
			}

			if handler.IsBucketOwnerPreferredAndRestricted(oldEacl) {
				records = append(records, *handler.BucketOwnerPreferredAndRestrictedRecord())
			}

			newEACLTable.SetRecords(records)

			if applyFlag {
				var tcancel context.CancelFunc
				ctx, tcancel = context.WithTimeout(ctx, timeoutFlag)
				defer tcancel()

				if err = neoFS.SetContainerEACL(ctx, newEACLTable, or.SessionTokenForSetEACL); err != nil {
					return cli.Exit(fmt.Sprintf("failed to setup eacl: %s", err), 1)
				}
			} else {
				_, _ = fmt.Fprintln(os.Stdout, "New EACL table:")

				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				if err = enc.Encode(newEACLTable.Records()); err != nil {
					return cli.Exit(fmt.Sprintf("failed to encode new neofs EACL records: %s", err), 1)
				}

				_, _ = fmt.Fprintln(os.Stdout, "\nuse --apply flag to apply EACL changes")
			}

			return nil
		},
	}

	return command
}
