package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/minio/minio/auth"
	"github.com/minio/minio/neofs/pool"
	"github.com/pkg/errors"

	"github.com/minio/minio/misc"

	crypto "github.com/nspcc-dev/neofs-crypto"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

const (
	devNull   = empty(0)
	generated = "generated"

	minimumTTLInMinutes = 5

	defaultTTL = minimumTTLInMinutes * time.Minute

	defaultRebalanceTimer  = 15 * time.Second
	defaultRequestTimeout  = 15 * time.Second
	defaultConnectTimeout  = 30 * time.Second
	defaultShutdownTimeout = 15 * time.Second

	defaultKeepaliveTime    = 10 * time.Second
	defaultKeepaliveTimeout = 10 * time.Second

	defaultMaxClientsCount    = 100
	defaultMaxClientsDeadline = time.Second * 30
)

const ( // settings
	// Logger:
	cfgLoggerLevel              = "logger.level"
	cfgLoggerFormat             = "logger.format"
	cfgLoggerTraceLevel         = "logger.trace_level"
	cfgLoggerNoDisclaimer       = "logger.no_disclaimer"
	cfgLoggerSamplingInitial    = "logger.sampling.initial"
	cfgLoggerSamplingThereafter = "logger.sampling.thereafter"

	// KeepAlive
	cfgKeepaliveTime                = "keepalive.time"
	cfgKeepaliveTimeout             = "keepalive.timeout"
	cfgKeepalivePermitWithoutStream = "keepalive.permit_without_stream"

	// Keys
	cfgNeoFSPrivateKey    = "neofs-ecdsa-key"
	cfgUserAuthPrivateKey = "userauth-rsa-key"

	// HTTPS/TLS
	cfgTLSKeyFile  = "tls.key_file"
	cfgTLSCertFile = "tls.cert_file"

	// Timeouts
	cfgConnectionTTL  = "con_ttl"
	cfgConnectTimeout = "connect_timeout"
	cfgRequestTimeout = "request_timeout"
	cfgRebalanceTimer = "rebalance_timer"

	// MaxClients
	cfgMaxClientsCount    = "max_clients_count"
	cfgMaxClientsDeadline = "max_clients_deadline"

	// gRPC
	cfgGRPCVerbose = "verbose"

	// Metrics / Profiler / Web
	cfgEnableMetrics  = "metrics"
	cfgEnableProfiler = "pprof"
	cfgListenAddress  = "listen_address"

	// Application
	cfgApplicationName      = "app.name"
	cfgApplicationVersion   = "app.version"
	cfgApplicationBuildTime = "app.build_time"
)

type empty int

func (empty) Read([]byte) (int, error) { return 0, io.EOF }

func fetchAuthCenter(l *zap.Logger, v *viper.Viper) (*auth.Center, error) {
	var (
		err                error
		neofsPrivateKey    *ecdsa.PrivateKey
		userAuthPrivateKey *rsa.PrivateKey
	)
	switch nfspk := v.GetString(cfgNeoFSPrivateKey); nfspk {
	case generated:
		neofsPrivateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, errors.Wrap(err, "could not generate NeoFS private key")
		}
	default:
		neofsPrivateKey, err = crypto.LoadPrivateKey(nfspk)
		if err != nil {
			return nil, errors.Wrap(err, "could not load NeoFS private key")
		}
	}
	uapk := v.GetString(cfgUserAuthPrivateKey)
	userAuthPrivateKey, err = auth.ReadRSAPrivateKeyFromPEMFile(uapk)
	if err != nil {
		return nil, errors.Wrapf(err, "could not load UserAuth private key %q", uapk)
	}
	center, err := auth.NewCenter(l)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create auth center")
	}
	center.SetUserAuthKeys(userAuthPrivateKey)
	if err = center.SetNeoFSKeys(neofsPrivateKey); err != nil {
		return nil, err
	}
	return center, nil
}

func fetchPeers(l *zap.Logger, v *viper.Viper) []pool.Peer {
	peers := make([]pool.Peer, 0)

	for i := 0; ; i++ {

		key := "peers." + strconv.Itoa(i) + "."
		address := v.GetString(key + "address")
		weight := v.GetFloat64(key + "weight")

		if address == "" {
			l.Warn("skip, empty address")
			break
		}

		peers = append(peers, pool.Peer{
			Address: address,
			Weight:  weight,
		})
	}

	return peers
}

func newSettings() *viper.Viper {
	v := viper.New()

	v.AutomaticEnv()
	v.SetEnvPrefix("S3")
	v.SetConfigType("yaml")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// flags setup:
	flags := pflag.NewFlagSet("commandline", pflag.ExitOnError)
	flags.SortFlags = false

	flags.Bool(cfgEnableProfiler, false, "enable pprof")
	flags.Bool(cfgEnableMetrics, false, "enable prometheus metrics")

	help := flags.BoolP("help", "h", false, "show help")
	version := flags.BoolP("version", "v", false, "show version")

	flags.String(cfgNeoFSPrivateKey, generated, fmt.Sprintf(`set value to hex string, WIF string, or path to NeoFS private key file (use "%s" to generate key)`, generated))
	flags.String(cfgUserAuthPrivateKey, "", "set path to file with private key to use in auth scheme")

	flags.Bool(cfgGRPCVerbose, false, "set debug mode of gRPC connections")
	flags.Duration(cfgRequestTimeout, defaultRequestTimeout, "set gRPC request timeout")
	flags.Duration(cfgConnectTimeout, defaultConnectTimeout, "set gRPC connect timeout")
	flags.Duration(cfgRebalanceTimer, defaultRebalanceTimer, "set gRPC connection rebalance timer")

	flags.Int(cfgMaxClientsCount, defaultMaxClientsCount, "set max-clients count")
	flags.Duration(cfgMaxClientsDeadline, defaultMaxClientsDeadline, "set max-clients deadline")

	ttl := flags.DurationP(cfgConnectionTTL, "t", defaultTTL, "set gRPC connection time to live")

	flags.String(cfgListenAddress, "0.0.0.0:8080", "set address to listen")
	peers := flags.StringArrayP("peers", "p", nil, "set NeoFS nodes")

	// set prefers:
	v.Set(cfgApplicationName, misc.ApplicationName)
	v.Set(cfgApplicationVersion, misc.Version)
	v.Set(cfgApplicationBuildTime, misc.Build)

	// set defaults:

	// logger:
	v.SetDefault(cfgLoggerLevel, "debug")
	v.SetDefault(cfgLoggerFormat, "console")
	v.SetDefault(cfgLoggerTraceLevel, "panic")
	v.SetDefault(cfgLoggerNoDisclaimer, true)
	v.SetDefault(cfgLoggerSamplingInitial, 1000)
	v.SetDefault(cfgLoggerSamplingThereafter, 1000)

	// keepalive:
	// If set below 10s, a minimum value of 10s will be used instead.
	v.SetDefault(cfgKeepaliveTime, defaultKeepaliveTime)
	v.SetDefault(cfgKeepaliveTimeout, defaultKeepaliveTimeout)
	v.SetDefault(cfgKeepalivePermitWithoutStream, true)

	if err := v.BindPFlags(flags); err != nil {
		panic(err)
	}

	if err := v.ReadConfig(devNull); err != nil {
		panic(err)
	}

	if err := flags.Parse(os.Args); err != nil {
		panic(err)
	}

	switch {
	case help != nil && *help:
		fmt.Printf("NeoFS S3 Gateway %s (%s)\n", misc.Version, misc.Build)
		flags.PrintDefaults()
		os.Exit(0)
	case version != nil && *version:
		fmt.Printf("NeoFS S3 Gateway %s (%s)\n", misc.Version, misc.Build)
		os.Exit(0)
	case ttl != nil && ttl.Minutes() < minimumTTLInMinutes:
		fmt.Printf("connection ttl should not be less than %s", defaultTTL)
	}

	if peers != nil && len(*peers) > 0 {
		for i := range *peers {
			v.SetDefault("peers."+strconv.Itoa(i)+".address", (*peers)[i])
			v.SetDefault("peers."+strconv.Itoa(i)+".weight", 1)
		}
	}

	return v
}
