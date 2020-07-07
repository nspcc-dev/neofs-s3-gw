package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/minio/minio/neofs/pool"

	"github.com/minio/minio/misc"

	"github.com/nspcc-dev/neofs-api-go/refs"
	crypto "github.com/nspcc-dev/neofs-crypto"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

type empty int

const (
	devNull   = empty(0)
	generated = "generated"

	minimumTTLInMinutes = 5

	defaultTTL = minimumTTLInMinutes * time.Minute

	defaultRebalanceTimer = 15 * time.Second
	defaultRequestTimeout = 15 * time.Second
	defaultConnectTimeout = 30 * time.Second

	defaultKeepaliveTime    = 10 * time.Second
	defaultKeepaliveTimeout = 10 * time.Second
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

	// Timeouts
	cfgConnectionTTL  = "con_ttl"
	cfgConnectTimeout = "connect_timeout"
	cfgRequestTimeout = "request_timeout"
	cfgRebalanceTimer = "rebalance_timer"

	// gRPC
	cfgGRPCVerbose    = "verbose"
	cfgGRPCPrivateKey = "key"

	// Metrics / Profiler / Web
	cfgEnableMetrics  = "metrics"
	cfgEnableProfiler = "pprof"
	cfgListenAddress  = "listen_address"

	// Application
	cfgApplicationName      = "app.name"
	cfgApplicationVersion   = "app.version"
	cfgApplicationBuildTime = "app.build_time"
)

func (empty) Read([]byte) (int, error) { return 0, io.EOF }

func fetchKey(l *zap.Logger, v *viper.Viper) *ecdsa.PrivateKey {
	switch val := v.GetString("key"); val {
	case generated:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			l.Fatal("could not generate private key", zap.Error(err))
		}

		id, err := refs.NewOwnerID(&key.PublicKey)
		l.Info("generate new key",
			zap.Stringer("key", id),
			zap.Error(err))

		return key

	default:
		key, err := crypto.LoadPrivateKey(val)
		if err != nil {
			l.Fatal("could not load private key",
				zap.String("key", v.GetString("key")),
				zap.Error(err))
		}

		return key
	}
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
	flags.Bool(cfgEnableMetrics, false, "enable prometheus")

	help := flags.BoolP("help", "h", false, "show help")
	version := flags.BoolP("version", "v", false, "show version")

	flags.String(cfgGRPCPrivateKey, generated, `"`+generated+`" to generate key, path to private key file, hex string or wif`)

	flags.Bool(cfgGRPCVerbose, false, "debug gRPC connections")
	flags.Duration(cfgRequestTimeout, defaultRequestTimeout, "gRPC request timeout")
	flags.Duration(cfgConnectTimeout, defaultConnectTimeout, "gRPC connect timeout")
	flags.Duration(cfgRebalanceTimer, defaultRebalanceTimer, "gRPC connection rebalance timer")

	ttl := flags.DurationP(cfgConnectionTTL, "t", defaultTTL, "gRPC connection time to live")

	flags.String(cfgListenAddress, "0.0.0.0:8080", "S3 Gateway listen address")
	peers := flags.StringArrayP("peers", "p", nil, "NeoFS nodes")

	// set prefers:
<<<<<<< Updated upstream
	v.Set("app.name", misc.ApplicationName)
	v.Set("app.version", misc.Version)
	v.Set("app.build_time", misc.Build)
=======
	v.Set(cfgApplicationName, "neofs-gw")
	v.Set(cfgApplicationVersion, misc.Version)
	v.Set(cfgApplicationBuildTime, misc.Build)
>>>>>>> Stashed changes

	// set defaults:

	// logger:
	v.SetDefault(cfgLoggerLevel, "debug")
	v.SetDefault(cfgLoggerFormat, "console")
	v.SetDefault(cfgLoggerTraceLevel, "fatal")
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
