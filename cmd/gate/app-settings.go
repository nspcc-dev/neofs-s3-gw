package main

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nspcc-dev/neofs-s3-gate/misc"
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
	cfgNeoFSPrivateKey    = "neofs-key"
	cfgGateAuthPrivateKey = "auth-key"

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

	// Peers
	cfgPeers = "peers"

	// Application
	cfgApplicationName      = "app.name"
	cfgApplicationVersion   = "app.version"
	cfgApplicationBuildTime = "app.build_time"

	// command line args
	cmdHelp    = "help"
	cmdVersion = "version"
)

type empty int

var ignore = map[string]struct{}{
	cfgApplicationName:      {},
	cfgApplicationVersion:   {},
	cfgApplicationBuildTime: {},

	cfgPeers: {},

	cmdHelp:    {},
	cmdVersion: {},
}

func (empty) Read([]byte) (int, error) { return 0, io.EOF }

func fetchPeers(l *zap.Logger, v *viper.Viper) map[string]float64 {
	peers := make(map[string]float64, 0)

	for i := 0; ; i++ {

		key := cfgPeers + "." + strconv.Itoa(i) + "."
		address := v.GetString(key + "address")
		weight := v.GetFloat64(key + "weight")

		if address == "" {
			l.Warn("skip, empty address")
			break
		}

		peers[address] = weight
		l.Info("add connection peer",
			zap.String("address", address),
			zap.Float64("weight", weight))
	}

	return peers
}

func newSettings() *viper.Viper {
	v := viper.New()

	v.AutomaticEnv()
	v.SetEnvPrefix(misc.Prefix)
	v.SetConfigType("yaml")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// flags setup:
	flags := pflag.NewFlagSet("commandline", pflag.ExitOnError)
	flags.SortFlags = false

	flags.Bool(cfgEnableProfiler, false, "enable pprof")
	flags.Bool(cfgEnableMetrics, false, "enable prometheus metrics")

	help := flags.BoolP(cmdHelp, "h", false, "show help")
	version := flags.BoolP(cmdVersion, "v", false, "show version")

	flags.String(cfgNeoFSPrivateKey, generated, fmt.Sprintf(`set value to hex string, WIF string, or path to NeoFS private key file (use "%s" to generate key)`, generated))
	flags.String(cfgGateAuthPrivateKey, "", "set path to file with auth (curve25519) private key to use in auth scheme")

	flags.Bool(cfgGRPCVerbose, false, "set debug mode of gRPC connections")
	flags.Duration(cfgRequestTimeout, defaultRequestTimeout, "set gRPC request timeout")
	flags.Duration(cfgConnectTimeout, defaultConnectTimeout, "set gRPC connect timeout")
	flags.Duration(cfgRebalanceTimer, defaultRebalanceTimer, "set gRPC connection rebalance timer")

	flags.Int(cfgMaxClientsCount, defaultMaxClientsCount, "set max-clients count")
	flags.Duration(cfgMaxClientsDeadline, defaultMaxClientsDeadline, "set max-clients deadline")

	ttl := flags.DurationP(cfgConnectionTTL, "t", defaultTTL, "set gRPC connection time to live")

	flags.String(cfgListenAddress, "0.0.0.0:8080", "set address to listen")
	peers := flags.StringArrayP(cfgPeers, "p", nil, "set NeoFS nodes")

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

	if peers != nil && len(*peers) > 0 {
		for i := range *peers {
			v.SetDefault(cfgPeers+"."+strconv.Itoa(i)+".address", (*peers)[i])
			v.SetDefault(cfgPeers+"."+strconv.Itoa(i)+".weight", 1)
		}
	}

	switch {
	case help != nil && *help:
		fmt.Printf("NeoFS S3 Gateway %s (%s)\n", misc.Version, misc.Build)
		flags.PrintDefaults()

		fmt.Println()
		fmt.Println("Default environments:")
		fmt.Println()
		keys := v.AllKeys()
		sort.Strings(keys)

		for i := range keys {
			if _, ok := ignore[keys[i]]; ok {
				continue
			}

			k := strings.Replace(keys[i], ".", "_", -1)
			fmt.Printf("%s_%s = %v\n", misc.Prefix, strings.ToUpper(k), v.Get(keys[i]))
		}

		fmt.Println()
		fmt.Println("Peers preset:")
		fmt.Println()

		fmt.Printf("%s_%s_[N]_ADDRESS = string\n", misc.Prefix, strings.ToUpper(cfgPeers))
		fmt.Printf("%s_%s_[N]_WEIGHT = 0..1 (float)\n", misc.Prefix, strings.ToUpper(cfgPeers))

		os.Exit(0)
	case version != nil && *version:
		fmt.Printf("NeoFS S3 Gateway %s (%s)\n", misc.Version, misc.Build)
		os.Exit(0)
	case ttl != nil && ttl.Minutes() < minimumTTLInMinutes:
		fmt.Printf("connection ttl should not be less than %s", defaultTTL)
	}

	return v
}
