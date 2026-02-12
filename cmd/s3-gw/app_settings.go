package main

import (
	"fmt"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/internal/version"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/term"
)

const (
	defaultRebalanceInterval  = 60 * time.Second
	defaultHealthcheckTimeout = 15 * time.Second
	defaultConnectTimeout     = 10 * time.Second
	defaultStreamTimeout      = 10 * time.Second
	defaultShutdownTimeout    = 15 * time.Second

	defaultPoolErrorThreshold uint32 = 100

	defaultMaxClientsCount    = 100
	defaultMaxClientsDeadline = time.Second * 30

	defaultMaxObjectDeletePerRequest = 1000
	minWaiterPollInterval            = 50 * time.Millisecond
)

const ( // Settings.
	// Logger.
	cfgLoggerLevel      = "logger.level"
	cfgLoggerEncoding   = "logger.encoding"
	cfgLoggerTimestamp  = "logger.timestamp"
	cfgLoggerSamplingOn = "logger.sampling.enabled"

	// Wallet.
	cfgWalletPath       = "wallet.path"
	cfgWalletAddress    = "wallet.address"
	cfgWalletPassphrase = "wallet.passphrase"
	cmdWallet           = "wallet"
	cmdAddress          = "address"

	// Server.
	cfgServer      = "server"
	cfgTLSEnabled  = "tls.enabled"
	cfgTLSKeyFile  = "tls.key_file"
	cfgTLSCertFile = "tls.cert_file"

	// Pool config.
	cfgConnectTimeout     = "connect_timeout"
	cfgStreamTimeout      = "stream_timeout"
	cfgHealthcheckTimeout = "healthcheck_timeout"
	cfgRebalanceInterval  = "rebalance_interval"
	cfgPoolErrorThreshold = "pool_error_threshold"

	// Caching.
	cfgObjectsCacheLifetime       = "cache.objects.lifetime"
	cfgObjectsCacheSize           = "cache.objects.size"
	cfgListObjectsCacheLifetime   = "cache.list.lifetime"
	cfgListObjectsCacheSize       = "cache.list.size"
	cfgBucketsCacheLifetime       = "cache.buckets.lifetime"
	cfgBucketsCacheSize           = "cache.buckets.size"
	cfgNamesCacheLifetime         = "cache.names.lifetime"
	cfgNamesCacheSize             = "cache.names.size"
	cfgSystemCacheLifetime        = "cache.system.lifetime"
	cfgSystemCacheSize            = "cache.system.size"
	cfgAccessBoxCacheLifetime     = "cache.accessbox.lifetime"
	cfgAccessBoxCacheSize         = "cache.accessbox.size"
	cfgAccessControlCacheLifetime = "cache.accesscontrol.lifetime"
	cfgAccessControlCacheSize     = "cache.accesscontrol.size"

	// NATS.
	cfgEnableNATS             = "nats.enabled"
	cfgNATSEndpoint           = "nats.endpoint"
	cfgNATSTimeout            = "nats.timeout"
	cfgNATSTLSCertFile        = "nats.cert_file"
	cfgNATSAuthPrivateKeyFile = "nats.key_file"
	cfgNATSRootCAFiles        = "nats.root_ca"

	// Policy.
	cfgPolicyDefault               = "placement_policy.default"
	cfgPolicyRegionMapFile         = "placement_policy.region_mapping"
	cfgPolicyLocations             = "placement_policy.locations"
	cfgPolicyLocationsContractName = "placement_policy.contract_name"

	// CORS.
	cfgDefaultMaxAge = "cors.default_max_age"

	// MaxClients.
	cfgMaxClientsCount    = "max_clients_count"
	cfgMaxClientsDeadline = "max_clients_deadline"

	// Metrics / Profiler / Web.
	cfgPrometheusEnabled = "prometheus.enabled"
	cfgPrometheusAddress = "prometheus.address"
	cfgPProfEnabled      = "pprof.enabled"
	cfgPProfAddress      = "pprof.address"

	cfgListenDomains = "listen_domains"

	// Peers.
	cfgPeers = "peers"

	// NeoGo.
	cfgRPCEndpoints = "fschain.endpoints"

	// Application.
	cfgApplicationBuildTime = "app.build_time"

	// Command line args.
	cmdHelp    = "help"
	cmdVersion = "version"
	cmdConfig  = "config"
	cmdPProf   = "pprof"
	cmdMetrics = "metrics"

	cmdListenAddress = "listen_address"

	// cfgContainerMetadataPolicy is an experimental setting with "strict", "optimistic" and unset values.
	cfgContainerMetadataPolicy = "neofs.metadata_policy"

	// Maximum number of objects to be deleted per request limit by this value.
	cfgMaxObjectToDeletePerRequest = "s3.max_object_to_delete_per_request"

	// List of allowed AccessKeyID prefixes.
	cfgAllowedAccessKeyIDPrefixes = "allowed_access_key_id_prefixes"

	// envPrefix is an environment variables prefix used for configuration.
	envPrefix = "S3_GW"

	// Shows if slicer is enabled. If enabled slicer will be used for object put.
	cfgSlicerEnabled = "internal_slicer"

	// Polling interval for container operation waiter (half a block, but not less than 50ms by default).
	cfgContainerOpsPollInterval = "container_ops_poll_interval"
)

var ignore = map[string]struct{}{
	cfgApplicationBuildTime: {},

	cfgPeers: {},

	cmdHelp:    {},
	cmdVersion: {},
}

func fetchPeers(l *zap.Logger, v *viper.Viper) []pool.NodeParam {
	var nodes []pool.NodeParam
	for i := 0; ; i++ {
		key := cfgPeers + "." + strconv.Itoa(i) + "."
		address := v.GetString(key + "address")
		weight := v.GetFloat64(key + "weight")
		priority := v.GetInt(key + "priority")

		if address == "" {
			l.Warn("skip, empty address")
			break
		}
		if weight <= 0 { // unspecified or wrong
			weight = 1
		}
		if priority <= 0 { // unspecified or wrong
			priority = 1
		}

		nodes = append(nodes, pool.NewNodeParam(priority, address, weight))

		l.Info("added connection peer",
			zap.String("address", address),
			zap.Float64("weight", weight))
	}

	return nodes
}

func fetchServers(v *viper.Viper) []ServerInfo {
	var servers []ServerInfo

	for i := 0; ; i++ {
		key := cfgServer + "." + strconv.Itoa(i) + "."

		var serverInfo ServerInfo
		serverInfo.Address = v.GetString(key + "address")
		serverInfo.TLS.Enabled = v.GetBool(key + cfgTLSEnabled)
		serverInfo.TLS.KeyFile = v.GetString(key + cfgTLSKeyFile)
		serverInfo.TLS.CertFile = v.GetString(key + cfgTLSCertFile)

		if serverInfo.Address == "" {
			break
		}

		servers = append(servers, serverInfo)
	}

	return servers
}

func newSettings() *viper.Viper {
	v := viper.New()

	v.AutomaticEnv()
	v.SetEnvPrefix(envPrefix)
	v.SetConfigType("yaml")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AllowEmptyEnv(true)

	// flags setup:
	flags := pflag.NewFlagSet("commandline", pflag.ExitOnError)
	flags.SetOutput(os.Stdout)
	flags.SortFlags = false

	flags.Bool(cmdPProf, false, "enable pprof")
	flags.Bool(cmdMetrics, false, "enable prometheus metrics")

	help := flags.BoolP(cmdHelp, "h", false, "show help")
	versionFlag := flags.BoolP(cmdVersion, "v", false, "show version")

	flags.StringP(cmdWallet, "w", "", `path to the wallet`)
	flags.String(cmdAddress, "", `address of wallet account`)
	flags.String(cmdConfig, "", "config path")

	flags.Duration(cfgHealthcheckTimeout, defaultHealthcheckTimeout, "set timeout to check node health during rebalance")
	flags.Duration(cfgConnectTimeout, defaultConnectTimeout, "set timeout to connect to NeoFS nodes")
	flags.Duration(cfgRebalanceInterval, defaultRebalanceInterval, "set rebalance interval")

	flags.Int(cfgMaxClientsCount, defaultMaxClientsCount, "set max-clients count")
	flags.Duration(cfgMaxClientsDeadline, defaultMaxClientsDeadline, "set max-clients deadline")

	flags.String(cmdListenAddress, "0.0.0.0:8080", "set the main address to listen")
	flags.String(cfgTLSCertFile, "", "TLS certificate file to use")
	flags.String(cfgTLSKeyFile, "", "TLS key file to use")

	peers := flags.StringArrayP(cfgPeers, "p", nil, "set NeoFS nodes")

	flags.StringP(cfgRPCEndpoints, "r", "", "set RPC endpoints")

	domains := flags.StringSliceP(cfgListenDomains, "d", nil, "set domains to be listened")

	// set defaults:

	// logger:
	v.SetDefault(cfgLoggerLevel, "debug")
	v.SetDefault(cfgLoggerEncoding, "console")

	// pool:
	v.SetDefault(cfgPoolErrorThreshold, defaultPoolErrorThreshold)
	v.SetDefault(cfgStreamTimeout, defaultStreamTimeout)

	v.SetDefault(cfgPProfAddress, "localhost:8085")
	v.SetDefault(cfgPrometheusAddress, "localhost:8086")

	// Bind flags
	if err := bindFlags(v, flags); err != nil {
		panic(fmt.Errorf("bind flags: %w", err))
	}

	if err := flags.Parse(os.Args); err != nil {
		panic(err)
	}

	if v.IsSet(cfgServer+".0."+cfgTLSKeyFile) && v.IsSet(cfgServer+".0."+cfgTLSCertFile) {
		v.Set(cfgServer+".0."+cfgTLSEnabled, true)
	}

	if peers != nil && len(*peers) > 0 {
		for i := range *peers {
			v.SetDefault(cfgPeers+"."+strconv.Itoa(i)+".address", (*peers)[i])
			v.SetDefault(cfgPeers+"."+strconv.Itoa(i)+".weight", 1)
			v.SetDefault(cfgPeers+"."+strconv.Itoa(i)+".priority", 1)
		}
	}

	if domains != nil && len(*domains) > 0 {
		v.SetDefault(cfgListenDomains, *domains)
	}

	switch {
	case help != nil && *help:
		fmt.Printf("NeoFS S3 gateway %s\n", version.Version)
		flags.PrintDefaults()

		fmt.Println()
		fmt.Println("Default environments:")
		fmt.Println()
		keys := v.AllKeys()
		slices.Sort(keys)

		for i := range keys {
			if _, ok := ignore[keys[i]]; ok {
				continue
			}

			defaultValue := v.GetString(keys[i])
			if len(defaultValue) == 0 {
				continue
			}

			k := strings.ReplaceAll(keys[i], ".", "_")
			fmt.Printf("%s_%s = %s\n", envPrefix, strings.ToUpper(k), defaultValue)
		}

		fmt.Println()
		fmt.Println("Peers preset:")
		fmt.Println()

		fmt.Printf("%s_%s_[N]_ADDRESS = string\n", envPrefix, strings.ToUpper(cfgPeers))
		fmt.Printf("%s_%s_[N]_WEIGHT = 0..1 (float)\n", envPrefix, strings.ToUpper(cfgPeers))

		os.Exit(0)
	case versionFlag != nil && *versionFlag:
		fmt.Printf("NeoFS S3 Gateway\nVersion: %s\nGoVersion: %s\n", version.Version, runtime.Version())
		os.Exit(0)
	}

	if v.IsSet(cmdConfig) {
		if err := readConfig(v); err != nil {
			panic(err)
		}
	}

	return v
}

func bindFlags(v *viper.Viper, flags *pflag.FlagSet) error {
	if err := v.BindPFlag(cfgPProfEnabled, flags.Lookup(cmdPProf)); err != nil {
		return err
	}
	if err := v.BindPFlag(cfgPrometheusEnabled, flags.Lookup(cmdMetrics)); err != nil {
		return err
	}
	if err := v.BindPFlag(cmdConfig, flags.Lookup(cmdConfig)); err != nil {
		return err
	}
	if err := v.BindPFlag(cfgWalletPath, flags.Lookup(cmdWallet)); err != nil {
		return err
	}
	if err := v.BindPFlag(cfgWalletAddress, flags.Lookup(cmdAddress)); err != nil {
		return err
	}
	if err := v.BindPFlag(cfgHealthcheckTimeout, flags.Lookup(cfgHealthcheckTimeout)); err != nil {
		return err
	}
	if err := v.BindPFlag(cfgConnectTimeout, flags.Lookup(cfgConnectTimeout)); err != nil {
		return err
	}
	if err := v.BindPFlag(cfgRebalanceInterval, flags.Lookup(cfgRebalanceInterval)); err != nil {
		return err
	}
	if err := v.BindPFlag(cfgMaxClientsCount, flags.Lookup(cfgMaxClientsCount)); err != nil {
		return err
	}
	if err := v.BindPFlag(cfgMaxClientsDeadline, flags.Lookup(cfgMaxClientsDeadline)); err != nil {
		return err
	}
	if err := v.BindPFlag(cfgRPCEndpoints, flags.Lookup(cfgRPCEndpoints)); err != nil {
		return err
	}

	if err := v.BindPFlag(cfgServer+".0.address", flags.Lookup(cmdListenAddress)); err != nil {
		return err
	}
	if err := v.BindPFlag(cfgServer+".0."+cfgTLSKeyFile, flags.Lookup(cfgTLSKeyFile)); err != nil {
		return err
	}

	return v.BindPFlag(cfgServer+".0."+cfgTLSCertFile, flags.Lookup(cfgTLSCertFile))
}

func readConfig(v *viper.Viper) error {
	cfgFileName := v.GetString(cmdConfig)
	cfgFile, err := os.Open(cfgFileName)
	if err != nil {
		return err
	}
	if err = v.ReadConfig(cfgFile); err != nil {
		return err
	}

	return cfgFile.Close()
}

// newLogger constructs a Logger instance for the current application.
// Panics on failure.
//
// Logger contains a logger is built from zap's production logging configuration with:
//   - parameterized level (debug by default)
//   - console encoding
//   - ISO8601 time encoding
//
// and atomic log level to dynamically change it.
//
// Logger records a stack trace for all messages at or above fatal level.
//
// See also zapcore.Level, zap.NewProductionConfig, zap.AddStacktrace.
func newLogger(v *viper.Viper) *Logger {
	lvl, err := getLogLevel(v)
	if err != nil {
		panic(err)
	}

	encoding, err := getEncoding(v)
	if err != nil {
		panic(err)
	}

	c := zap.NewProductionConfig()
	c.Level = zap.NewAtomicLevelAt(lvl)
	c.Encoding = encoding
	if !v.GetBool(cfgLoggerSamplingOn) {
		c.Sampling = nil
	}
	if (term.IsTerminal(int(os.Stdout.Fd())) && !v.GetBool(cfgLoggerTimestamp)) || v.GetBool(cfgLoggerTimestamp) {
		c.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	} else {
		c.EncoderConfig.EncodeTime = func(_ time.Time, _ zapcore.PrimitiveArrayEncoder) {}
	}

	l, err := c.Build(
		zap.AddStacktrace(zap.NewAtomicLevelAt(zap.FatalLevel)),
	)
	if err != nil {
		panic(fmt.Sprintf("build zap logger instance: %v", err))
	}

	return &Logger{
		logger: l,
		lvl:    c.Level,
	}
}

func getLogLevel(v *viper.Viper) (zapcore.Level, error) {
	var lvl zapcore.Level
	lvlStr := v.GetString(cfgLoggerLevel)
	err := lvl.UnmarshalText([]byte(lvlStr))
	if err != nil {
		return lvl, fmt.Errorf("incorrect logger level configuration %s (%v), "+
			"value should be one of %v", lvlStr, err, [...]zapcore.Level{
			zapcore.DebugLevel,
			zapcore.InfoLevel,
			zapcore.WarnLevel,
			zapcore.ErrorLevel,
			zapcore.DPanicLevel,
			zapcore.PanicLevel,
			zapcore.FatalLevel,
		})
	}
	return lvl, nil
}

func getEncoding(v *viper.Viper) (string, error) {
	val := v.GetString(cfgLoggerEncoding)

	if val != "console" && val != "json" {
		return "", fmt.Errorf("invalid encoding value: %s", val)
	}

	return val, nil
}
