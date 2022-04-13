package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api/resolver"
	"github.com/nspcc-dev/neofs-s3-gw/internal/version"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

const (
	defaultRebalanceInterval  = 15 * time.Second
	defaultHealthcheckTimeout = 15 * time.Second
	defaultConnectTimeout     = 30 * time.Second
	defaultShutdownTimeout    = 15 * time.Second

	defaultMaxClientsCount    = 100
	defaultMaxClientsDeadline = time.Second * 30
)

const ( // Settings.
	// Logger.
	cfgLoggerLevel = "logger.level"

	// Wallet.
	cfgWallet           = "wallet"
	cfgAddress          = "address"
	cfgWalletPassphrase = "wallet.passphrase"

	// HTTPS/TLS.
	cfgTLSKeyFile  = "tls.key_file"
	cfgTLSCertFile = "tls.cert_file"

	// Timeouts.
	cfgConnectTimeout     = "connect_timeout"
	cfgHealthcheckTimeout = "healthcheck_timeout"
	cfgRebalanceInterval  = "rebalance_interval"

	// Caching.
	cfgObjectsCacheLifetime     = "cache.objects.lifetime"
	cfgObjectsCacheSize         = "cache.objects.size"
	cfgListObjectsCacheLifetime = "cache.list.lifetime"
	cfgListObjectsCacheSize     = "cache.list.size"
	cfgBucketsCacheLifetime     = "cache.buckets.lifetime"
	cfgBucketsCacheSize         = "cache.buckets.size"
	cfgNamesCacheLifetime       = "cache.names.lifetime"
	cfgNamesCacheSize           = "cache.names.size"
	cfgSystemLifetimeSize       = "cache.system.lifetime"
	cfgSystemCacheSize          = "cache.system.size"
	cfgAccessBoxCacheLifetime   = "cache.accessbox.lifetime"
	cfgAccessBoxCacheSize       = "cache.accessbox.size"

	// NATS.
	cfgEnableNATS             = "nats.enabled"
	cfgNATSEndpoint           = "nats.endpoint"
	cfgNATSTimeout            = "nats.timeout"
	cfgNATSTLSCertFile        = "nats.cert_file"
	cfgNATSAuthPrivateKeyFile = "nats.key_file"
	cfgNATSRootCAFiles        = "nats.root_ca"

	// Policy.
	cfgDefaultPolicy = "default_policy"

	// CORS.
	cfgDefaultMaxAge = "cors.default_max_age"

	// MaxClients.
	cfgMaxClientsCount    = "max_clients_count"
	cfgMaxClientsDeadline = "max_clients_deadline"

	// Metrics / Profiler / Web.
	cfgEnableMetrics  = "metrics"
	cfgEnableProfiler = "pprof"
	cfgListenAddress  = "listen_address"
	cfgListenDomains  = "listen_domains"

	// Peers.
	cfgPeers = "peers"

	// NeoGo.
	cfgRPCEndpoint = "rpc_endpoint"

	// Resolving.
	cfgResolveOrder = "resolve_order"

	// Application.
	cfgApplicationBuildTime = "app.build_time"

	// Command line args.
	cmdHelp    = "help"
	cmdVersion = "version"
	cmdConfig  = "config"

	// envPrefix is an environment variables prefix used for configuration.
	envPrefix = "S3_GW"
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

func fetchDomains(v *viper.Viper) []string {
	cnt := v.GetInt(cfgListenDomains + ".count")
	res := make([]string, 0, cnt)
	for i := 0; ; i++ {
		domain := v.GetString(cfgListenDomains + "." + strconv.Itoa(i))
		if domain == "" {
			break
		}

		res = append(res, domain)
	}

	return res
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

	flags.Bool(cfgEnableProfiler, false, "enable pprof")
	flags.Bool(cfgEnableMetrics, false, "enable prometheus metrics")

	help := flags.BoolP(cmdHelp, "h", false, "show help")
	versionFlag := flags.BoolP(cmdVersion, "v", false, "show version")

	flags.StringP(cfgWallet, "w", "", `path to the wallet`)
	flags.String(cfgAddress, "", `address of wallet account`)
	config := flags.String(cmdConfig, "", "config path")

	flags.Duration(cfgHealthcheckTimeout, defaultHealthcheckTimeout, "set timeout to check node health during rebalance")
	flags.Duration(cfgConnectTimeout, defaultConnectTimeout, "set timeout to connect to NeoFS nodes")
	flags.Duration(cfgRebalanceInterval, defaultRebalanceInterval, "set rebalance interval")

	flags.Int(cfgMaxClientsCount, defaultMaxClientsCount, "set max-clients count")
	flags.Duration(cfgMaxClientsDeadline, defaultMaxClientsDeadline, "set max-clients deadline")

	flags.String(cfgListenAddress, "0.0.0.0:8080", "set address to listen")
	flags.String(cfgTLSCertFile, "", "TLS certificate file to use")
	flags.String(cfgTLSKeyFile, "", "TLS key file to use")

	peers := flags.StringArrayP(cfgPeers, "p", nil, "set NeoFS nodes")

	flags.StringP(cfgRPCEndpoint, "r", "", "set RPC endpoint")
	resolveMethods := flags.StringSlice(cfgResolveOrder, []string{resolver.DNSResolver}, "set bucket name resolve order")

	domains := flags.StringArrayP(cfgListenDomains, "d", nil, "set domains to be listened")

	// set defaults:

	// logger:
	v.SetDefault(cfgLoggerLevel, "debug")

	if err := v.BindPFlags(flags); err != nil {
		panic(err)
	}

	if err := flags.Parse(os.Args); err != nil {
		panic(err)
	}

	if resolveMethods != nil {
		v.SetDefault(cfgResolveOrder, *resolveMethods)
	}

	if peers != nil && len(*peers) > 0 {
		for i := range *peers {
			v.SetDefault(cfgPeers+"."+strconv.Itoa(i)+".address", (*peers)[i])
			v.SetDefault(cfgPeers+"."+strconv.Itoa(i)+".weight", 1)
		}
	}

	if domains != nil && len(*domains) > 0 {
		for i := range *domains {
			v.SetDefault(cfgListenDomains+"."+strconv.Itoa(i), (*domains)[i])
		}

		v.SetDefault(cfgListenDomains+".count", len(*domains))
	}

	switch {
	case help != nil && *help:
		fmt.Printf("NeoFS S3 gateway %s\n", version.Version)
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
			fmt.Printf("%s_%s = %v\n", envPrefix, strings.ToUpper(k), v.Get(keys[i]))
		}

		fmt.Println()
		fmt.Println("Peers preset:")
		fmt.Println()

		fmt.Printf("%s_%s_[N]_ADDRESS = string\n", envPrefix, strings.ToUpper(cfgPeers))
		fmt.Printf("%s_%s_[N]_WEIGHT = 0..1 (float)\n", envPrefix, strings.ToUpper(cfgPeers))

		os.Exit(0)
	case versionFlag != nil && *versionFlag:
		fmt.Printf("NeoFS S3 gateway %s\n", version.Version)
		os.Exit(0)
	}

	if v.IsSet(cmdConfig) {
		if cfgFile, err := os.Open(*config); err != nil {
			panic(err)
		} else if err := v.ReadConfig(cfgFile); err != nil {
			panic(err)
		}
	}

	return v
}
