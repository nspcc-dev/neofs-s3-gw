package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/auth"
	"github.com/nspcc-dev/neofs-s3-gw/api/cache"
	"github.com/nspcc-dev/neofs-s3-gw/api/handler"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/nspcc-dev/neofs-s3-gw/api/notifications"
	"github.com/nspcc-dev/neofs-s3-gw/api/resolver"
	"github.com/nspcc-dev/neofs-s3-gw/internal/neofs"
	"github.com/nspcc-dev/neofs-s3-gw/internal/version"
	"github.com/nspcc-dev/neofs-s3-gw/internal/wallet"
	"github.com/nspcc-dev/neofs-sdk-go/policy"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

type (
	// App is the main application structure.
	App struct {
		ctr auth.Center
		log *zap.Logger
		cfg *viper.Viper
		tls *tlsConfig
		obj layer.Client
		api api.Handler

		maxClients api.MaxClients

		webDone chan struct{}
		wrkDone chan struct{}
	}

	tlsConfig struct {
		KeyFile  string
		CertFile string
	}
)

func newApp(ctx context.Context, l *zap.Logger, v *viper.Viper) *App {
	var (
		key    *keys.PrivateKey
		err    error
		tls    *tlsConfig
		caller api.Handler
		ctr    auth.Center
		obj    layer.Client
		nc     *notifications.Controller

		prmPool pool.InitParameters

		reBalance  = defaultRebalanceInterval
		conTimeout = defaultConnectTimeout
		hckTimeout = defaultHealthcheckTimeout

		maxClientsCount    = defaultMaxClientsCount
		maxClientsDeadline = defaultMaxClientsDeadline
	)

	if v := v.GetDuration(cfgConnectTimeout); v > 0 {
		conTimeout = v
	}

	if v := v.GetDuration(cfgHealthcheckTimeout); v > 0 {
		hckTimeout = v
	}

	if v := v.GetInt(cfgMaxClientsCount); v > 0 {
		maxClientsCount = v
	}

	if v := v.GetDuration(cfgMaxClientsDeadline); v > 0 {
		maxClientsDeadline = v
	}

	if v := v.GetDuration(cfgRebalanceInterval); v > 0 {
		reBalance = v
	}

	password := wallet.GetPassword(v, cfgWalletPassphrase)
	if key, err = wallet.GetKeyFromPath(v.GetString(cfgWallet), v.GetString(cfgAddress), password); err != nil {
		l.Fatal("could not load NeoFS private key", zap.Error(err))
	}

	if v.IsSet(cfgTLSKeyFile) && v.IsSet(cfgTLSCertFile) {
		tls = &tlsConfig{
			KeyFile:  v.GetString(cfgTLSKeyFile),
			CertFile: v.GetString(cfgTLSCertFile),
		}
	}

	l.Info("using credentials",
		zap.String("NeoFS", hex.EncodeToString(key.PublicKey().Bytes())))

	prmPool.SetKey(&key.PrivateKey)
	prmPool.SetNodeDialTimeout(conTimeout)
	prmPool.SetHealthcheckTimeout(hckTimeout)
	prmPool.SetClientRebalanceInterval(reBalance)
	for _, peer := range fetchPeers(l, v) {
		prmPool.AddNode(peer)
	}

	conns, err := pool.NewPool(prmPool)
	if err != nil {
		l.Fatal("failed to create connection pool", zap.Error(err))
	}

	if err = conns.Dial(ctx); err != nil {
		l.Fatal("failed to dial connection pool", zap.Error(err))
	}

	// prepare random key for anonymous requests
	randomKey, err := keys.NewPrivateKey()
	if err != nil {
		l.Fatal("couldn't generate random key", zap.Error(err))
	}

	resolveCfg := &resolver.Config{
		NeoFS:      neofs.NewResolverNeoFS(conns),
		RPCAddress: v.GetString(cfgRPCEndpoint),
	}

	order := v.GetStringSlice(cfgResolveOrder)
	if resolveCfg.RPCAddress == "" {
		order = remove(order, resolver.NNSResolver)
		l.Warn(fmt.Sprintf("resolver '%s' won't be used since '%s' isn't provided", resolver.NNSResolver, cfgRPCEndpoint))
	}

	bucketResolver, err := resolver.NewResolver(order, resolveCfg)
	if err != nil {
		l.Fatal("failed to form resolver", zap.Error(err))
	}

	layerCfg := &layer.Config{
		Caches: getCacheOptions(v, l),
		AnonKey: layer.AnonymousKey{
			Key: randomKey,
		},
		Resolver: bucketResolver,
	}

	// prepare object layer
	obj = layer.NewLayer(l, neofs.NewNeoFS(conns), layerCfg)

	if v.GetBool(cfgEnableNATS) {
		nopts := getNotificationsOptions(v, l)
		nc, err = notifications.NewController(nopts, l)
		if err != nil {
			l.Fatal("failed to enable notifications", zap.Error(err))
		}

		if err = obj.Initialize(ctx, nc); err != nil {
			l.Fatal("couldn't initialize layer", zap.Error(err))
		}
	}

	// prepare auth center
	ctr = auth.New(neofs.NewAuthmateNeoFS(conns), key, getAccessBoxCacheConfig(v, l))
	handlerOptions := getHandlerOptions(v, l)

	if caller, err = handler.New(l, obj, nc, handlerOptions); err != nil {
		l.Fatal("could not initialize API handler", zap.Error(err))
	}

	return &App{
		ctr: ctr,
		log: l,
		cfg: v,
		obj: obj,
		tls: tls,
		api: caller,

		webDone: make(chan struct{}, 1),
		wrkDone: make(chan struct{}, 1),

		maxClients: api.NewMaxClientsMiddleware(maxClientsCount, maxClientsDeadline),
	}
}

func remove(list []string, element string) []string {
	for i, item := range list {
		if item == element {
			return append(list[:i], list[i+1:]...)
		}
	}
	return list
}

// Wait waits for an application to finish.
//
// Pre-logs a message about the launch of the application mentioning its
// version (version.Version) and its name (neofs-s3-gw). At the end, it writes
// about the stop to the log.
func (a *App) Wait() {
	a.log.Info("application started",
		zap.String("name", "neofs-s3-gw"),
		zap.String("version", version.Version),
	)

	<-a.webDone // wait for web-server to be stopped

	a.log.Info("application finished")
}

// Server runs HTTP server to handle S3 API requests.
func (a *App) Server(ctx context.Context) {
	var (
		err  error
		lis  net.Listener
		lic  net.ListenConfig
		srv  = new(http.Server)
		addr = a.cfg.GetString(cfgListenAddress)
	)

	if lis, err = lic.Listen(ctx, "tcp", addr); err != nil {
		a.log.Fatal("could not prepare listener",
			zap.Error(err))
	}

	router := newS3Router()

	// Attach app-specific routes:
	//	attachHealthy(router, a.cli)
	attachMetrics(router, a.cfg, a.log)
	attachProfiler(router, a.cfg, a.log)

	// Attach S3 API:
	domains := fetchDomains(a.cfg)
	a.log.Info("fetch domains, prepare to use API",
		zap.Strings("domains", domains))
	api.Attach(router, domains, a.maxClients, a.api, a.ctr, a.log)

	// Use mux.Router as http.Handler
	srv.Handler = router
	srv.ErrorLog = zap.NewStdLog(a.log)

	go func() {
		a.log.Info("starting server",
			zap.String("bind", addr))

		switch a.tls {
		case nil:
			if err = srv.Serve(lis); err != nil && err != http.ErrServerClosed {
				a.log.Fatal("listen and serve",
					zap.Error(err))
			}
		default:
			a.log.Info("using certificate",
				zap.String("key", a.tls.KeyFile),
				zap.String("cert", a.tls.CertFile))

			if err = srv.ServeTLS(lis, a.tls.CertFile, a.tls.KeyFile); err != nil && err != http.ErrServerClosed {
				a.log.Fatal("listen and serve",
					zap.Error(err))
			}
		}
	}()

	<-ctx.Done()

	ctx, cancel := context.WithTimeout(context.Background(), defaultShutdownTimeout)
	defer cancel()

	a.log.Info("stopping server",
		zap.Error(srv.Shutdown(ctx)))

	close(a.webDone)
}

func getNotificationsOptions(v *viper.Viper, l *zap.Logger) *notifications.Options {
	cfg := notifications.Options{}
	cfg.URL = v.GetString(cfgNATSEndpoint)
	cfg.Timeout = v.GetDuration(cfgNATSTimeout)
	if cfg.Timeout <= 0 {
		l.Error("invalid lifetime, using default value (in seconds)",
			zap.String("parameter", cfgNATSTimeout),
			zap.Duration("value in config", cfg.Timeout),
			zap.Duration("default", notifications.DefaultTimeout))
		cfg.Timeout = notifications.DefaultTimeout
	}
	cfg.TLSCertFilepath = v.GetString(cfgNATSTLSCertFile)
	cfg.TLSAuthPrivateKeyFilePath = v.GetString(cfgNATSAuthPrivateKeyFile)
	cfg.RootCAFiles = v.GetStringSlice(cfgNATSRootCAFiles)

	return &cfg
}

func getCacheOptions(v *viper.Viper, l *zap.Logger) *layer.CachesConfig {
	cacheCfg := layer.DefaultCachesConfigs()

	cacheCfg.Objects.Lifetime = getLifetime(v, l, cfgObjectsCacheLifetime, cacheCfg.Objects.Lifetime)
	cacheCfg.Objects.Size = getSize(v, l, cfgObjectsCacheSize, cacheCfg.Objects.Size)

	cacheCfg.ObjectsList.Lifetime = getLifetime(v, l, cfgListObjectsCacheLifetime, cacheCfg.ObjectsList.Lifetime)
	cacheCfg.ObjectsList.Size = getSize(v, l, cfgListObjectsCacheSize, cacheCfg.ObjectsList.Size)

	cacheCfg.Buckets.Lifetime = getLifetime(v, l, cfgBucketsCacheLifetime, cacheCfg.Buckets.Lifetime)
	cacheCfg.Buckets.Size = getSize(v, l, cfgBucketsCacheSize, cacheCfg.Buckets.Size)

	cacheCfg.Names.Lifetime = getLifetime(v, l, cfgNamesCacheLifetime, cacheCfg.Names.Lifetime)
	cacheCfg.Names.Size = getSize(v, l, cfgNamesCacheSize, cacheCfg.Names.Size)

	cacheCfg.System.Lifetime = getLifetime(v, l, cfgSystemLifetimeSize, cacheCfg.System.Lifetime)
	cacheCfg.System.Size = getSize(v, l, cfgSystemCacheSize, cacheCfg.System.Size)

	return cacheCfg
}

func getLifetime(v *viper.Viper, l *zap.Logger, cfgEntry string, defaultValue time.Duration) time.Duration {
	if v.IsSet(cfgEntry) {
		lifetime := v.GetDuration(cfgEntry)
		if lifetime <= 0 {
			l.Error("invalid lifetime, using default value (in seconds)",
				zap.String("parameter", cfgEntry),
				zap.Duration("value in config", lifetime),
				zap.Duration("default", defaultValue))
		} else {
			return lifetime
		}
	}
	return defaultValue
}

func getSize(v *viper.Viper, l *zap.Logger, cfgEntry string, defaultValue int) int {
	if v.IsSet(cfgEntry) {
		size := v.GetInt(cfgEntry)
		if size <= 0 {
			l.Error("invalid cache size, using default value",
				zap.String("parameter", cfgEntry),
				zap.Int("value in config", size),
				zap.Int("default", defaultValue))
		} else {
			return size
		}
	}
	return defaultValue
}

func getAccessBoxCacheConfig(v *viper.Viper, l *zap.Logger) *cache.Config {
	cacheCfg := cache.DefaultAccessBoxConfig()

	cacheCfg.Lifetime = getLifetime(v, l, cfgAccessBoxCacheLifetime, cacheCfg.Lifetime)
	cacheCfg.Size = getSize(v, l, cfgAccessBoxCacheSize, cacheCfg.Size)

	return cacheCfg
}

func getHandlerOptions(v *viper.Viper, l *zap.Logger) *handler.Config {
	var (
		cfg           handler.Config
		err           error
		policyStr     = handler.DefaultPolicy
		defaultMaxAge = handler.DefaultMaxAge
	)

	if v.IsSet(cfgDefaultPolicy) {
		policyStr = v.GetString(cfgDefaultPolicy)
	}

	if cfg.DefaultPolicy, err = policy.Parse(policyStr); err != nil {
		l.Fatal("couldn't parse container default policy",
			zap.Error(err))
	}

	if v.IsSet(cfgDefaultMaxAge) {
		defaultMaxAge = v.GetInt(cfgDefaultMaxAge)

		if defaultMaxAge <= 0 && defaultMaxAge != -1 {
			l.Fatal("invalid defaultMaxAge",
				zap.String("parameter", cfgDefaultMaxAge),
				zap.String("value in config", strconv.Itoa(defaultMaxAge)))
		}
	}

	cfg.DefaultMaxAge = defaultMaxAge
	cfg.NotificatorEnabled = v.GetBool(cfgEnableNATS)

	return &cfg
}
