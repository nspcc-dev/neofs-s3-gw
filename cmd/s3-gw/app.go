package main

import (
	"context"
	"encoding/hex"
	"math"
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
	"github.com/nspcc-dev/neofs-s3-gw/internal/wallet"
	"github.com/nspcc-dev/neofs-sdk-go/policy"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

type (
	// App is the main application structure.
	App struct {
		pool pool.Pool
		ctr  auth.Center
		log  *zap.Logger
		cfg  *viper.Viper
		tls  *tlsConfig
		obj  layer.Client
		api  api.Handler

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
		conns  pool.Pool
		key    *keys.PrivateKey
		err    error
		tls    *tlsConfig
		caller api.Handler
		ctr    auth.Center
		obj    layer.Client

		poolPeers = fetchPeers(l, v)

		reBalance  = defaultRebalanceTimer
		conTimeout = defaultConnectTimeout
		reqTimeout = defaultRequestTimeout

		maxClientsCount    = defaultMaxClientsCount
		maxClientsDeadline = defaultMaxClientsDeadline
	)

	if v := v.GetDuration(cfgConnectTimeout); v > 0 {
		conTimeout = v
	}

	if v := v.GetDuration(cfgRequestTimeout); v > 0 {
		reqTimeout = v
	}

	if v := v.GetInt(cfgMaxClientsCount); v > 0 {
		maxClientsCount = v
	}

	if v := v.GetDuration(cfgMaxClientsDeadline); v > 0 {
		maxClientsDeadline = v
	}

	if v := v.GetDuration(cfgRebalanceTimer); v > 0 {
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

	opts := &pool.BuilderOptions{
		Key:                     &key.PrivateKey,
		NodeConnectionTimeout:   conTimeout,
		NodeRequestTimeout:      reqTimeout,
		ClientRebalanceInterval: reBalance,
		SessionExpirationEpoch:  math.MaxUint64,
	}
	conns, err = poolPeers.Build(ctx, opts)
	if err != nil {
		l.Fatal("failed to create connection pool", zap.Error(err))
	}

	// prepare random key for anonymous requests
	randomKey, err := keys.NewPrivateKey()
	if err != nil {
		l.Fatal("couldn't generate random key", zap.Error(err))
	}
	anonKey := layer.AnonymousKey{
		Key: randomKey,
	}

	cacheCfg := getCacheOptions(v, l)

	// prepare object layer
	obj = layer.NewLayer(l, conns, cacheCfg, anonKey)

	// prepare auth center
	ctr = auth.New(conns, key, getAccessBoxCacheConfig(v, l))

	handlerOptions := getHandlerOptions(v, l)

	if caller, err = handler.New(l, obj, handlerOptions); err != nil {
		l.Fatal("could not initialize API handler", zap.Error(err))
	}

	return &App{
		ctr:  ctr,
		pool: conns,
		log:  l,
		cfg:  v,
		obj:  obj,
		tls:  tls,
		api:  caller,

		webDone: make(chan struct{}, 1),
		wrkDone: make(chan struct{}, 1),

		maxClients: api.NewMaxClientsMiddleware(maxClientsCount, maxClientsDeadline),
	}
}

// Wait waits for application to finish.
func (a *App) Wait() {
	a.log.Info("application started")

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

	return &cfg
}
