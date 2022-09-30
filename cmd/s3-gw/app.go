package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/mux"
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
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

type (
	// App is the main application structure.
	App struct {
		ctr  auth.Center
		log  *zap.Logger
		cfg  *viper.Viper
		pool *pool.Pool
		key  *keys.PrivateKey
		nc   *notifications.Controller
		obj  layer.Client
		api  api.Handler

		metrics        *appMetrics
		bucketResolver *resolver.BucketResolver
		tlsProvider    *certProvider
		services       []*Service
		settings       *appSettings
		maxClients     api.MaxClients

		webDone chan struct{}
		wrkDone chan struct{}
	}

	appSettings struct {
		LogLevel zap.AtomicLevel
	}

	Logger struct {
		logger *zap.Logger
		lvl    zap.AtomicLevel
	}

	certProvider struct {
		Enabled bool

		mu       sync.RWMutex
		certPath string
		keyPath  string
		cert     *tls.Certificate
	}

	appMetrics struct {
		logger   *zap.Logger
		provider GateMetricsCollector
		mu       sync.RWMutex
		enabled  bool
	}

	GateMetricsCollector interface {
		SetHealth(int32)
		Unregister()
	}
)

func newApp(ctx context.Context, log *Logger, v *viper.Viper) *App {
	conns, key := getPool(ctx, log.logger, v)

	// prepare auth center
	ctr := auth.New(neofs.NewAuthmateNeoFS(conns), key, v.GetStringSlice(cfgAllowedAccessKeyIDPrefixes), getAccessBoxCacheConfig(v, log.logger))

	app := &App{
		ctr:  ctr,
		log:  log.logger,
		cfg:  v,
		pool: conns,
		key:  key,

		webDone: make(chan struct{}, 1),
		wrkDone: make(chan struct{}, 1),

		maxClients: newMaxClients(v),
		settings:   &appSettings{LogLevel: log.lvl},
	}

	app.init(ctx)

	return app
}

func (a *App) init(ctx context.Context) {
	a.initHandlers(ctx)
	a.initMetrics()
	a.initTLSProvider()
}

func (a *App) initLayer(ctx context.Context) {
	a.initResolver()

	treeServiceEndpoint := a.cfg.GetString(cfgTreeServiceEndpoint)
	treeService, err := neofs.NewTreeClient(treeServiceEndpoint, a.key)
	if err != nil {
		a.log.Fatal("failed to create tree service", zap.Error(err))
	}
	a.log.Info("init tree service", zap.String("endpoint", treeServiceEndpoint))

	// prepare random key for anonymous requests
	randomKey, err := keys.NewPrivateKey()
	if err != nil {
		a.log.Fatal("couldn't generate random key", zap.Error(err))
	}

	layerCfg := &layer.Config{
		Caches: getCacheOptions(a.cfg, a.log),
		AnonKey: layer.AnonymousKey{
			Key: randomKey,
		},
		Resolver:    a.bucketResolver,
		TreeService: treeService,
	}

	// prepare object layer
	a.obj = layer.NewLayer(a.log, neofs.NewNeoFS(a.pool), layerCfg)

	if a.cfg.GetBool(cfgEnableNATS) {
		nopts := getNotificationsOptions(a.cfg, a.log)
		a.nc, err = notifications.NewController(nopts, a.log)
		if err != nil {
			a.log.Fatal("failed to enable notifications", zap.Error(err))
		}

		if err = a.obj.Initialize(ctx, a.nc); err != nil {
			a.log.Fatal("couldn't initialize layer", zap.Error(err))
		}
	}
}

func (a *App) initHandlers(ctx context.Context) {
	a.initLayer(ctx)

	var err error
	handlerOptions := getHandlerOptions(a.cfg, a.log)

	a.api, err = handler.New(a.log, a.obj, a.nc, handlerOptions)
	if err != nil {
		a.log.Fatal("could not initialize API handler", zap.Error(err))
	}
}

func (a *App) initMetrics() {
	gateMetricsProvider := newGateMetrics(neofs.NewPoolStatistic(a.pool))
	a.metrics = newAppMetrics(a.log, gateMetricsProvider, a.cfg.GetBool(cfgPrometheusEnabled))
}

func (a *App) initResolver() {
	var err error
	a.bucketResolver, err = resolver.NewBucketResolver(a.getResolverConfig())
	if err != nil {
		a.log.Fatal("failed to create resolver", zap.Error(err))
	}
}

func (a *App) initTLSProvider() {
	a.tlsProvider = &certProvider{
		Enabled: a.cfg.IsSet(cfgTLSCertFile) || a.cfg.IsSet(cfgTLSKeyFile),
	}
}

func (a *App) getResolverConfig() ([]string, *resolver.Config) {
	resolveCfg := &resolver.Config{
		NeoFS:      neofs.NewResolverNeoFS(a.pool),
		RPCAddress: a.cfg.GetString(cfgRPCEndpoint),
	}

	order := a.cfg.GetStringSlice(cfgResolveOrder)
	if resolveCfg.RPCAddress == "" {
		order = remove(order, resolver.NNSResolver)
		a.log.Warn(fmt.Sprintf("resolver '%s' won't be used since '%s' isn't provided", resolver.NNSResolver, cfgRPCEndpoint))
	}

	if len(order) == 0 {
		a.log.Info("container resolver will be disabled because of resolvers 'resolver_order' is empty")
	}

	return order, resolveCfg
}

func newMaxClients(cfg *viper.Viper) api.MaxClients {
	maxClientsCount := cfg.GetInt(cfgMaxClientsCount)
	if maxClientsCount <= 0 {
		maxClientsCount = defaultMaxClientsCount
	}

	maxClientsDeadline := cfg.GetDuration(cfgMaxClientsDeadline)
	if maxClientsDeadline <= 0 {
		maxClientsDeadline = defaultMaxClientsDeadline
	}

	return api.NewMaxClientsMiddleware(maxClientsCount, maxClientsDeadline)
}

func getPool(ctx context.Context, logger *zap.Logger, cfg *viper.Viper) (*pool.Pool, *keys.PrivateKey) {
	var prm pool.InitParameters

	password := wallet.GetPassword(cfg, cfgWalletPassphrase)
	key, err := wallet.GetKeyFromPath(cfg.GetString(cfgWalletPath), cfg.GetString(cfgWalletAddress), password)
	if err != nil {
		logger.Fatal("could not load NeoFS private key", zap.Error(err))
	}

	prm.SetKey(&key.PrivateKey)
	logger.Info("using credentials", zap.String("NeoFS", hex.EncodeToString(key.PublicKey().Bytes())))

	for _, peer := range fetchPeers(logger, cfg) {
		prm.AddNode(peer)
	}

	connTimeout := cfg.GetDuration(cfgConnectTimeout)
	if connTimeout <= 0 {
		connTimeout = defaultConnectTimeout
	}
	prm.SetNodeDialTimeout(connTimeout)

	healthCheckTimeout := cfg.GetDuration(cfgHealthcheckTimeout)
	if healthCheckTimeout <= 0 {
		healthCheckTimeout = defaultHealthcheckTimeout
	}
	prm.SetNodeDialTimeout(healthCheckTimeout)

	rebalanceInterval := cfg.GetDuration(cfgRebalanceInterval)
	if rebalanceInterval <= 0 {
		rebalanceInterval = defaultRebalanceInterval
	}
	prm.SetClientRebalanceInterval(rebalanceInterval)

	errorThreshold := cfg.GetUint32(cfgPoolErrorThreshold)
	if errorThreshold <= 0 {
		errorThreshold = defaultPoolErrorThreshold
	}
	prm.SetErrorThreshold(errorThreshold)

	p, err := pool.NewPool(prm)
	if err != nil {
		logger.Fatal("failed to create connection pool", zap.Error(err))
	}

	if err = p.Dial(ctx); err != nil {
		logger.Fatal("failed to dial connection pool", zap.Error(err))
	}

	return p, key
}

func newAppMetrics(logger *zap.Logger, provider GateMetricsCollector, enabled bool) *appMetrics {
	if !enabled {
		logger.Warn("metrics are disabled")
	}
	return &appMetrics{
		logger:   logger,
		provider: provider,
	}
}

func (m *appMetrics) SetEnabled(enabled bool) {
	if !enabled {
		m.logger.Warn("metrics are disabled")
	}

	m.mu.Lock()
	m.enabled = enabled
	m.mu.Unlock()
}

func (m *appMetrics) SetHealth(status int32) {
	m.mu.RLock()
	if !m.enabled {
		m.mu.RUnlock()
		return
	}
	m.mu.RUnlock()

	m.provider.SetHealth(status)
}

func (m *appMetrics) Shutdown() {
	m.mu.Lock()
	if m.enabled {
		m.provider.SetHealth(0)
		m.enabled = false
	}
	m.provider.Unregister()
	m.mu.Unlock()
}

func (p *certProvider) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if !p.Enabled {
		return nil, errors.New("cert provider: disabled")
	}

	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.cert, nil
}

func (p *certProvider) UpdateCert(certPath, keyPath string) error {
	if !p.Enabled {
		return fmt.Errorf("tls disabled")
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return fmt.Errorf("cannot load TLS key pair from certFile '%s' and keyFile '%s': %w", certPath, keyPath, err)
	}

	p.mu.Lock()
	p.certPath = certPath
	p.keyPath = keyPath
	p.cert = &cert
	p.mu.Unlock()
	return nil
}

func (p *certProvider) FilePaths() (string, string) {
	if !p.Enabled {
		return "", ""
	}

	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.certPath, p.keyPath
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

	a.setHealthStatus()

	<-a.webDone // wait for web-server to be stopped

	a.log.Info("application finished")
}

func (a *App) setHealthStatus() {
	a.metrics.SetHealth(1)
}

// Serve runs HTTP server to handle S3 API requests.
func (a *App) Serve(ctx context.Context) {
	// Attach S3 API:
	domains := a.cfg.GetStringSlice(cfgListenDomains)
	a.log.Info("fetch domains, prepare to use API", zap.Strings("domains", domains))
	router := mux.NewRouter().SkipClean(true).UseEncodedPath()
	api.Attach(router, domains, a.maxClients, a.api, a.ctr, a.log)

	// Use mux.Router as http.Handler
	srv := new(http.Server)
	srv.Handler = router
	srv.ErrorLog = zap.NewStdLog(a.log)

	a.startServices()

	go func() {
		addr := a.cfg.GetString(cfgListenAddress)
		a.log.Info("starting server", zap.String("bind", addr))

		var lic net.ListenConfig
		ln, err := lic.Listen(ctx, "tcp", addr)
		if err != nil {
			a.log.Fatal("could not prepare listener", zap.Error(err))
		}

		if a.tlsProvider.Enabled {
			certFile := a.cfg.GetString(cfgTLSCertFile)
			keyFile := a.cfg.GetString(cfgTLSKeyFile)

			a.log.Info("using certificate", zap.String("cert", certFile), zap.String("key", keyFile))
			if err = a.tlsProvider.UpdateCert(certFile, keyFile); err != nil {
				a.log.Fatal("failed to update cert", zap.Error(err))
			}

			ln = tls.NewListener(ln, &tls.Config{
				GetCertificate: a.tlsProvider.GetCertificate,
			})
		}

		if err = srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			a.log.Fatal("listen and serve", zap.Error(err))
		}
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGHUP)

LOOP:
	for {
		select {
		case <-ctx.Done():
			break LOOP
		case <-sigs:
			a.configReload()
		}
	}

	ctx, cancel := shutdownContext()
	defer cancel()

	a.log.Info("stopping server", zap.Error(srv.Shutdown(ctx)))

	a.metrics.Shutdown()
	a.stopServices()

	close(a.webDone)
}

func shutdownContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), defaultShutdownTimeout)
}

func (a *App) configReload() {
	a.log.Info("SIGHUP config reload started")

	if !a.cfg.IsSet(cmdConfig) {
		a.log.Warn("failed to reload config because it's missed")
		return
	}
	if err := readConfig(a.cfg); err != nil {
		a.log.Warn("failed to reload config", zap.Error(err))
		return
	}

	if err := a.bucketResolver.UpdateResolvers(a.getResolverConfig()); err != nil {
		a.log.Warn("failed to reload resolvers", zap.Error(err))
	}

	if err := a.tlsProvider.UpdateCert(a.cfg.GetString(cfgTLSCertFile), a.cfg.GetString(cfgTLSKeyFile)); err != nil {
		a.log.Warn("failed to reload TLS certs", zap.Error(err))
	}

	a.stopServices()
	a.startServices()

	a.updateSettings()

	a.metrics.SetEnabled(a.cfg.GetBool(cfgPrometheusEnabled))
	a.setHealthStatus()

	a.log.Info("SIGHUP config reload completed")
}

func (a *App) updateSettings() {
	if lvl, err := getLogLevel(a.cfg); err != nil {
		a.log.Warn("log level won't be updated", zap.Error(err))
	} else {
		a.settings.LogLevel.SetLevel(lvl)
	}
}

func (a *App) startServices() {
	pprofService := NewPprofService(a.cfg, a.log)
	a.services = append(a.services, pprofService)
	go pprofService.Start()

	prometheusService := NewPrometheusService(a.cfg, a.log)
	a.services = append(a.services, prometheusService)
	go prometheusService.Start()
}

func (a *App) stopServices() {
	ctx, cancel := shutdownContext()
	defer cancel()

	for _, svc := range a.services {
		svc.ShutDown(ctx)
	}
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
	cacheCfg := layer.DefaultCachesConfigs(l)

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
	cacheCfg := cache.DefaultAccessBoxConfig(l)

	cacheCfg.Lifetime = getLifetime(v, l, cfgAccessBoxCacheLifetime, cacheCfg.Lifetime)
	cacheCfg.Size = getSize(v, l, cfgAccessBoxCacheSize, cacheCfg.Size)

	return cacheCfg
}

func getHandlerOptions(v *viper.Viper, l *zap.Logger) *handler.Config {
	var (
		cfg             handler.Config
		err             error
		policyStr       = handler.DefaultPolicy
		defaultMaxAge   = handler.DefaultMaxAge
		setCopiesNumber = handler.DefaultCopiesNumber
	)

	if v.IsSet(cfgDefaultPolicy) {
		policyStr = v.GetString(cfgDefaultPolicy)
	}

	if err = cfg.DefaultPolicy.DecodeString(policyStr); err != nil {
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

	if val := v.GetUint32(cfgSetCopiesNumber); val > 0 {
		setCopiesNumber = val
	}

	cfg.DefaultMaxAge = defaultMaxAge
	cfg.NotificatorEnabled = v.GetBool(cfgEnableNATS)
	cfg.TLSEnabled = v.IsSet(cfgTLSKeyFile) && v.IsSet(cfgTLSCertFile)
	cfg.CopiesNumber = setCopiesNumber

	return &cfg
}
