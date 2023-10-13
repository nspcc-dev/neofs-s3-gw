package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	"github.com/nspcc-dev/neofs-sdk-go/client"
	"github.com/nspcc-dev/neofs-sdk-go/netmap"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-sdk-go/stat"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

type (
	// App is the main application structure.
	App struct {
		ctr      auth.Center
		log      *zap.Logger
		cfg      *viper.Viper
		pool     *pool.Pool
		poolStat *stat.PoolStat
		gateKey  *keys.PrivateKey
		nc       *notifications.Controller
		obj      layer.Client
		api      api.Handler

		servers []Server

		metrics           *appMetrics
		resolverContainer *resolver.Container
		services          []*Service
		settings          *appSettings
		maxClients        api.MaxClients

		webDone chan struct{}
		wrkDone chan struct{}
	}

	appSettings struct {
		logLevel zap.AtomicLevel
		policies *placementPolicy
	}

	Logger struct {
		logger *zap.Logger
		lvl    zap.AtomicLevel
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

	placementPolicy struct {
		mu            sync.RWMutex
		defaultPolicy netmap.PlacementPolicy
		regionMap     map[string]netmap.PlacementPolicy
	}
)

func newApp(ctx context.Context, log *Logger, v *viper.Viper) *App {
	conns, key, poolStat := getPool(ctx, log.logger, v)

	signer := user.NewAutoIDSignerRFC6979(key.PrivateKey)

	// authmate doesn't require anonKey for work, but let's create random one.
	anonKey, err := keys.NewPrivateKey()
	if err != nil {
		log.logger.Fatal("newApp: couldn't generate random key", zap.Error(err))
	}
	anonSigner := user.NewAutoIDSignerRFC6979(anonKey.PrivateKey)
	log.logger.Info("anonymous signer", zap.String("userID", anonSigner.UserID().String()))

	ni, err := conns.NetworkInfo(ctx, client.PrmNetworkInfo{})
	if err != nil {
		log.logger.Fatal("newApp: networkInfo", zap.Error(err))
	}

	neofsCfg := neofs.Config{
		MaxObjectSize:        int64(ni.MaxObjectSize()),
		IsSlicerEnabled:      v.GetBool(cfgSlicerEnabled),
		IsHomomorphicEnabled: !ni.HomomorphicHashingDisabled(),
	}

	// If slicer is disabled, we should use "static" getter, which doesn't make periodic requests to the NeoFS.
	var epochGetter neofs.EpochGetter = ni

	if neofsCfg.IsSlicerEnabled {
		epochUpdateInterval := v.GetDuration(cfgEpochUpdateInterval)

		if epochUpdateInterval == 0 {
			epochUpdateInterval = time.Duration(int64(ni.EpochDuration())/2*ni.MsPerBlock()) * time.Millisecond
		}

		epochGetter = neofs.NewPeriodicGetter(ctx, ni.CurrentEpoch(), epochUpdateInterval, conns, log.logger)
	}

	neoFS := neofs.NewNeoFS(conns, signer, anonSigner, neofsCfg, epochGetter)

	// prepare auth center
	ctr := auth.New(neofs.NewAuthmateNeoFS(neoFS), key, v.GetStringSlice(cfgAllowedAccessKeyIDPrefixes), getAccessBoxCacheConfig(v, log.logger))

	app := &App{
		ctr:      ctr,
		log:      log.logger,
		cfg:      v,
		pool:     conns,
		poolStat: poolStat,
		gateKey:  key,

		webDone: make(chan struct{}, 1),
		wrkDone: make(chan struct{}, 1),

		maxClients: newMaxClients(v),
		settings:   newAppSettings(log, v),
	}

	app.init(ctx, anonSigner, neoFS)

	return app
}

func (a *App) init(ctx context.Context, anonSigner user.Signer, neoFS *neofs.NeoFS) {
	a.initAPI(ctx, anonSigner, neoFS)
	a.initMetrics()
	a.initServers(ctx)
}

func (a *App) initLayer(ctx context.Context, anonSigner user.Signer, neoFS *neofs.NeoFS) {
	a.initResolver(ctx)

	treeServiceEndpoint := a.cfg.GetString(cfgTreeServiceEndpoint)
	treeService, err := neofs.NewTreeClient(ctx, treeServiceEndpoint, a.gateKey)
	if err != nil {
		a.log.Fatal("failed to create tree service", zap.Error(err))
	}
	a.log.Info("init tree service", zap.String("endpoint", treeServiceEndpoint))

	layerCfg := &layer.Config{
		Caches:      getCacheOptions(a.cfg, a.log),
		GateKey:     a.gateKey,
		Anonymous:   anonSigner.UserID(),
		Resolver:    a.resolverContainer,
		TreeService: treeService,
	}

	// prepare object layer
	a.obj = layer.NewLayer(a.log, neoFS, layerCfg)

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

func newAppSettings(log *Logger, v *viper.Viper) *appSettings {
	policies, err := newPlacementPolicy(getDefaultPolicyValue(v), v.GetString(cfgPolicyRegionMapFile))
	if err != nil {
		log.logger.Fatal("failed to create new policy mapping", zap.Error(err))
	}

	return &appSettings{
		logLevel: log.lvl,
		policies: policies,
	}
}

func getDefaultPolicyValue(v *viper.Viper) string {
	defaultPolicyStr := handler.DefaultPolicy
	if v.IsSet(cfgPolicyDefault) {
		defaultPolicyStr = v.GetString(cfgPolicyDefault)
	}

	return defaultPolicyStr
}

func (a *App) initAPI(ctx context.Context, anonSigner user.Signer, neoFS *neofs.NeoFS) {
	a.initLayer(ctx, anonSigner, neoFS)
	a.initHandler()
}

func (a *App) initMetrics() {
	gateMetricsProvider := newGateMetrics(neofs.NewPoolStatistic(a.poolStat))
	gateMetricsProvider.SetGWVersion(version.Version)
	a.metrics = newAppMetrics(a.log, gateMetricsProvider, a.cfg.GetBool(cfgPrometheusEnabled))
}

func (a *App) initResolver(ctx context.Context) {
	endpoint := a.cfg.GetString(cfgRPCEndpoint)

	a.log.Info("rpc endpoint", zap.String("address", endpoint))

	res, err := resolver.NewContainer(ctx, endpoint)
	if err != nil {
		a.log.Fatal("resolver", zap.Error(err))
	}

	a.resolverContainer = res
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

func getPool(ctx context.Context, logger *zap.Logger, cfg *viper.Viper) (*pool.Pool, *keys.PrivateKey, *stat.PoolStat) {
	poolStat := stat.NewPoolStatistic()

	var prm pool.InitParameters
	prm.SetStatisticCallback(poolStat.OperationCallback)

	password := wallet.GetPassword(cfg, cfgWalletPassphrase)
	key, err := wallet.GetKeyFromPath(cfg.GetString(cfgWalletPath), cfg.GetString(cfgWalletAddress), password)
	if err != nil {
		logger.Fatal("could not load NeoFS private key", zap.Error(err))
	}

	prm.SetSigner(user.NewAutoIDSignerRFC6979(key.PrivateKey))
	logger.Info("using credentials", zap.String("NeoFS", hex.EncodeToString(key.PublicKey().Bytes())))

	for _, peer := range fetchPeers(logger, cfg) {
		prm.AddNode(peer)
	}

	connTimeout := cfg.GetDuration(cfgConnectTimeout)
	if connTimeout <= 0 {
		connTimeout = defaultConnectTimeout
	}
	prm.SetNodeDialTimeout(connTimeout)

	streamTimeout := cfg.GetDuration(cfgStreamTimeout)
	if streamTimeout <= 0 {
		streamTimeout = defaultStreamTimeout
	}
	prm.SetNodeStreamTimeout(streamTimeout)

	healthCheckTimeout := cfg.GetDuration(cfgHealthcheckTimeout)
	if healthCheckTimeout <= 0 {
		healthCheckTimeout = defaultHealthcheckTimeout
	}
	prm.SetHealthcheckTimeout(healthCheckTimeout)

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
	prm.SetLogger(logger)

	p, err := pool.NewPool(prm)
	if err != nil {
		logger.Fatal("failed to create connection pool", zap.Error(err))
	}

	if err = p.Dial(ctx); err != nil {
		logger.Fatal("failed to dial connection pool", zap.Error(err))
	}

	return p, key, poolStat
}

func newPlacementPolicy(defaultPolicy string, regionPolicyFilepath string) (*placementPolicy, error) {
	policies := &placementPolicy{
		regionMap: make(map[string]netmap.PlacementPolicy),
	}

	return policies, policies.update(defaultPolicy, regionPolicyFilepath)
}

func (p *placementPolicy) Default() netmap.PlacementPolicy {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.defaultPolicy
}

func (p *placementPolicy) Get(name string) (netmap.PlacementPolicy, bool) {
	p.mu.RLock()
	policy, ok := p.regionMap[name]
	p.mu.RUnlock()

	return policy, ok
}

func (p *placementPolicy) update(defaultPolicy string, regionPolicyFilepath string) error {
	var defaultPlacementPolicy netmap.PlacementPolicy
	if err := defaultPlacementPolicy.DecodeString(defaultPolicy); err != nil {
		return fmt.Errorf("parse default policy '%s': %w", defaultPolicy, err)
	}

	regionPolicyMap, err := readRegionMap(regionPolicyFilepath)
	if err != nil {
		return fmt.Errorf("read region map file: %w", err)
	}

	regionMap := make(map[string]netmap.PlacementPolicy, len(regionPolicyMap))
	for region, policy := range regionPolicyMap {
		var pp netmap.PlacementPolicy
		if err = pp.DecodeString(policy); err == nil {
			regionMap[region] = pp
			continue
		}

		if err = pp.UnmarshalJSON([]byte(policy)); err == nil {
			regionMap[region] = pp
			continue
		}

		return fmt.Errorf("parse region '%s' to policy mapping: %w", region, err)
	}

	p.mu.Lock()
	p.defaultPolicy = defaultPlacementPolicy
	p.regionMap = regionMap
	p.mu.Unlock()

	return nil
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

	for i := range a.servers {
		go func(i int) {
			a.log.Info("starting server", zap.String("address", a.servers[i].Address()))

			if err := srv.Serve(a.servers[i].Listener()); err != nil && err != http.ErrServerClosed {
				a.log.Fatal("listen and serve", zap.Error(err))
			}
		}(i)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGHUP)

LOOP:
	for {
		select {
		case <-ctx.Done():
			break LOOP
		case <-sigs:
			a.configReload(ctx)
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

func (a *App) configReload(ctx context.Context) {
	a.log.Info("SIGHUP config reload started")

	if !a.cfg.IsSet(cmdConfig) {
		a.log.Warn("failed to reload config because it's missed")
		return
	}
	if err := readConfig(a.cfg); err != nil {
		a.log.Warn("failed to reload config", zap.Error(err))
		return
	}

	if err := a.resolverContainer.UpdateResolvers(ctx, a.cfg.GetString(cfgRPCEndpoint)); err != nil {
		a.log.Warn("failed to update resolvers", zap.Error(err))
	}

	if err := a.updateServers(); err != nil {
		a.log.Warn("failed to reload server parameters", zap.Error(err))
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
		a.settings.logLevel.SetLevel(lvl)
	}

	if err := a.settings.policies.update(getDefaultPolicyValue(a.cfg), a.cfg.GetString(cfgPolicyRegionMapFile)); err != nil {
		a.log.Warn("policies won't be updated", zap.Error(err))
	}
}

func (a *App) startServices() {
	a.services = a.services[:0]

	pprofService := NewPprofService(a.cfg, a.log)
	a.services = append(a.services, pprofService)
	go pprofService.Start()

	prometheusService := NewPrometheusService(a.cfg, a.log)
	a.services = append(a.services, prometheusService)
	go prometheusService.Start()
}

func (a *App) initServers(ctx context.Context) {
	serversInfo := fetchServers(a.cfg)

	a.servers = make([]Server, len(serversInfo))
	for i, serverInfo := range serversInfo {
		a.log.Info("added server",
			zap.String("address", serverInfo.Address), zap.Bool("tls enabled", serverInfo.TLS.Enabled),
			zap.String("tls cert", serverInfo.TLS.CertFile), zap.String("tls key", serverInfo.TLS.KeyFile))
		a.servers[i] = newServer(ctx, serverInfo, a.log)
	}
}

func (a *App) updateServers() error {
	serversInfo := fetchServers(a.cfg)

	if len(serversInfo) != len(a.servers) {
		return fmt.Errorf("invalid servers configuration: amount mismatch: old '%d', new '%d", len(a.servers), len(serversInfo))
	}

	for i, serverInfo := range serversInfo {
		if serverInfo.Address != a.servers[i].Address() {
			return fmt.Errorf("invalid servers configuration: addresses mismatch: old '%s', new '%s", a.servers[i].Address(), serverInfo.Address)
		}

		if serverInfo.TLS.Enabled {
			if err := a.servers[i].UpdateCert(serverInfo.TLS.CertFile, serverInfo.TLS.KeyFile); err != nil {
				return fmt.Errorf("failed to update tls certs: %w", err)
			}
		}
	}

	return nil
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

	cacheCfg.System.Lifetime = getLifetime(v, l, cfgSystemCacheLifetime, cacheCfg.System.Lifetime)
	cacheCfg.System.Size = getSize(v, l, cfgSystemCacheSize, cacheCfg.System.Size)

	cacheCfg.AccessControl.Lifetime = getLifetime(v, l, cfgAccessControlCacheLifetime, cacheCfg.AccessControl.Lifetime)
	cacheCfg.AccessControl.Size = getSize(v, l, cfgAccessControlCacheSize, cacheCfg.AccessControl.Size)

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

func (a *App) initHandler() {
	cfg := &handler.Config{
		Policy:             a.settings.policies,
		DefaultMaxAge:      handler.DefaultMaxAge,
		NotificatorEnabled: a.cfg.GetBool(cfgEnableNATS),
		CopiesNumber:       handler.DefaultCopiesNumber,
	}

	if a.cfg.IsSet(cfgDefaultMaxAge) {
		defaultMaxAge := a.cfg.GetInt(cfgDefaultMaxAge)

		if defaultMaxAge <= 0 && defaultMaxAge != -1 {
			a.log.Fatal("invalid defaultMaxAge",
				zap.String("parameter", cfgDefaultMaxAge),
				zap.String("value in config", strconv.Itoa(defaultMaxAge)))
		}
		cfg.DefaultMaxAge = defaultMaxAge
	}

	if val := a.cfg.GetUint32(cfgSetCopiesNumber); val > 0 {
		cfg.CopiesNumber = val
	}

	cfg.MaxDeletePerRequest = a.cfg.GetInt(cfgMaxObjectToDeletePerRequest)
	if cfg.MaxDeletePerRequest == 0 {
		cfg.MaxDeletePerRequest = defaultMaxObjectDeletePerRequest
	}

	var err error
	a.api, err = handler.New(a.log, a.obj, a.nc, cfg)
	if err != nil {
		a.log.Fatal("could not initialize API handler", zap.Error(err))
	}
}

func readRegionMap(filePath string) (map[string]string, error) {
	regionMap := make(map[string]string)

	if filePath == "" {
		return regionMap, nil
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("coudln't read file '%s'", filePath)
	}

	if err = json.Unmarshal(data, &regionMap); err != nil {
		return nil, fmt.Errorf("unmarshal policies: %w", err)
	}

	if _, ok := regionMap[api.DefaultLocationConstraint]; ok {
		return nil, fmt.Errorf("config overrides %s location constraint", api.DefaultLocationConstraint)
	}

	return regionMap, nil
}
