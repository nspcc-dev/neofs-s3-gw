package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"net/http"

	"github.com/nspcc-dev/neo-go/cli/flags"
	"github.com/nspcc-dev/neo-go/cli/input"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neo-go/pkg/util"
	"github.com/nspcc-dev/neo-go/pkg/wallet"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/auth"
	"github.com/nspcc-dev/neofs-s3-gw/api/handler"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/nspcc-dev/neofs-sdk-go/pkg/pool"
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

	var password *string
	if v.IsSet(cfgWalletPassphrase) {
		pwd := v.GetString(cfgWalletPassphrase)
		password = &pwd
	}
	if key, err = getKeyFromWallet(v.GetString(cfgWallet), v.GetString(cfgAddress), password); err != nil {
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

	// prepare object layer
	obj = layer.NewLayer(l, conns)

	// prepare auth center
	ctr = auth.New(conns, &key.PrivateKey)

	if caller, err = handler.New(l, obj); err != nil {
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

func getKeyFromWallet(walletPath, addrStr string, password *string) (*keys.PrivateKey, error) {
	if len(walletPath) == 0 {
		return nil, fmt.Errorf("wallet path must not be empty")
	}
	w, err := wallet.NewWalletFromFile(walletPath)
	if err != nil {
		return nil, err
	}

	var addr util.Uint160
	if len(addrStr) == 0 {
		addr = w.GetChangeAddress()
	} else {
		addr, err = flags.ParseAddress(addrStr)
		if err != nil {
			return nil, fmt.Errorf("invalid address")
		}
	}

	acc := w.GetAccount(addr)
	if acc == nil {
		return nil, fmt.Errorf("couldn't find wallet account for %s", addrStr)
	}

	if password == nil {
		pwd, err := input.ReadPassword("Enter password > ")
		if err != nil {
			return nil, fmt.Errorf("couldn't read password")
		}
		password = &pwd
	}
	if err := acc.Decrypt(*password, w.Scrypt); err != nil {
		return nil, fmt.Errorf("couldn't decrypt account: %w", err)
	}

	return acc.PrivateKey(), nil
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
