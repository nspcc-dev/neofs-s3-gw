package main

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/nspcc-dev/neofs-authmate/accessbox/hcs"
	"github.com/nspcc-dev/neofs-s3-gate/api"
	"github.com/nspcc-dev/neofs-s3-gate/api/handler"
	"github.com/nspcc-dev/neofs-s3-gate/api/layer"
	"github.com/nspcc-dev/neofs-s3-gate/api/pool"
	"github.com/nspcc-dev/neofs-s3-gate/auth"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"google.golang.org/grpc/keepalive"
)

type (
	App struct {
		cli pool.Pool
		ctr *auth.Center
		log *zap.Logger
		cfg *viper.Viper
		tls *tlsConfig
		obj layer.Client
		api api.Handler

		conTimeout time.Duration
		reqTimeout time.Duration

		reBalance time.Duration

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
		err    error
		cli    pool.Pool
		tls    *tlsConfig
		caller api.Handler
		ctr    *auth.Center
		obj    layer.Client

		gaKey *hcs.X25519Keys
		nfKey *ecdsa.PrivateKey

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

	if nfKey, err = fetchNeoFSKey(v); err != nil {
		l.Fatal("could not load NeoFS private key")
	}

	if gaKey, err = fetchGateAuthKeys(v); err != nil {
		l.Fatal("could not load gate auth key")
	}

	if v.IsSet(cfgTLSKeyFile) && v.IsSet(cfgTLSCertFile) {
		tls = &tlsConfig{
			KeyFile:  v.GetString(cfgTLSKeyFile),
			CertFile: v.GetString(cfgTLSCertFile),
		}
	}

	peers := fetchPeers(l, v)

	poolConfig := &pool.Config{
		ConnectTimeout: conTimeout,
		RequestTimeout: reqTimeout,
		ConnectionTTL:  v.GetDuration(cfgConnectionTTL),

		Peers: peers,

		Logger:     l,
		PrivateKey: nfKey,

		GRPCLogger:  gRPCLogger(l),
		GRPCVerbose: v.GetBool(cfgGRPCVerbose),

		ClientParameters: keepalive.ClientParameters{},
	}

	if cli, err = pool.New(poolConfig); err != nil {
		l.Fatal("could not prepare pool connections", zap.Error(err))
	}

	{ // prepare auth center
		ctx, cancel := context.WithTimeout(ctx, conTimeout)
		defer cancel()

		params := &authCenterParams{
			Logger: l,
			Pool:   cli,

			Timeout: conTimeout,

			GateAuthKeys:    gaKey,
			NeoFSPrivateKey: nfKey,
		}

		if ctr, err = fetchAuthCenter(ctx, params); err != nil {
			l.Fatal("failed to initialize auth center", zap.Error(err))
		}
	}

	{ // should establish connection with NeoFS Storage Nodes
		ctx, cancel := context.WithTimeout(ctx, conTimeout)
		defer cancel()

		cli.ReBalance(ctx)

		if _, err = cli.Connection(ctx); err != nil {
			if errors.Is(err, context.Canceled) {
				l.Info("connection canceled")
				os.Exit(0)
			}

			l.Fatal("could not establish connection",
				zap.Error(err))
		}
	}

	layerParams := &layer.Params{
		Pool:    cli,
		Logger:  l,
		Timeout: reqTimeout,
		NFKey:   nfKey,
	}

	if obj, err = layer.NewLayer(layerParams); err != nil {
		l.Fatal("could not prepare ObjectLayer", zap.Error(err))
	}

	if caller, err = handler.New(l, obj); err != nil {
		l.Fatal("could not initialize API handler", zap.Error(err))
	}

	return &App{
		ctr: ctr,
		cli: cli,
		log: l,
		cfg: v,
		obj: obj,
		tls: tls,
		api: caller,

		webDone: make(chan struct{}, 1),
		wrkDone: make(chan struct{}, 1),

		reBalance: reBalance,

		maxClients: api.NewMaxClientsMiddleware(maxClientsCount, maxClientsDeadline),

		conTimeout: conTimeout,
		reqTimeout: reqTimeout,
	}
}

func (a *App) Wait() {
	a.log.Info("application started")

	select {
	case <-a.wrkDone: // wait for worker is stopped
		<-a.webDone
	case <-a.webDone: // wait for web-server is stopped
		<-a.wrkDone
	}

	a.log.Info("application finished")
}

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
	attachHealthy(router, a.cli)
	attachMetrics(router, a.cfg, a.log)
	attachProfiler(router, a.cfg, a.log)

	// Attach S3 API:
	api.Attach(router, a.maxClients, a.api, a.ctr, a.log)

	// Use mux.Router as http.Handler
	srv.Handler = router

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

func (a *App) Worker(ctx context.Context) {
	tick := time.NewTimer(a.reBalance)

loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-tick.C:
			ctx, cancel := context.WithTimeout(ctx, a.conTimeout)
			a.cli.ReBalance(ctx)
			cancel()

			tick.Reset(a.reBalance)
		}
	}

	tick.Stop()
	a.cli.Close()
	a.log.Info("stopping worker")
	close(a.wrkDone)
}
