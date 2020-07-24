package main

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/minio/minio/auth"
	"github.com/minio/minio/neofs/api"
	"github.com/minio/minio/neofs/api/handler"
	"github.com/minio/minio/neofs/layer"
	"github.com/minio/minio/neofs/pool"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"google.golang.org/grpc/keepalive"

	// should be removed in future
	"github.com/minio/minio/legacy"
)

type (
	App struct {
		center *auth.Center
		cli    pool.Pool
		log    *zap.Logger
		cfg    *viper.Viper
		tls    *tlsConfig
		obj    legacy.ObjectLayer
		api    api.Handler

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

func newApp(l *zap.Logger, v *viper.Viper) *App {
	var (
		err        error
		cli        pool.Pool
		tls        *tlsConfig
		caller     api.Handler
		obj        legacy.ObjectLayer
		reBalance  = defaultRebalanceTimer
		conTimeout = defaultConnectTimeout
		reqTimeout = defaultRequestTimeout

		maxClientsCount    = defaultMaxClientsCount
		maxClientsDeadline = defaultMaxClientsDeadline
	)

	center, err := fetchAuthCenter(l, v)
	if err != nil {
		l.Fatal("failed to initialize auth center", zap.Error(err))
	}

	if v.IsSet(cfgTLSKeyFile) && v.IsSet(cfgTLSCertFile) {
		tls = &tlsConfig{
			KeyFile:  v.GetString(cfgTLSKeyFile),
			CertFile: v.GetString(cfgTLSCertFile),
		}
	}

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

	poolConfig := &pool.Config{
		ConnectionTTL:  v.GetDuration(cfgConnectionTTL),
		ConnectTimeout: v.GetDuration(cfgConnectTimeout),
		RequestTimeout: v.GetDuration(cfgRequestTimeout),

		Peers: fetchPeers(l, v),

		Logger:     l,
		PrivateKey: center.GetNeoFSPrivateKey(),

		GRPCLogger:  gRPCLogger(l),
		GRPCVerbose: v.GetBool(cfgGRPCVerbose),

		ClientParameters: keepalive.ClientParameters{},
	}

	if v := v.GetDuration(cfgRebalanceTimer); v > 0 {
		reBalance = v
	}

	if cli, err = pool.New(poolConfig); err != nil {
		l.Fatal("could not prepare pool connections", zap.Error(err))
	}

	{ // should establish connection with NeoFS Storage Nodes
		ctx, cancel := context.WithTimeout(context.Background(), conTimeout)
		defer cancel()

		cli.ReBalance(ctx)

		if _, err = cli.GetConnection(ctx); err != nil {
			l.Fatal("could not establish connection",
				zap.Error(err))
		}
	}

	if obj, err = layer.NewLayer(l, cli, center); err != nil {
		l.Fatal("could not prepare ObjectLayer", zap.Error(err))
	}

	{ // should prepare api.Handler:
		ctx, cancel := context.WithTimeout(context.Background(), conTimeout)
		defer cancel()

		apiParams := handler.Params{
			Log: l,
			Cli: cli,
			Key: center.GetNeoFSPrivateKey(),
		}

		if caller, err = handler.New(ctx, apiParams); err != nil {
			l.Fatal("could not initialize API handler", zap.Error(err))
		}
	}

	return &App{
		center: center,
		cli:    cli,
		log:    l,
		cfg:    v,
		obj:    obj,
		tls:    tls,
		api:    caller,

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
	api.Attach(router, a.maxClients, a.api, a.center, a.log)

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
