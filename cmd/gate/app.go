package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"

	sdk "github.com/nspcc-dev/cdn-sdk"
	"github.com/nspcc-dev/cdn-sdk/creds/hcs"
	"github.com/nspcc-dev/cdn-sdk/creds/neofs"
	"github.com/nspcc-dev/cdn-sdk/pool"
	"github.com/nspcc-dev/neofs-s3-gate/api"
	"github.com/nspcc-dev/neofs-s3-gate/api/auth"
	"github.com/nspcc-dev/neofs-s3-gate/api/handler"
	"github.com/nspcc-dev/neofs-s3-gate/api/layer"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

type (
	App struct {
		cli pool.Client
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
		err    error
		tls    *tlsConfig
		cli    sdk.Client
		con    pool.Client
		caller api.Handler
		ctr    auth.Center
		obj    layer.Client

		hcsCred hcs.Credentials
		nfsCred neofs.Credentials

		peers = fetchPeers(l, v)

		reBalance  = defaultRebalanceTimer
		conTimeout = defaultConnectTimeout
		reqTimeout = defaultRequestTimeout

		maxClientsCount    = defaultMaxClientsCount
		maxClientsDeadline = defaultMaxClientsDeadline

		hcsCredential = v.GetString(cfgGateAuthPrivateKey)
		nfsCredential = v.GetString(cfgNeoFSPrivateKey)
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

	if nfsCred, err = neofs.New(nfsCredential); err != nil {
		l.Fatal("could not load NeoFS private key")
	}

	if hcsCred, err = hcs.NewCredentials(hcsCredential); err != nil {
		l.Fatal("could not load gate auth key")
	}

	if v.IsSet(cfgTLSKeyFile) && v.IsSet(cfgTLSCertFile) {
		tls = &tlsConfig{
			KeyFile:  v.GetString(cfgTLSKeyFile),
			CertFile: v.GetString(cfgTLSCertFile),
		}
	}

	l.Info("using credentials",
		zap.String("HCS", hcsCredential),
		zap.String("NeoFS", nfsCredential))

	poolOptions := []pool.Option{
		pool.WithLogger(l),
		pool.WithWeightPool(peers),
		pool.WithCredentials(nfsCred),
		pool.WithTickerTimeout(reBalance),
		pool.WithConnectTimeout(conTimeout),
		pool.WithRequestTimeout(reqTimeout),
		pool.WithAPIPreparer(sdk.APIPreparer),
		pool.WithGRPCOptions(
			grpc.WithBlock(),
			grpc.WithInsecure(),
			grpc.WithKeepaliveParams(keepalive.ClientParameters{
				Time:                v.GetDuration(cfgKeepaliveTime),
				Timeout:             v.GetDuration(cfgKeepaliveTimeout),
				PermitWithoutStream: v.GetBool(cfgKeepalivePermitWithoutStream),
			}))}

	if con, err = pool.New(ctx, poolOptions...); err != nil {
		l.Fatal("could not prepare pool connections", zap.Error(err))
	}

	{ // should establish connection with NeoFS Storage Nodes
		ctx, cancel := context.WithTimeout(ctx, conTimeout)
		defer cancel()

		if _, err = con.Connection(ctx); err != nil {
			if errors.Is(err, context.Canceled) {
				l.Info("connection canceled")
				os.Exit(0)
			}

			l.Fatal("could not establish connection",
				zap.Error(err))
		}
	}

	if cli, err = sdk.New(ctx,
		sdk.WithLogger(l),
		sdk.WithConnectionPool(con),
		sdk.WithCredentials(nfsCred),
		sdk.WithAPIPreparer(sdk.APIPreparer)); err != nil {
		l.Fatal("could not prepare sdk client",
			zap.Error(err))
	}

	// prepare object layer
	obj = layer.NewLayer(l, cli)

	// prepare auth center
	ctr = auth.New(cli.Object(), hcsCred.PrivateKey())

	if caller, err = handler.New(l, obj); err != nil {
		l.Fatal("could not initialize API handler", zap.Error(err))
	}

	return &App{
		ctr: ctr,
		cli: con,
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

func (a *App) Worker(ctx context.Context) {
	a.cli.Worker(ctx)
	a.log.Info("stopping worker")
	close(a.wrkDone)
}
