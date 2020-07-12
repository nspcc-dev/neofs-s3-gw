package main

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	minio "github.com/minio/minio/legacy"
	"github.com/minio/minio/neofs/layer"
	"github.com/minio/minio/neofs/pool"
	"github.com/minio/minio/pkg/auth"
	"github.com/nspcc-dev/neofs-api-go/refs"
	crypto "github.com/nspcc-dev/neofs-crypto"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"google.golang.org/grpc/keepalive"
)

type (
	App struct {
		cli pool.Pool
		log *zap.Logger
		web *mux.Router
		cfg *viper.Viper
		obj minio.ObjectLayer

		conTimeout time.Duration
		reqTimeout time.Duration

		reBalance time.Duration

		webDone chan struct{}
		wrkDone chan struct{}
	}
)

func newApp(l *zap.Logger, v *viper.Viper) *App {
	var (
		err error
		wif string
		cli pool.Pool
		uid refs.OwnerID
		obj minio.ObjectLayer

		key = fetchKey(l, v)

		reBalance = defaultRebalanceTimer

		conTimeout = defaultConnectTimeout
		reqTimeout = defaultRequestTimeout
	)

	if v := v.GetDuration(cfgConnectTimeout); v > 0 {
		conTimeout = v
	}

	if v := v.GetDuration(cfgRequestTimeout); v > 0 {
		reqTimeout = v
	}

	poolConfig := &pool.Config{
		ConnectionTTL:  v.GetDuration(cfgConnectionTTL),
		ConnectTimeout: v.GetDuration(cfgConnectTimeout),
		RequestTimeout: v.GetDuration(cfgRequestTimeout),

		Peers: fetchPeers(l, v),

		Logger:     l,
		PrivateKey: key,

		GRPCLogger:  gRPCLogger(l),
		GRPCVerbose: v.GetBool(cfgGRPCVerbose),

		ClientParameters: keepalive.ClientParameters{},
	}

	if v := v.GetDuration(cfgRebalanceTimer); v > 0 {
		reBalance = v
	}

	if cli, err = pool.New(poolConfig); err != nil {
		l.Fatal("could not prepare pool connections",
			zap.Error(err))
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

	{ // should prepare object layer
		if uid, err = refs.NewOwnerID(&key.PublicKey); err != nil {
			l.Fatal("could not fetch OwnerID",
				zap.Error(err))
		}

		if wif, err = crypto.WIFEncode(key); err != nil {
			l.Fatal("could not encode key to WIF",
				zap.Error(err))
		}

		if obj, err = layer.NewLayer(cli, auth.Credentials{AccessKey: uid.String(), SecretKey: wif}); err != nil {
			l.Fatal("could not prepare ObjectLayer",
				zap.Error(err))
		}

		_ = obj
	}

	return &App{
		cli: cli,
		log: l,
		cfg: v,
		web: minio.NewRouter(obj),

		webDone: make(chan struct{}, 1),
		wrkDone: make(chan struct{}, 1),

		reBalance: reBalance,

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
		srv  = http.Server{Handler: a.web}
		addr = a.cfg.GetString(cfgListenAddress)
	)

	if lis, err = lic.Listen(ctx, "tcp", addr); err != nil {
		a.log.Fatal("could not prepare listener",
			zap.Error(err))
	}

	// Attach app-specific routes:
	attachHealthy(a.web, a.cli)
	attachMetrics(a.cfg, a.log, a.web)
	attachProfiler(a.cfg, a.log, a.web)

	go func() {
		a.log.Info("starting server",
			zap.String("bind", addr))

		if err = srv.Serve(lis); err != nil && err != http.ErrServerClosed {
			a.log.Warn("listen and serve",
				zap.Error(err))
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
