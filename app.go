package main

import (
	"context"
	"time"

	crypto "github.com/nspcc-dev/neofs-crypto"

	"github.com/minio/minio/neofs/layer"
	"github.com/minio/minio/pkg/auth"
	"github.com/nspcc-dev/neofs-api-go/refs"

	minio "github.com/minio/minio/cmd"
	"github.com/minio/minio/neofs/pool"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

type (
	App struct {
		cli pool.Pool
		log *zap.Logger
		cfg *viper.Viper
		obj minio.ObjectLayer

		conTimeout time.Duration
		reqTimeout time.Duration

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

		conTimeout = defaultConnectTimeout
		reqTimeout = defaultRequestTimeout
	)

	if v := v.GetDuration("connect_timeout"); v > 0 {
		conTimeout = v
	}

	if v := v.GetDuration("request_timeout"); v > 0 {
		reqTimeout = v
	}

	if cli, err = pool.New(l, v, key); err != nil {
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

		webDone: make(chan struct{}, 1),
		wrkDone: make(chan struct{}, 1),

		conTimeout: conTimeout,
		reqTimeout: reqTimeout,
	}
}

func (a *App) Wait(ctx context.Context) {
	a.log.Info("application started")

	select {
	case <-a.wrkDone: // wait for worker is stopped
		<-a.webDone
	case <-a.webDone: // wait for web-server is stopped
		<-a.wrkDone
	}
}

func (a *App) Server(ctx context.Context) {
	defer func() {
		<-ctx.Done()
		a.log.Info("stopping server")
		close(a.webDone)
	}()
}

func (a *App) Worker(ctx context.Context) {
	defer func() {
		<-ctx.Done()
		a.log.Info("stopping worker")
		close(a.wrkDone)
	}()
}
