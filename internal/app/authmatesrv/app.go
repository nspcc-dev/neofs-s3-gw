package authmatesrv

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	service2 "github.com/nspcc-dev/neofs-s3-gw/internal/app/authmatesrv/service"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

type (
	// App is the authbox service application.
	App struct {
		log  *zap.Logger
		echo *echo.Echo
	}
)

func NewApp(log *zap.Logger, v *viper.Viper) *App {
	gates, err := fetchGates(v)
	if err != nil {
		log.Fatal("could not read default gate keys", zap.Error(err))
	}

	for _, gate := range gates {
		log.Info("default gate", zap.String("public_key", gate.StringCompressed()))
	}

	service, err := service2.New(service2.Config{
		Gates:       gates,
		MaxLifetime: v.GetDuration(cfgMaxLifetime),
		Logger:      log,
	})
	if err != nil {
		log.Fatal("could not create service", zap.Error(err))
	}

	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	e.Server.ErrorLog = zap.NewStdLog(log)
	e.TLSServer.ErrorLog = e.Server.ErrorLog
	e.Use(middleware.Recover())
	e.Use(middleware.BodyLimit(fmt.Sprintf("%dB", v.GetInt64(cfgMaxRequestSize))))
	e.Use(middleware.CORS())

	service.RegisterRoutes(e)

	var (
		address = v.GetString(cfgServerAddress)
		useTLS  = v.GetBool(cfgTLSEnabled)
	)

	go func() {
		log.Info("starting server", zap.String("address", address), zap.Bool("tls", useTLS))

		var err error
		if useTLS {
			err = e.StartTLS(address, v.GetString(cfgTLSCertFile), v.GetString(cfgTLSKeyFile))
		} else {
			err = e.Start(address)
		}

		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("listen and serve", zap.Error(err))
		}
	}()

	return &App{log: log, echo: e}
}

// Serve blocks until the context is done, then shuts the server down.
func (a *App) Serve(ctx context.Context) {
	<-ctx.Done()

	a.log.Info("shutting down")

	// Detached from the cancelled context so that in-flight requests get their
	// grace period instead of being cut off immediately.
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), defaultShutdownTimeout)
	defer cancel()

	if err := a.echo.Shutdown(shutdownCtx); err != nil {
		a.log.Warn("shutdown", zap.Error(err))
	}

	a.log.Info("stopped")
}

func fetchGates(v *viper.Viper) (keys.PublicKeys, error) {
	var configured = v.GetStringSlice(cfgGates)
	if len(configured) == 0 {
		return nil, errors.New("no default gate keys configured")
	}

	var gates = make(keys.PublicKeys, 0, len(configured))

	for _, s := range configured {
		gateKey, err := keys.NewPublicKeyFromString(s)
		if err != nil {
			return nil, fmt.Errorf("invalid gate key %q: %w", s, err)
		}

		if gates.Contains(gateKey) {
			return nil, fmt.Errorf("duplicate gate key %q", s)
		}

		gates = append(gates, gateKey)
	}

	return gates, nil
}
