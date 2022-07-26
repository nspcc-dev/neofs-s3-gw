package main

import (
	"context"
	"net/http"

	"go.uber.org/zap"
)

// Service serves metrics.
type Service struct {
	*http.Server
	enabled     bool
	log         *zap.Logger
	serviceType string
}

// Start runs http service with the exposed endpoint on the configured port.
func (ms *Service) Start() {
	if ms.enabled {
		ms.log.Info("service is running", zap.String("endpoint", ms.Addr))
		err := ms.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			ms.log.Warn("service couldn't start on configured port")
		}
	} else {
		ms.log.Info("service hasn't started since it's disabled")
	}
}

// ShutDown stops the service.
func (ms *Service) ShutDown(ctx context.Context) {
	ms.log.Info("shutting down service", zap.String("endpoint", ms.Addr))
	err := ms.Shutdown(ctx)
	if err != nil {
		ms.log.Panic("can't shut down service")
	}
}
