package main

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

const (
	namespace      = "neofs_s3_gw"
	stateSubsystem = "state"
)

type GateMetrics struct {
	stateMetrics
}

type stateMetrics struct {
	healthCheck prometheus.Gauge
}

func newGateMetrics() *GateMetrics {
	stateMetric := newStateMetrics()
	stateMetric.register()

	return &GateMetrics{
		stateMetrics: *stateMetric,
	}
}

func newStateMetrics() *stateMetrics {
	return &stateMetrics{
		healthCheck: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: stateSubsystem,
			Name:      "health",
			Help:      "Current S3 gateway state",
		}),
	}
}

func (m stateMetrics) register() {
	prometheus.MustRegister(m.healthCheck)
}

func (m stateMetrics) SetHealth(s int32) {
	m.healthCheck.Set(float64(s))
}

// NewPrometheusService creates a new service for gathering prometheus metrics.
func NewPrometheusService(v *viper.Viper, log *zap.Logger) *Service {
	if log == nil {
		return nil
	}

	return &Service{
		Server: &http.Server{
			Addr:    v.GetString(cfgPrometheusAddress),
			Handler: promhttp.Handler(),
		},
		enabled:     v.GetBool(cfgPrometheusEnabled),
		serviceType: "Prometheus",
		log:         log.With(zap.String("service", "Prometheus")),
	}
}
