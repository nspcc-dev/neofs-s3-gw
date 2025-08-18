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

const (
	healthStatusUnhealthy healthStatus = iota
	healthStatusStaring
	healthStatusReady
)

type healthStatus int32

type GateMetrics struct {
	stateMetrics
}

type stateMetrics struct {
	healthCheck prometheus.Gauge
	gwVersion   *prometheus.GaugeVec
}

func newGateMetrics() *GateMetrics {
	stateMetric := newStateMetrics()
	stateMetric.register()

	return &GateMetrics{
		stateMetrics: *stateMetric,
	}
}

func (g *GateMetrics) Unregister() {
	g.stateMetrics.unregister()
}

func newStateMetrics() *stateMetrics {
	return &stateMetrics{
		healthCheck: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: stateSubsystem,
			Name:      "health",
			Help:      "Current S3 gateway state",
		}),
		gwVersion: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Help:      "Gateway version",
				Name:      "version",
				Namespace: namespace,
			},
			[]string{"version"},
		),
	}
}

func (m stateMetrics) register() {
	prometheus.MustRegister(m.healthCheck)
}

func (m stateMetrics) unregister() {
	prometheus.Unregister(m.healthCheck)
}

func (m stateMetrics) SetHealth(status healthStatus) {
	m.healthCheck.Set(float64(status))
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

func (g *GateMetrics) SetGWVersion(ver string) {
	g.gwVersion.WithLabelValues(ver).Add(1)
}
