package main

import (
	"net/http"

	"github.com/nspcc-dev/neofs-sdk-go/pool"
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
	p           *pool.Pool
	healthCheck prometheus.Gauge
	gwVersion   *prometheus.GaugeVec
}

func newGateMetrics(p *pool.Pool) *GateMetrics {
	stateMetric := newStateMetrics(p)
	prometheus.MustRegister(stateMetric)

	return &GateMetrics{
		stateMetrics: *stateMetric,
	}
}

func (g *GateMetrics) Unregister() {
	g.unregister()
}

func newStateMetrics(p *pool.Pool) *stateMetrics {
	return &stateMetrics{
		p: p,
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

func (m *stateMetrics) unregister() {
	prometheus.Unregister(m.healthCheck)
}

func (m *stateMetrics) SetHealth(status healthStatus) {
	m.healthCheck.Set(float64(status))
}

func (m *stateMetrics) updateHealthStatus() {
	// Only "no healthy client" error is possible.
	if _, err := m.p.RawClient(); err != nil {
		m.SetHealth(healthStatusUnhealthy)
		return
	}

	m.SetHealth(healthStatusReady)
}

func (m *stateMetrics) Collect(ch chan<- prometheus.Metric) {
	m.updateHealthStatus()
	m.healthCheck.Collect(ch)
}

func (m stateMetrics) Describe(descs chan<- *prometheus.Desc) {
	m.healthCheck.Describe(descs)
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
