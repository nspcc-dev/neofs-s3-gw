package main

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/nspcc-dev/neofs-sdk-go/client"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

const (
	namespace      = "neofs_s3_gw"
	stateSubsystem = "state"

	checkNeoFSConnectionTimeOut = 5 * time.Second
)

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
	g.stateMetrics.unregister()
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

func (m *stateMetrics) SetHealth(s int32) {
	m.healthCheck.Set(float64(s))
}

func (m *stateMetrics) updateHealthStatus() {
	ctx, cancel := context.WithTimeout(context.Background(), checkNeoFSConnectionTimeOut)
	defer cancel()

	cl, err := m.p.RawClient()
	// Only "no healthy client" error is possible.
	if err != nil {
		m.healthCheck.Set(0)
		return
	}

	// Check actual connection is really alive.
	_, err = cl.NetworkInfo(ctx, client.PrmNetworkInfo{})
	if err != nil && strings.Contains(err.Error(), "connection error") {
		m.healthCheck.Set(0)
		return
	}

	m.healthCheck.Set(1)
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
