package main

import (
	"github.com/prometheus/client_golang/prometheus"
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
		stateMetrics: stateMetric,
	}
}

func newStateMetrics() stateMetrics {
	return stateMetrics{
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
