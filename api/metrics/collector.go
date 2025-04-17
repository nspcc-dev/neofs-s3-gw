package metrics

import (
	"github.com/nspcc-dev/neofs-s3-gw/internal/version"
	"github.com/prometheus/client_golang/prometheus"
)

type stats struct {
	desc *prometheus.Desc
}

const (
	namespace = "neofs_s3"
)

var (
	versionInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "version",
			Help:      "Version of current NeoFS S3 Gate instance",
		},
		[]string{
			// current version
			"version",
		},
	)

	statsMetrics = &stats{
		desc: prometheus.NewDesc(namespace+"_stats", "Statistics exposed by NeoFS S3 Gate instance", nil, nil),
	}
)

func init() {
	prometheus.MustRegister(versionInfo)
	prometheus.MustRegister(statsMetrics)
	prometheus.MustRegister(httpRequestsDuration)

	// Expose current version information
	versionInfo.WithLabelValues(version.Version).Set(1.0)
}

func collectNetworkMetrics(ch chan<- prometheus.Metric) {
	// Network Sent/Received Bytes (Outbound)
	ch <- prometheus.MustNewConstMetric(
		prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "tx", "bytes_total"),
			"Total number of bytes sent by current NeoFS S3 Gate instance",
			nil, nil),
		prometheus.CounterValue,
		float64(httpStatsMetric.getInputBytes()),
	)

	ch <- prometheus.MustNewConstMetric(
		prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "rx", "bytes_total"),
			"Total number of bytes received by current NeoFS S3 Gate instance",
			nil, nil),
		prometheus.CounterValue,
		float64(httpStatsMetric.getOutputBytes()),
	)
}

func (s *stats) Describe(ch chan<- *prometheus.Desc) {
	ch <- s.desc
}

func (s *stats) Collect(ch chan<- prometheus.Metric) {
	// connect collectors
	collectHTTPMetrics(ch)
	collectNetworkMetrics(ch)
}
