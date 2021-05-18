package metrics

import (
	"github.com/nspcc-dev/neofs-s3-gw/misc"
	"github.com/prometheus/client_golang/prometheus"
)

type stats struct {
	desc *prometheus.Desc
}

var (
	versionInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "neofs_s3",
			Name:      "version_info",
			Help:      "Version of current NeoFS S3 Gate instance",
		},
		[]string{
			// current version
			"version",
			// build time of the current version
			"build_time",
		},
	)

	statsMetrics = &stats{
		desc: prometheus.NewDesc("neofs_s3_stats", "Statistics exposed by MinIO server", nil, nil),
	}
)

func init() {
	prometheus.MustRegister(versionInfo)
	prometheus.MustRegister(statsMetrics)
	prometheus.MustRegister(httpRequestsDuration)
}

func collectNetworkMetrics(ch chan<- prometheus.Metric) {
	// Network Sent/Received Bytes (Outbound)
	ch <- prometheus.MustNewConstMetric(
		prometheus.NewDesc(
			prometheus.BuildFQName("neofs_s3", "tx", "bytes_total"),
			"Total number of bytes sent by current NeoFS S3 Gate instance",
			nil, nil),
		prometheus.CounterValue,
		float64(httpStatsMetric.getInputBytes()),
	)

	ch <- prometheus.MustNewConstMetric(
		prometheus.NewDesc(
			prometheus.BuildFQName("neofs_s3", "rx", "bytes_total"),
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
	// Expose current version information
	versionInfo.WithLabelValues(misc.Version, misc.Build).Set(1.0)

	// connect collectors
	collectHTTPMetrics(ch)
	collectNetworkMetrics(ch)
}
