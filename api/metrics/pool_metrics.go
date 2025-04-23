package metrics

import (
	"time"

	"github.com/nspcc-dev/neofs-sdk-go/stat"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	poolSubsystem = "pool"
)

type (
	// PoolMetrics provides metrics for SDK pool method calls.
	PoolMetrics struct {
		BalanceGet         prometheus.Histogram
		ContainerPut       prometheus.Histogram
		ContainerDelete    prometheus.Histogram
		ContainerGet       prometheus.Histogram
		ContainerSetEACL   prometheus.Histogram
		ContainerEACL      prometheus.Histogram
		ContainerList      prometheus.Histogram
		NetworkInfo        prometheus.Histogram
		ObjectHead         prometheus.Histogram
		ObjectRangeInit    prometheus.Histogram
		ObjectDelete       prometheus.Histogram
		ObjectGetInit      prometheus.Histogram
		SearchObjects      prometheus.Histogram
		ObjectPutInit      prometheus.Histogram
		EndpointInfo       prometheus.Histogram
		SessionCreate      prometheus.Histogram
		NetMapSnapshot     prometheus.Histogram
		ObjectHash         prometheus.Histogram
		ObjectGetStream    prometheus.Histogram
		ObjectRangeStream  prometheus.Histogram
		ObjectSearchStream prometheus.Histogram
		ObjectPutStream    prometheus.Histogram
		ObjectSearchV2     prometheus.Histogram
		OverallErrors      *prometheus.CounterVec
	}
)

// NewPoolMetrics is a constructor for PoolMetrics.
func NewPoolMetrics() *PoolMetrics {
	m := &PoolMetrics{
		BalanceGet: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: poolSubsystem,
			Name:      "balance_get",
			Help:      "Balance get request handling time",
		}),
		ContainerPut: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: poolSubsystem,
			Name:      "container_put",
			Help:      "Container put request handling time",
		}),
		ContainerDelete: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: poolSubsystem,
			Name:      "container_delete",
			Help:      "Container delete request handling time",
		}),
		ContainerGet: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: poolSubsystem,
			Name:      "container_get",
			Help:      "Container get request handling time",
		}),
		ContainerSetEACL: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: poolSubsystem,
			Name:      "container_set_eacl",
			Help:      "Container set eacl request handling time",
		}),
		ContainerEACL: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: poolSubsystem,
			Name:      "container_eacl",
			Help:      "Container eacl request handling time",
		}),
		ContainerList: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: poolSubsystem,
			Name:      "container_list",
			Help:      "Container list request handling time",
		}),
		NetworkInfo: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: poolSubsystem,
			Name:      "network_info",
			Help:      "Network info request handling time",
		}),
		ObjectHead: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: poolSubsystem,
			Name:      "object_head",
			Help:      "Object head request handling time",
		}),
		ObjectRangeInit: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: poolSubsystem,
			Name:      "object_range_init",
			Help:      "Object range init request handling time",
		}),

		ObjectDelete: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: poolSubsystem,
			Name:      "object_delete",
			Help:      "Object delete request handling time",
		}),
		ObjectGetInit: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: poolSubsystem,
			Name:      "object_get_init",
			Help:      "Object get init request handling time",
		}),
		SearchObjects: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: poolSubsystem,
			Name:      "search_objects",
			Help:      "Search objects request handling time",
		}),
		ObjectPutInit: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: poolSubsystem,
			Name:      "object_put_init",
			Help:      "Object put init request handling time",
		}),
		EndpointInfo: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: poolSubsystem,
			Name:      "endpoint_info",
			Help:      "Endpoint info request handling time",
		}),
		SessionCreate: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: poolSubsystem,
			Name:      "session_create",
			Help:      "Session create request handling time",
		}),
		NetMapSnapshot: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: poolSubsystem,
			Name:      "netmap_snapshot",
			Help:      "Netmap snapshot request handling time",
		}),
		ObjectHash: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: poolSubsystem,
			Name:      "object_hash",
			Help:      "Object hash request handling time",
		}),
		ObjectGetStream: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: poolSubsystem,
			Name:      "object_get_stream",
			Help:      "Object get stream request handling time",
		}),
		ObjectRangeStream: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: poolSubsystem,
			Name:      "object_range_stream",
			Help:      "Object range stream request handling time",
		}),
		ObjectSearchStream: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: poolSubsystem,
			Name:      "object_search_stream",
			Help:      "Object search stream request handling time",
		}),
		ObjectPutStream: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: poolSubsystem,
			Name:      "object_put_stream",
			Help:      "Object put stream request handling time",
		}),
		ObjectSearchV2: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: poolSubsystem,
			Name:      "object_search_v2",
			Help:      "Object search v2 request handling time",
		}),
		OverallErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: poolSubsystem,
			Name:      "overall_errors",
			Help:      "Overall errors for endpoint method",
		}, []string{"endpoint", "method"}),
	}

	m.register()

	return m
}

func (m PoolMetrics) register() {
	prometheus.MustRegister(m.BalanceGet)
	prometheus.MustRegister(m.ContainerPut)
	prometheus.MustRegister(m.ContainerDelete)
	prometheus.MustRegister(m.ContainerGet)
	prometheus.MustRegister(m.ContainerSetEACL)
	prometheus.MustRegister(m.ContainerEACL)
	prometheus.MustRegister(m.ContainerList)
	prometheus.MustRegister(m.NetworkInfo)
	prometheus.MustRegister(m.ObjectHead)
	prometheus.MustRegister(m.ObjectRangeInit)
	prometheus.MustRegister(m.ObjectDelete)
	prometheus.MustRegister(m.ObjectGetInit)
	prometheus.MustRegister(m.SearchObjects)
	prometheus.MustRegister(m.ObjectPutInit)
	prometheus.MustRegister(m.EndpointInfo)
	prometheus.MustRegister(m.SessionCreate)
	prometheus.MustRegister(m.NetMapSnapshot)
	prometheus.MustRegister(m.ObjectHash)
	prometheus.MustRegister(m.ObjectGetStream)
	prometheus.MustRegister(m.ObjectRangeStream)
	prometheus.MustRegister(m.ObjectSearchStream)
	prometheus.MustRegister(m.ObjectPutStream)
	prometheus.MustRegister(m.ObjectSearchV2)
	prometheus.MustRegister(m.OverallErrors)
}

func (m *PoolMetrics) OperationCallback(nodeKey []byte, endpoint string, method stat.Method, duration time.Duration, err error) {
	if len(nodeKey) == 0 {
		return
	}

	switch method {
	case stat.MethodBalanceGet:
		m.BalanceGet.Observe(duration.Seconds())
	case stat.MethodContainerPut:
		m.ContainerPut.Observe(duration.Seconds())
	case stat.MethodContainerGet:
		m.ContainerGet.Observe(duration.Seconds())
	case stat.MethodContainerList:
		m.ContainerList.Observe(duration.Seconds())
	case stat.MethodContainerDelete:
		m.ContainerDelete.Observe(duration.Seconds())
	case stat.MethodContainerEACL:
		m.ContainerEACL.Observe(duration.Seconds())
	case stat.MethodContainerSetEACL:
		m.ContainerSetEACL.Observe(duration.Seconds())
	case stat.MethodEndpointInfo:
		m.EndpointInfo.Observe(duration.Seconds())
	case stat.MethodNetworkInfo:
		m.NetworkInfo.Observe(duration.Seconds())
	case stat.MethodObjectPut:
		m.ObjectPutInit.Observe(duration.Seconds())
	case stat.MethodObjectDelete:
		m.ObjectDelete.Observe(duration.Seconds())
	case stat.MethodObjectGet:
		m.ObjectGetInit.Observe(duration.Seconds())
	case stat.MethodObjectHead:
		m.ObjectHead.Observe(duration.Seconds())
	case stat.MethodObjectRange:
		m.ObjectRangeInit.Observe(duration.Seconds())
	case stat.MethodSessionCreate:
		m.SessionCreate.Observe(duration.Seconds())
	case stat.MethodNetMapSnapshot:
		m.NetMapSnapshot.Observe(duration.Seconds())
	case stat.MethodObjectHash:
		m.ObjectHash.Observe(duration.Seconds())
	case stat.MethodObjectSearch:
		m.SearchObjects.Observe(duration.Seconds())
	case stat.MethodObjectGetStream:
		m.ObjectGetStream.Observe(duration.Seconds())
	case stat.MethodObjectRangeStream:
		m.ObjectRangeStream.Observe(duration.Seconds())
	case stat.MethodObjectSearchStream:
		m.ObjectSearchStream.Observe(duration.Seconds())
	case stat.MethodObjectPutStream:
		m.ObjectPutStream.Observe(duration.Seconds())
	case stat.MethodObjectSearchV2:
		m.ObjectSearchV2.Observe(duration.Seconds())
	default:
	}

	if err != nil {
		m.OverallErrors.WithLabelValues(endpoint, method.String()).Inc()
	}
}
