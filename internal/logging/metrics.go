package logging

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	HTTPRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "painscaler_http_requests_total",
		Help: "Total number of HTTP requests handled, partitioned by route, method, and status code.",
	}, []string{"route", "method", "status"})

	HTTPRequestDurationSeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "painscaler_http_request_duration_seconds",
		Help:    "Duration of HTTP requests in seconds, partitioned by route and method.",
		Buckets: prometheus.DefBuckets,
	}, []string{"route", "method"})

	FrontendEventsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "painscaler_frontend_events_total",
		Help: "Total number of telemetry events received from the frontend, partitioned by type.",
	}, []string{"type"})

	BuildInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "painscaler_build_info",
		Help: "Build metadata exposed as labels; value is always 1.",
	}, []string{"version", "commit", "date"})

	IndexBuildDurationSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "painscaler_index_build_duration_seconds",
		Help:    "Duration of a full index rebuild in seconds.",
		Buckets: prometheus.DefBuckets,
	})

	IndexBuildsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "painscaler_index_builds_total",
		Help: "Total number of index rebuild attempts, partitioned by outcome.",
	}, []string{"outcome"})

	FetchResourceDurationSeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "painscaler_fetch_resource_duration_seconds",
		Help:    "Duration of a single upstream resource fetch in seconds, partitioned by resource.",
		Buckets: prometheus.DefBuckets,
	}, []string{"resource"})

	FetchResourceErrorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "painscaler_fetch_resource_errors_total",
		Help: "Total number of upstream resource fetch errors, partitioned by resource.",
	}, []string{"resource"})
)

func SetBuildInfo(version, commit, date string) {
	BuildInfo.Reset()
	BuildInfo.WithLabelValues(version, commit, date).Set(1)
}
