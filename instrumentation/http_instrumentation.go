package instrumentation

import (
	"github.com/go-chi/chi"
	metricslegacy "github.com/observatorium/api/api/metrics/legacy"
	metricsv1 "github.com/observatorium/api/api/metrics/v1"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/middleware"
	"github.com/observatorium/api/authentication"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// httpMetricsCollector is responsible for collecting HTTP metrics with extra tenant labels.
type httpMetricsCollector struct {
	requestCounter  *prometheus.CounterVec
	requestSize     *prometheus.SummaryVec
	requestDuration *prometheus.HistogramVec
	responseSize    *prometheus.HistogramVec
}

// newHTTPMetricsCollector creates a new httpMetricsCollector.
func newHTTPMetricsCollector(reg *prometheus.Registry) httpMetricsCollector {
	m := httpMetricsCollector{
		requestCounter: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Counter of HTTP requests.",
		},
			[]string{"group", "handler", "code", "method", "tenant"},
		),
		requestSize: promauto.With(reg).NewSummaryVec(
			prometheus.SummaryOpts{
				Name: "http_request_size_bytes",
				Help: "Size of HTTP requests.",
			},
			[]string{"group", "handler", "code", "method", "tenant"},
		),
		requestDuration: promauto.With(reg).NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_request_duration_seconds",
				Help:    "Histogram of latencies for HTTP requests.",
				Buckets: []float64{.1, .2, .4, 1, 2.5, 5, 8, 20, 60, 120},
			},
			[]string{"group", "handler", "code", "method", "tenant"},
		),
		responseSize: promauto.With(reg).NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_response_size_bytes",
				Help:    "Histogram of response size for HTTP requests.",
				Buckets: prometheus.ExponentialBuckets(100, 10, 8),
			},
			[]string{"group", "handler", "code", "method", "tenant"},
		),
	}
	return m
}

// instrumentedHandlerFactory is a factory for creating HTTP handlers instrumented by httpMetricsCollector.
type instrumentedHandlerFactory struct {
	metricsCollector httpMetricsCollector
}

// NewHandler creates a new instrumented HTTP handler with the given extra labels and calling the "next" handlers.
// If no extra labels are provided, we fetch them from request metadata.
func (m instrumentedHandlerFactory) NewHandler(extraLabels prometheus.Labels, next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(extraLabels) == 0 {
			if labels := httpHandlerLabels(r); len(labels) != 0 {
				extraLabels = labels
			}
		}
		rw := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		now := time.Now()
		next.ServeHTTP(rw, r)

		tenant, _ := authentication.GetTenantID(r.Context())
		m.metricsCollector.requestCounter.
			MustCurryWith(extraLabels).
			WithLabelValues(strconv.Itoa(rw.Status()), r.Method, tenant).
			Inc()

		size := computeApproximateRequestSize(r)
		m.metricsCollector.requestSize.
			MustCurryWith(extraLabels).
			WithLabelValues(strconv.Itoa(rw.Status()), r.Method, tenant).
			Observe(float64(size))

		m.metricsCollector.requestDuration.
			MustCurryWith(extraLabels).
			WithLabelValues(strconv.Itoa(rw.Status()), r.Method, tenant).
			Observe(time.Since(now).Seconds())

		m.metricsCollector.responseSize.
			MustCurryWith(extraLabels).
			WithLabelValues(strconv.Itoa(rw.Status()), r.Method, tenant).
			Observe(float64(rw.BytesWritten()))
	}
}

// NewInstrumentedHandlerFactory creates a new instrumentedHandlerFactory.
func NewInstrumentedHandlerFactory(req *prometheus.Registry) instrumentedHandlerFactory {
	return instrumentedHandlerFactory{
		metricsCollector: newHTTPMetricsCollector(req),
	}
}

func httpHandlerLabels(r *http.Request) prometheus.Labels {
	extraLabels := prometheus.Labels{
		"handler": "unknown",
		"group":   "unknown",
	}

	routePattern := chi.RouteContext(r.Context()).RoutePattern()
	tenant, ok := authentication.GetTenant(r.Context())
	if !ok {
		return extraLabels
	}

	var groupHandler map[string]groupHandler
	switch routePattern {
	case "/api/metrics/v1/{tenant}/*":
		groupHandler = metricsV1Group
	case "/api/v1/{tenant}/*":
		groupHandler = legacyMetricsGroup
	}

	strippedPath := strings.Split(r.URL.Path, tenant)
	if len(strippedPath) != 2 {
		return extraLabels
	}

	gh, ok := groupHandler[strippedPath[1]]
	if ok {
		extraLabels = prometheus.Labels{
			"group":   gh.group,
			"handler": gh.handler,
		}
	}
	return extraLabels
}

type groupHandler struct {
	group   string
	handler string
}

var legacyMetricsGroup = map[string]groupHandler{
	metricslegacy.QueryRoute:      {"metricslegacy", "query"},
	metricslegacy.QueryRangeRoute: {"metricslegacy", "query_range"},
}

var metricsV1Group = map[string]groupHandler{
	metricsv1.UIRoute:          {"metricsv1", "ui"},
	metricsv1.QueryRoute:       {"metricsv1", "query"},
	metricsv1.QueryRangeRoute:  {"metricsv1", "query_range"},
	metricsv1.SeriesRoute:      {"metricsv1", "series"},
	metricsv1.LabelNamesRoute:  {"metricsv1", "labels"},
	metricsv1.LabelValuesRoute: {"metricsv1", "labelvalues"},
	metricsv1.ReceiveRoute:     {"metricsv1", "receive"},
	metricsv1.RulesRoute:       {"metricsv1", "rules"},
	metricsv1.RulesRawRoute:    {"metricsv1", "rules"},
}

// Copied from https://github.com/prometheus/client_golang/blob/9075cdf61646b5adf54d3ba77a0e4f6c65cb4fd7/prometheus/promhttp/instrument_server.go#L350
func computeApproximateRequestSize(r *http.Request) int {
	s := 0
	if r.URL != nil {
		s += len(r.URL.String())
	}

	s += len(r.Method)
	s += len(r.Proto)
	for name, values := range r.Header {
		s += len(name)
		for _, value := range values {
			s += len(value)
		}
	}
	s += len(r.Host)

	// N.B. r.Form and r.MultipartForm are assumed to be included in r.URL.

	if r.ContentLength != -1 {
		s += int(r.ContentLength)
	}
	return s
}
