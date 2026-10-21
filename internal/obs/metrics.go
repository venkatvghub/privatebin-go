package obs

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	reg           *prometheus.Registry
	Requests      *prometheus.CounterVec
	Latency       *prometheus.HistogramVec
	PastesCreated *prometheus.CounterVec
	PastesBurned  prometheus.Counter
}

func NewMetrics() *Metrics {
	m := &Metrics{
		reg: prometheus.NewRegistry(),
		Requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "privatebin_go_http_requests_total", Help: "HTTP requests."}, []string{"method", "route", "status"}),
		Latency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "privatebin_go_http_request_duration_seconds", Help: "HTTP latency.",
			Buckets: prometheus.DefBuckets}, []string{"method", "route"}),
		PastesCreated: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "privatebin_go_pastes_created_total", Help: "Pastes created."}, []string{"burn"}),
		PastesBurned: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "privatebin_go_pastes_burned_total", Help: "Burn-after-reading pastes consumed."}),
	}
	m.reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.Requests, m.Latency, m.PastesCreated, m.PastesBurned)
	return m
}

func (m *Metrics) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{}))
	return mux
}
