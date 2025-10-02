package dashboard

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"

	"dns-resolver/internal/metrics"
)

//go:embed public
var publicFS embed.FS

// Server represents the dashboard server.
type Server struct {
	addr    string
	metrics *metrics.Metrics
}

// NewServer creates a new dashboard server.
func NewServer(addr string, m *metrics.Metrics) *Server {
	return &Server{
		addr:    addr,
		metrics: m,
	}
}

// Start starts the dashboard server.
func (s *Server) Start() {
	// Create a sub-filesystem that starts from the "public" directory
	staticFS, err := fs.Sub(publicFS, "public")
	if err != nil {
		log.Fatalf("Failed to create sub-filesystem for static assets: %v", err)
	}

	// Serve static files from the embedded filesystem.
	fs := http.FileServer(http.FS(staticFS))
	http.Handle("/", fs)

	// Handle metrics endpoint.
	http.HandleFunc("/metrics", s.metricsHandler)

	log.Printf("Dashboard server starting on %s", s.addr)
	if err := http.ListenAndServe(s.addr, nil); err != nil {
		log.Fatalf("Failed to start dashboard server: %v", err)
	}
}

// metricsHandler handles requests for metrics data.
func (s *Server) metricsHandler(w http.ResponseWriter, r *http.Request) {
	qps, totalQueries, probation, protected, qpsHistory, cacheLoadHistory, cpuUsage, memUsage, goroutines, cpuHistory, memHistory, topNX, topLatency, queryTypes, responseCodes := s.metrics.GetStats()

	data := struct {
		QPS                 float64             `json:"qps"`
		TotalQueries        int64               `json:"total_queries"`
		CacheProbation      int                 `json:"cache_probation"`
		CacheProtected      int                 `json:"cache_protected"`
		QPSHistory          []float64           `json:"qps_history"`
		CacheLoadHistory    []float64           `json:"cache_load_history"`
		CPUUsage            float64             `json:"cpu_usage"`
		MemoryUsage         float64             `json:"mem_usage"`
		GoroutineCount      int                 `json:"goroutine_count"`
		CPUHistory          []float64           `json:"cpu_history"`
		MemHistory          []float64           `json:"mem_history"`
		TopNXDomains        []metrics.TopDomain `json:"top_nx_domains"`
		TopLatencyDomains   []metrics.TopDomain `json:"top_latency_domains"`
		QueryTypes          []metrics.StatItem  `json:"query_types"`
		ResponseCodes       []metrics.StatItem  `json:"response_codes"`
	}{
		QPS:                 qps,
		TotalQueries:        totalQueries,
		CacheProbation:      probation,
		CacheProtected:      protected,
		QPSHistory:          qpsHistory,
		CacheLoadHistory:    cacheLoadHistory,
		CPUUsage:            cpuUsage,
		MemoryUsage:         memUsage,
		GoroutineCount:      goroutines,
		CPUHistory:          cpuHistory,
		MemHistory:          memHistory,
		TopNXDomains:        topNX,
		TopLatencyDomains:   topLatency,
		QueryTypes:          queryTypes,
		ResponseCodes:       responseCodes,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode metrics: %v", err), http.StatusInternalServerError)
	}
}