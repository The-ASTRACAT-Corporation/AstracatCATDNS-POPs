package metrics

import (
	"log"
	"runtime"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

// LatencyStat holds the total latency and count for a domain.
type LatencyStat struct {
	TotalLatency time.Duration
	Count        int64
}

// Metrics holds the collected metrics.
type Metrics struct {
	sync.RWMutex
	totalQueries      int64
	startTime         time.Time
	topNXDomains      sync.Map // map[string]int64
	topLatencyDomains sync.Map // map[string]LatencyStat
	queryTypes        sync.Map // map[string]int64
	responseCodes     sync.Map // map[string]int64
}

var (
	instance *Metrics
	once     sync.Once

	promQPS = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "dns_resolver_qps",
		Help: "Queries per second",
	})
	promTotalQueries = promauto.NewCounter(prometheus.CounterOpts{
		Name: "dns_resolver_total_queries",
		Help: "Total number of DNS queries",
	})
	promCacheProbation = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "dns_resolver_cache_probation_size",
		Help: "Size of the probation segment of the cache",
	})
	promCacheProtected = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "dns_resolver_cache_protected_size",
		Help: "Size of the protected segment of the cache",
	})
	promCPUUsage = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "dns_resolver_cpu_usage_percent",
		Help: "Current CPU usage percentage",
	})
	promMemoryUsage = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "dns_resolver_memory_usage_percent",
		Help: "Current memory usage percentage",
	})
	promGoroutineCount = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "dns_resolver_goroutine_count",
		Help: "Current number of goroutines",
	})
	promNetworkSent = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "dns_resolver_network_sent_bytes",
		Help: "Total network bytes sent",
	})
	promNetworkRecv = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "dns_resolver_network_recv_bytes",
		Help: "Total network bytes received",
	})
	promTopNXDomains = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dns_resolver_top_nx_domains",
		Help: "Top domains with NXDOMAIN responses",
	}, []string{"domain"})
	promTopLatencyDomains = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dns_resolver_top_latency_domains_ms",
		Help: "Top domains by average query latency in milliseconds",
	}, []string{"domain"})
	promQueryTypes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_resolver_query_types_total",
		Help: "Total number of queries by type",
	}, []string{"type"})
	promResponseCodes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_resolver_response_codes_total",
		Help: "Total number of responses by code",
	}, []string{"code"})
	promUnboundErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "dns_resolver_unbound_errors_total",
		Help: "Total number of errors from the Unbound resolver",
	})
	promDNSSECValidation = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_resolver_dnssec_validation_total",
		Help: "Total number of DNSSEC validation results by type",
	}, []string{"result"})
	promCacheRevalidations = promauto.NewCounter(prometheus.CounterOpts{
		Name: "dns_resolver_cache_revalidations_total",
		Help: "Total number of cache revalidations",
	})
	promCacheHits = promauto.NewCounter(prometheus.CounterOpts{
		Name: "dns_resolver_cache_hits_total",
		Help: "Total number of cache hits",
	})
	promCacheMisses = promauto.NewCounter(prometheus.CounterOpts{
		Name: "dns_resolver_cache_misses_total",
		Help: "Total number of cache misses",
	})
	promCacheEvictions = promauto.NewCounter(prometheus.CounterOpts{
		Name: "dns_resolver_cache_evictions_total",
		Help: "Total number of cache evictions",
	})
	promLMDBCacheLoads = promauto.NewCounter(prometheus.CounterOpts{
		Name: "dns_resolver_lmdb_loads_total",
		Help: "Total number of items loaded from LMDB",
	})
	promLMDBErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "dns_resolver_lmdb_errors_total",
		Help: "Total number of LMDB errors",
	})
	promPrefetches = promauto.NewCounter(prometheus.CounterOpts{
		Name: "dns_resolver_prefetches_total",
		Help: "Total number of cache prefetches",
	})
)

// NewMetrics returns the singleton instance of Metrics.
func NewMetrics() *Metrics {
	once.Do(func() {
		instance = &Metrics{
			startTime: time.Now(),
		}
		go instance.qpsCalculator()
		go instance.systemMetricsCollector()
		go instance.topDomainsProcessor()
	})
	return instance
}

// IncrementQueries increments the total number of queries.
func (m *Metrics) IncrementQueries() {
	m.Lock()
	defer m.Unlock()
	m.totalQueries++
	promTotalQueries.Inc()
}

// qpsCalculator calculates the QPS every second.
func (m *Metrics) qpsCalculator() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var lastQueryCount int64
	for range ticker.C {
		m.Lock()
		currentQueries := m.totalQueries
		qps := float64(currentQueries - lastQueryCount)
		lastQueryCount = currentQueries
		m.Unlock()
		promQPS.Set(qps)
	}
}

// systemMetricsCollector gathers system metrics periodically.
func (m *Metrics) systemMetricsCollector() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// CPU Usage
		cpuPercentages, err := cpu.Percent(0, false)
		if err == nil && len(cpuPercentages) > 0 {
			promCPUUsage.Set(cpuPercentages[0])
		}

		// Memory Usage
		memInfo, err := mem.VirtualMemory()
		if err == nil {
			promMemoryUsage.Set(memInfo.UsedPercent)
		}

		// Goroutine Count
		promGoroutineCount.Set(float64(runtime.NumGoroutine()))

		// Network Stats
		netIO, err := net.IOCounters(false)
		if err == nil && len(netIO) > 0 {
			promNetworkSent.Set(float64(netIO[0].BytesSent))
			promNetworkRecv.Set(float64(netIO[0].BytesRecv))
		}

		if err != nil {
			log.Printf("Error collecting system metrics: %v", err)
		}
	}
}

// UpdateCacheStats updates the cache statistics.
func (m *Metrics) UpdateCacheStats(probation, protected int) {
	promCacheProbation.Set(float64(probation))
	promCacheProtected.Set(float64(protected))
}

// RecordNXDOMAIN records an NXDOMAIN response for a given domain.
func (m *Metrics) RecordNXDOMAIN(domain string) {
	val, _ := m.topNXDomains.LoadOrStore(domain, int64(0))
	m.topNXDomains.Store(domain, val.(int64)+1)
}

// RecordLatency records the query latency for a given domain.
func (m *Metrics) RecordLatency(domain string, latency time.Duration) {
	val, _ := m.topLatencyDomains.LoadOrStore(domain, LatencyStat{})
	stat := val.(LatencyStat)
	stat.TotalLatency += latency
	stat.Count++
	m.topLatencyDomains.Store(domain, stat)
}

// topDomainsProcessor periodically processes the domain maps to generate top lists.
func (m *Metrics) topDomainsProcessor() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		m.processTopNXDomains()
		m.processTopLatencyDomains()
	}
}

func (m *Metrics) processTopNXDomains() {
	var domains []struct {
		Domain string
		Count  int64
	}
	m.topNXDomains.Range(func(key, value interface{}) bool {
		domains = append(domains, struct {
			Domain string
			Count  int64
		}{key.(string), value.(int64)})
		return true
	})

	// Sort and get top 10
	// Simple bubble sort for demonstration
	for i := 0; i < len(domains); i++ {
		for j := i + 1; j < len(domains); j++ {
			if domains[i].Count < domains[j].Count {
				domains[i], domains[j] = domains[j], domains[i]
			}
		}
	}
	if len(domains) > 10 {
		domains = domains[:10]
	}

	promTopNXDomains.Reset()
	for _, d := range domains {
		promTopNXDomains.WithLabelValues(d.Domain).Set(float64(d.Count))
	}
}

func (m *Metrics) processTopLatencyDomains() {
	var domains []struct {
		Domain     string
		AvgLatency float64
	}
	m.topLatencyDomains.Range(func(key, value interface{}) bool {
		stat := value.(LatencyStat)
		if stat.Count > 0 {
			avgLatency := stat.TotalLatency.Seconds() * 1000 / float64(stat.Count) // avg in ms
			domains = append(domains, struct {
				Domain     string
				AvgLatency float64
			}{key.(string), avgLatency})
		}
		return true
	})

	// Sort and get top 10
	for i := 0; i < len(domains); i++ {
		for j := i + 1; j < len(domains); j++ {
			if domains[i].AvgLatency < domains[j].AvgLatency {
				domains[i], domains[j] = domains[j], domains[i]
			}
		}
	}
	if len(domains) > 10 {
		domains = domains[:10]
	}

	promTopLatencyDomains.Reset()
	for _, d := range domains {
		promTopLatencyDomains.WithLabelValues(d.Domain).Set(d.AvgLatency)
	}
}

// RecordQueryType records the type of a DNS query.
func (m *Metrics) RecordQueryType(qtype string) {
	promQueryTypes.WithLabelValues(qtype).Inc()
}

// RecordResponseCode records the response code of a DNS query.
func (m *Metrics) RecordResponseCode(rcode string) {
	promResponseCodes.WithLabelValues(rcode).Inc()
}

// IncrementUnboundErrors increments the Unbound error counter.
func (m *Metrics) IncrementUnboundErrors() {
	promUnboundErrors.Inc()
}

// RecordDNSSECValidation records a DNSSEC validation result.
func (m *Metrics) RecordDNSSECValidation(result string) {
	promDNSSECValidation.WithLabelValues(result).Inc()
}

// IncrementCacheRevalidations increments the cache revalidation counter.
func (m *Metrics) IncrementCacheRevalidations() {
	promCacheRevalidations.Inc()
}

// IncrementCacheHits increments the cache hit counter.
func (m *Metrics) IncrementCacheHits() {
	promCacheHits.Inc()
}

// IncrementCacheMisses increments the cache miss counter.
func (m *Metrics) IncrementCacheMisses() {
	promCacheMisses.Inc()
}

// IncrementCacheEvictions increments the cache eviction counter.
func (m *Metrics) IncrementCacheEvictions() {
	promCacheEvictions.Inc()
}

// IncrementLMDBCacheLoads increments the LMDB cache load counter.
func (m *Metrics) IncrementLMDBCacheLoads() {
	promLMDBCacheLoads.Inc()
}

// IncrementLMDBErrors increments the LMDB error counter.
func (m *Metrics) IncrementLMDBErrors() {
	promLMDBErrors.Inc()
}

// IncrementPrefetches increments the prefetch counter.
func (m *Metrics) IncrementPrefetches() {
	promPrefetches.Inc()
}