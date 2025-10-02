package metrics

import (
	"log"
	"runtime"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

// TopDomain holds a domain and its associated metric (count or latency).
type TopDomain struct {
	Domain string  `json:"domain"`
	Value  float64 `json:"value"`
}

// LatencyStat holds the total latency and count for a domain.
type LatencyStat struct {
	TotalLatency time.Duration
	Count        int64
}

// StatItem holds a name and a value for general statistics.
type StatItem struct {
	Name  string `json:"name"`
	Value int64  `json:"value"`
}

// Metrics holds the collected metrics.
type Metrics struct {
	sync.RWMutex
	qps                 float64
	totalQueries        int64
	startTime           time.Time
	CacheProbation      int
	CacheProtected      int
	qpsHistory          []float64
	cacheLoadHistory    []float64
	CPUUsage            float64       `json:"cpu_usage"`
	MemoryUsage         float64       `json:"mem_usage"`
	GoroutineCount      int           `json:"goroutine_count"`
	NetworkSent         uint64        `json:"network_sent"`
	NetworkRecv         uint64        `json:"network_recv"`
	cpuHistory          []float64     `json:"-"`
	memHistory          []float64     `json:"-"`
	networkSentHistory  []float64     `json:"-"`
	networkRecvHistory  []float64     `json:"-"`
	topNXDomains        sync.Map      // map[string]int64
	topLatencyDomains   sync.Map      // map[string]LatencyStat
	TopNXDomainsList    []TopDomain   `json:"top_nx_domains"`
	TopLatencyDomainsList []TopDomain `json:"top_latency_domains"`
	queryTypes          sync.Map      // map[string]int64
	responseCodes       sync.Map      // map[string]int64
	QueryTypesList      []StatItem    `json:"query_types"`
	ResponseCodesList   []StatItem    `json:"response_codes"`
}

var (
	instance *Metrics
	once     sync.Once
)

// NewMetrics returns the singleton instance of Metrics.
func NewMetrics() *Metrics {
	once.Do(func() {
		instance = &Metrics{
			startTime:           time.Now(),
			qpsHistory:          make([]float64, 0, 60),
			cacheLoadHistory:    make([]float64, 0, 60),
			cpuHistory:          make([]float64, 0, 60),
			memHistory:          make([]float64, 0, 60),
			networkSentHistory:  make([]float64, 0, 60),
			networkRecvHistory:  make([]float64, 0, 60),
			TopNXDomainsList:    make([]TopDomain, 0),
			TopLatencyDomainsList: make([]TopDomain, 0),
			QueryTypesList:      make([]StatItem, 0),
			ResponseCodesList:   make([]StatItem, 0),
		}
		go instance.qpsCalculator()
		go instance.cacheLoadCalculator()
		go instance.systemMetricsCollector()
		go instance.topDomainsProcessor()
		go instance.statisticsProcessor()
	})
	return instance
}

// IncrementQueries increments the total number of queries.
func (m *Metrics) IncrementQueries() {
	m.Lock()
	defer m.Unlock()
	m.totalQueries++
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
		m.qps = qps
		lastQueryCount = currentQueries

		m.qpsHistory = append(m.qpsHistory, m.qps)
		if len(m.qpsHistory) > 60 {
			m.qpsHistory = m.qpsHistory[1:]
		}
		m.Unlock()
	}
}

// cacheLoadCalculator calculates the cache load every second.
func (m *Metrics) cacheLoadCalculator() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		m.Lock()
		totalCache := m.CacheProbation + m.CacheProtected
		m.cacheLoadHistory = append(m.cacheLoadHistory, float64(totalCache))
		if len(m.cacheLoadHistory) > 60 {
			m.cacheLoadHistory = m.cacheLoadHistory[1:]
		}
		m.Unlock()
	}
}

// systemMetricsCollector gathers system metrics periodically.
func (m *Metrics) systemMetricsCollector() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		m.Lock()

		// CPU Usage
		cpuPercentages, err := cpu.Percent(0, false)
		if err == nil && len(cpuPercentages) > 0 {
			m.CPUUsage = cpuPercentages[0]
		}

		// Memory Usage
		memInfo, err := mem.VirtualMemory()
		if err == nil {
			m.MemoryUsage = memInfo.UsedPercent
		}

		// Goroutine Count
		m.GoroutineCount = runtime.NumGoroutine()

		// Network Stats
		netIO, err := net.IOCounters(false)
		if err == nil && len(netIO) > 0 {
			m.NetworkSent = netIO[0].BytesSent
			m.NetworkRecv = netIO[0].BytesRecv
		}

		// History for charts
		m.cpuHistory = append(m.cpuHistory, m.CPUUsage)
		if len(m.cpuHistory) > 60 {
			m.cpuHistory = m.cpuHistory[1:]
		}

		m.memHistory = append(m.memHistory, m.MemoryUsage)
		if len(m.memHistory) > 60 {
			m.memHistory = m.memHistory[1:]
		}

		m.networkSentHistory = append(m.networkSentHistory, float64(m.NetworkSent))
		if len(m.networkSentHistory) > 60 {
			m.networkSentHistory = m.networkSentHistory[1:]
		}

		m.networkRecvHistory = append(m.networkRecvHistory, float64(m.NetworkRecv))
		if len(m.networkRecvHistory) > 60 {
			m.networkRecvHistory = m.networkRecvHistory[1:]
		}

		m.Unlock()
		if err != nil {
			log.Printf("Error collecting system metrics: %v", err)
		}
	}
}

// GetStats returns the current statistics.
func (m *Metrics) GetStats() (float64, int64, int, int, []float64, []float64, float64, float64, int, []float64, []float64, []TopDomain, []TopDomain, []StatItem, []StatItem) {
	m.RLock()
	defer m.RUnlock()
	return m.qps, m.totalQueries, m.CacheProbation, m.CacheProtected, m.qpsHistory, m.cacheLoadHistory, m.CPUUsage, m.MemoryUsage, m.GoroutineCount, m.cpuHistory, m.memHistory, m.TopNXDomainsList, m.TopLatencyDomainsList, m.QueryTypesList, m.ResponseCodesList
}

// UpdateCacheStats updates the cache statistics.
func (m *Metrics) UpdateCacheStats(probation, protected int) {
	m.Lock()
	defer m.Unlock()
	m.CacheProbation = probation
	m.CacheProtected = protected
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
	var domains []TopDomain
	m.topNXDomains.Range(func(key, value interface{}) bool {
		domains = append(domains, TopDomain{Domain: key.(string), Value: float64(value.(int64))})
		return true
	})

	// Sort by count descending
	// For simplicity, we'll just take the top 10
	// A more efficient implementation would use a heap
	m.Lock()
	defer m.Unlock()
	m.TopNXDomainsList = sortAndTrim(domains, 10)
}

func (m *Metrics) processTopLatencyDomains() {
	var domains []TopDomain
	m.topLatencyDomains.Range(func(key, value interface{}) bool {
		stat := value.(LatencyStat)
		if stat.Count > 0 {
			avgLatency := stat.TotalLatency.Seconds() * 1000 / float64(stat.Count) // avg in ms
			domains = append(domains, TopDomain{Domain: key.(string), Value: avgLatency})
		}
		return true
	})

	m.Lock()
	defer m.Unlock()
	m.TopLatencyDomainsList = sortAndTrim(domains, 10)
}

// sortAndTrim sorts domains by value and trims the list to a given size.
func sortAndTrim(domains []TopDomain, size int) []TopDomain {
	// Simple bubble sort for demonstration. Replace with a more efficient algorithm for production.
	for i := 0; i < len(domains); i++ {
		for j := i + 1; j < len(domains); j++ {
			if domains[i].Value < domains[j].Value {
				domains[i], domains[j] = domains[j], domains[i]
			}
		}
	}

	if len(domains) > size {
		return domains[:size]
	}
	return domains
}

// RecordQueryType records the type of a DNS query.
func (m *Metrics) RecordQueryType(qtype string) {
	val, _ := m.queryTypes.LoadOrStore(qtype, int64(0))
	m.queryTypes.Store(qtype, val.(int64)+1)
}

// RecordResponseCode records the response code of a DNS query.
func (m *Metrics) RecordResponseCode(rcode string) {
	val, _ := m.responseCodes.LoadOrStore(rcode, int64(0))
	m.responseCodes.Store(rcode, val.(int64)+1)
}

// statisticsProcessor periodically processes the statistics maps.
func (m *Metrics) statisticsProcessor() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		m.processQueryTypes()
		m.processResponseCodes()
	}
}

func (m *Metrics) processQueryTypes() {
	var items []StatItem
	m.queryTypes.Range(func(key, value interface{}) bool {
		items = append(items, StatItem{Name: key.(string), Value: value.(int64)})
		return true
	})

	m.Lock()
	defer m.Unlock()
	m.QueryTypesList = items
}

func (m *Metrics) processResponseCodes() {
	var items []StatItem
	m.responseCodes.Range(func(key, value interface{}) bool {
		items = append(items, StatItem{Name: key.(string), Value: value.(int64)})
		return true
	})

	m.Lock()
	defer m.Unlock()
	m.ResponseCodesList = items
}