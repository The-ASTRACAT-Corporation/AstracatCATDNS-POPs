package metrics

import (
	"sync"
	"time"
)

// Metrics holds the collected metrics.
type Metrics struct {
	sync.RWMutex
	qps              float64
	totalQueries     int64
	startTime        time.Time
	CacheProbation   int
	CacheProtected   int
	qpsHistory       []float64
	cacheLoadHistory []float64
}

var (
	instance *Metrics
	once     sync.Once
)

// NewMetrics returns the singleton instance of Metrics.
func NewMetrics() *Metrics {
	once.Do(func() {
		instance = &Metrics{
			startTime:        time.Now(),
			qpsHistory:       make([]float64, 0, 60), // Store last 60 seconds
			cacheLoadHistory: make([]float64, 0, 60),
		}
		go instance.qpsCalculator()
		go instance.cacheLoadCalculator()
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
		// elapsed := time.Since(m.startTime).Seconds()
		// if elapsed == 0 {
		// 	m.qps = 0
		// } else {
		// 	m.qps = float64(m.totalQueries) / elapsed
		// }
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

// GetStats returns the current statistics.
func (m *Metrics) GetStats() (float64, int64, int, int, []float64, []float64) {
	m.RLock()
	defer m.RUnlock()
	return m.qps, m.totalQueries, m.CacheProbation, m.CacheProtected, m.qpsHistory, m.cacheLoadHistory
}

// UpdateCacheStats updates the cache statistics.
func (m *Metrics) UpdateCacheStats(probation, protected int) {
	m.Lock()
	defer m.Unlock()
	m.CacheProbation = probation
	m.CacheProtected = protected
}