package rtr

import (
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// CacheHealth tracks the operational health of a single RTR cache connection.
type CacheHealth struct {
	mu sync.RWMutex

	CacheAddr          string
	SessionUp          bool
	ConnectedAt        time.Time
	LastSerial         uint32
	LastSyncAt         time.Time
	VRPCount           int
	ASPACount          int
	RefreshInterval    time.Duration
	RetryInterval      time.Duration
	ExpireInterval     time.Duration
	StalenessThreshold time.Duration

	mSessionState prometheus.Gauge
	mVRPCount     prometheus.Gauge
	mASPACount    prometheus.Gauge
	mLastSyncTime prometheus.Gauge
	mSerialNumber prometheus.Gauge
	mSyncDuration prometheus.Histogram
	mStale        prometheus.Gauge
}

func NewCacheHealth(cacheAddr string, stalenessThreshold time.Duration, reg prometheus.Registerer) *CacheHealth {
	if stalenessThreshold == 0 {
		stalenessThreshold = 10 * time.Minute
	}
	labels := prometheus.Labels{"cache": cacheAddr}
	factory := promauto.With(reg)

	return &CacheHealth{
		CacheAddr:          cacheAddr,
		StalenessThreshold: stalenessThreshold,
		mSessionState: factory.NewGauge(prometheus.GaugeOpts{
			Name: "raven_rtr_session_state", Help: "RTR session state: 1=up, 0=down.", ConstLabels: labels,
		}),
		mVRPCount: factory.NewGauge(prometheus.GaugeOpts{
			Name: "raven_rtr_vrp_count", Help: "VRPs loaded from this RTR cache.", ConstLabels: labels,
		}),
		mASPACount: factory.NewGauge(prometheus.GaugeOpts{
			Name: "raven_rtr_aspa_count", Help: "ASPA records loaded from this RTR cache.", ConstLabels: labels,
		}),
		mLastSyncTime: factory.NewGauge(prometheus.GaugeOpts{
			Name: "raven_rtr_last_sync_seconds", Help: "Unix timestamp of last successful RTR sync.", ConstLabels: labels,
		}),
		mSerialNumber: factory.NewGauge(prometheus.GaugeOpts{
			Name: "raven_rtr_serial_number", Help: "Current RTR serial number.", ConstLabels: labels,
		}),
		mSyncDuration: factory.NewHistogram(prometheus.HistogramOpts{
			Name: "raven_rtr_sync_duration_seconds", Help: "Duration of RTR sync operations.",
			ConstLabels: labels, Buckets: []float64{0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0},
		}),
		mStale: factory.NewGauge(prometheus.GaugeOpts{
			Name: "raven_rtr_cache_stale", Help: "1 if cache has not synced within staleness threshold.", ConstLabels: labels,
		}),
	}
}

func (h *CacheHealth) MarkUp() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.SessionUp = true
	h.ConnectedAt = time.Now()
	h.mSessionState.Set(1)
}

func (h *CacheHealth) MarkDown() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.SessionUp = false
	h.mSessionState.Set(0)
}

func (h *CacheHealth) RecordSync(serial uint32, vrpCount, aspaCount int, duration time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.LastSerial = serial
	h.LastSyncAt = time.Now()
	h.VRPCount = vrpCount
	h.ASPACount = aspaCount
	h.mLastSyncTime.Set(float64(h.LastSyncAt.Unix()))
	h.mSerialNumber.Set(float64(serial))
	h.mVRPCount.Set(float64(vrpCount))
	h.mASPACount.Set(float64(aspaCount))
	h.mSyncDuration.Observe(duration.Seconds())
	h.mStale.Set(0)
}

func (h *CacheHealth) RecordIntervals(refresh, retry, expire uint32) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.RefreshInterval = time.Duration(refresh) * time.Second
	h.RetryInterval = time.Duration(retry) * time.Second
	h.ExpireInterval = time.Duration(expire) * time.Second
}

func (h *CacheHealth) Tick() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.SessionUp || h.LastSyncAt.IsZero() {
		return
	}
	if time.Since(h.LastSyncAt) > h.StalenessThreshold {
		h.mStale.Set(1)
	} else {
		h.mStale.Set(0)
	}
}

type StatusReport struct {
	CacheAddr          string
	SessionUp          bool
	ConnectedAt        time.Time
	LastSerial         uint32
	LastSyncAt         time.Time
	SinceLastSync      time.Duration
	VRPCount           int
	ASPACount          int
	RefreshInterval    time.Duration
	RetryInterval      time.Duration
	ExpireInterval     time.Duration
	Stale              bool
	StalenessThreshold time.Duration
}

func (h *CacheHealth) Report() StatusReport {
	h.mu.RLock()
	defer h.mu.RUnlock()
	stale := false
	sinceSync := time.Duration(0)
	if !h.LastSyncAt.IsZero() {
		sinceSync = time.Since(h.LastSyncAt).Round(time.Second)
		stale = sinceSync > h.StalenessThreshold
	}
	return StatusReport{
		CacheAddr: h.CacheAddr, SessionUp: h.SessionUp, ConnectedAt: h.ConnectedAt,
		LastSerial: h.LastSerial, LastSyncAt: h.LastSyncAt, SinceLastSync: sinceSync,
		VRPCount: h.VRPCount, ASPACount: h.ASPACount,
		RefreshInterval: h.RefreshInterval, RetryInterval: h.RetryInterval, ExpireInterval: h.ExpireInterval,
		Stale: stale, StalenessThreshold: h.StalenessThreshold,
	}
}

func (r StatusReport) String() string {
	state := "UP"
	if !r.SessionUp {
		state = "DOWN"
	}
	staleFlag := ""
	if r.Stale {
		staleFlag = " [STALE]"
	}
	return fmt.Sprintf("%s  state=%-4s  serial=%-8d  vrps=%-6d  aspas=%-5d  last-sync=%s ago%s",
		r.CacheAddr, state, r.LastSerial, r.VRPCount, r.ASPACount,
		r.SinceLastSync.Round(time.Second), staleFlag)
}
