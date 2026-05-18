// Package conntrack implements connection tracking garbage collection.
package conntrack

import (
	"context"
	"encoding/binary"
	"log/slog"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
	"golang.org/x/sys/unix"
)

// GCStats holds statistics from the most recent GC sweep.
type GCStats struct {
	LastSweepTime       time.Time
	LastSweepDuration   time.Duration
	TotalEntries        int
	EstablishedSessions int
	ExpiredDeleted      int
	NextSweepDelay      time.Duration
}

// MaxSessions is the maximum number of session entries in the BPF map.
// This counts both forward and reverse entries, so the effective session
// count for watermark comparison is total/2.
const MaxSessions = 10_000_000

const maxAdaptiveInterval = 60 * time.Second

type sessionCountPublisher interface {
	UpdateSessionCountSrc(dataplane.SessionCountKey, uint32) error
	UpdateSessionCountDst(dataplane.SessionCountKey, uint32) error
	ClearSessionCounts() error
}

type persistentNATProvider interface {
	GetPersistentNAT() *dataplane.PersistentNATTable
}

// GC performs periodic garbage collection on the session table.
type GC struct {
	sessions     dataplane.SessionStore
	telemetry    dataplane.Telemetry
	sessionCount sessionCountPublisher
	persistent   persistentNATProvider
	interval     time.Duration
	mu           sync.RWMutex
	stats        GCStats

	OnDeleteV4 func(key dataplane.SessionKey)
	OnDeleteV6 func(key dataplane.SessionKeyV6)

	// IsLocalPrimary returns true when this node owns session lifetime.
	// When set and returning false, GC skips session expiry — the peer
	// primary will age sessions and sync deletes to us.
	IsLocalPrimary func() bool

	lastV6Count int // v6 entries found in previous sweep
	sweepCount  int // sweep counter for periodic forced v6 check
	lastTotal   int // total entries (v4+v6) found in previous sweep

	lastSessionCounter uint64 // last seen GLOBAL_CTR_SESSIONS_NEW value
	lastClosedCounter  uint64 // last seen GLOBAL_CTR_SESSIONS_CLOSED value

	// Scratch buffers reused across sweeps to reduce allocation churn.
	toDeleteV4 []dataplane.SessionEntryV4
	toDeleteV6 []dataplane.SessionEntryV6

	// Aggressive session aging (set via SetAgingConfig).
	agingActive   bool
	earlyAgeout   uint64 // seconds
	highWatermark int    // percent of MaxSessions
	lowWatermark  int    // percent of MaxSessions

	// Per-IP session limiting: when enabled, GC accumulates per-src/dst
	// session counts and pushes them to BPF maps for xdp_screen to check.
	sessionLimitEnabled bool

	// SkipSweep, when non-nil and returning true, causes GC to skip
	// the expensive BPF session map scan entirely. Used when the
	// userspace dataplane manages sessions in its own hash table —
	// the BPF map scan wastes ~19% CPU on maps that aren't used for
	// active session tracking.
	//
	// When SkipSweep is active, the userspace helper still mirrors
	// sessions to the BPF conntrack map (for CLI/gRPC display) and
	// periodically refreshes last_seen so IterateSessions callers
	// see accurate idle times.  The helper owns session lifetime;
	// GC expiry is intentionally bypassed.  See #333.
	SkipSweep func() bool
}

// NewGC creates a new session garbage collector.
func NewGC(dp dataplane.DataPlane, interval time.Duration) *GC {
	return NewGCWithDomains(
		dataplane.SessionStoreOf(dp),
		dataplane.TelemetryOf(dp),
		dp,
		dp,
		interval,
	)
}

// NewGCWithDomains creates a garbage collector from the runtime-domain
// interfaces used by #1381. The legacy NewGC constructor adapts existing
// dataplanes into these surfaces so callers can migrate independently.
func NewGCWithDomains(
	sessions dataplane.SessionStore,
	telemetry dataplane.Telemetry,
	sessionCount sessionCountPublisher,
	persistent persistentNATProvider,
	interval time.Duration,
) *GC {
	return &GC{
		sessions:     sessions,
		telemetry:    telemetry,
		sessionCount: sessionCount,
		persistent:   persistent,
		interval:     interval,
		lastV6Count:  -1,
	}
}

// SetAgingConfig updates the aggressive aging parameters.
// earlyAgeout is the shortened timeout in seconds (0 = disabled).
// highWM/lowWM are utilization percentages of MaxSessions (0 = disabled).
func (gc *GC) SetAgingConfig(earlyAgeout, highWM, lowWM int) {
	gc.mu.Lock()
	defer gc.mu.Unlock()
	gc.earlyAgeout = uint64(earlyAgeout)
	gc.highWatermark = highWM
	gc.lowWatermark = lowWM
	if highWM == 0 || earlyAgeout == 0 {
		gc.agingActive = false
	}
}

// SetSessionLimitEnabled enables or disables per-IP session counting
// during GC sweeps. When enabled, GC accumulates per-src/dst counts
// and pushes them to BPF maps for xdp_screen session limiting.
func (gc *GC) SetSessionLimitEnabled(enabled bool) {
	gc.mu.Lock()
	defer gc.mu.Unlock()
	gc.sessionLimitEnabled = enabled
}

// Stats returns a snapshot of the most recent GC sweep statistics.
func (gc *GC) Stats() GCStats {
	gc.mu.RLock()
	defer gc.mu.RUnlock()
	return gc.stats
}

// Run starts the GC loop. It blocks until ctx is cancelled.
func (gc *GC) Run(ctx context.Context) {
	slog.Info("conntrack GC started", "interval", gc.interval)
	timer := time.NewTimer(gc.interval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("conntrack GC stopped")
			return
		case <-timer.C:
			next := gc.sweep()
			if next <= 0 {
				next = gc.interval
			}
			timer.Reset(next)
		}
	}
}

func (gc *GC) sweep() time.Duration {
	// When userspace dataplane is active, skip the BPF session map scan
	// entirely — sessions are managed in user-space. Without this, the
	// batch lookup burns ~19% CPU scanning maps not used for forwarding.
	if gc.SkipSweep != nil && gc.SkipSweep() {
		return gc.interval
	}
	if gc.sessions == nil {
		slog.Error("conntrack GC session store not ready")
		return gc.interval
	}

	// Fast path: if no sessions existed on last sweep AND no new sessions
	// have been created since, skip the entire iteration.  This eliminates
	// ~25% CPU from empty-table batch lookups on idle firewalls.
	if gc.lastTotal == 0 && gc.telemetry != nil {
		newCtr, err1 := gc.telemetry.GlobalCounter(dataplane.GlobalCtrSessionsNew)
		closedCtr, err2 := gc.telemetry.GlobalCounter(dataplane.GlobalCtrSessionsClosed)
		if err1 == nil && err2 == nil &&
			newCtr == gc.lastSessionCounter &&
			closedCtr == gc.lastClosedCounter {
			return gc.nextSweepDelay(0, false, false, 0)
		}
		// Counters changed — fall through to full sweep.
		gc.lastSessionCounter = newCtr
		gc.lastClosedCounter = closedCtr
	}

	sweepStart := time.Now()
	now := monotonicSeconds()

	// When in cluster mode and this node is secondary, skip session
	// expiry — the primary owns session lifetime and syncs deletes.
	isPrimary := gc.IsLocalPrimary == nil || gc.IsLocalPrimary()

	var total, established, expired int
	var earliestDeadline uint64
	toDelete := gc.toDeleteV4[:0]

	// Per-IP session count accumulators (only used when session limiting is enabled)
	countSessions := gc.sessionLimitEnabled && gc.sessionCount != nil
	var srcCounts, dstCounts map[dataplane.SessionCountKey]uint32
	if countSessions {
		srcCounts = make(map[dataplane.SessionCountKey]uint32, 1024)
		dstCounts = make(map[dataplane.SessionCountKey]uint32, 1024)
	}

	err := gc.sessions.ForEachV4(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		total++

		// Only process forward entries to avoid double-counting
		if val.IsReverse != 0 {
			return true
		}

		if val.State == dataplane.SessStateEstablished {
			established++
		}

		// Check expiry (aggressive aging shortens effective timeout).
		// Skip on secondary — primary owns session lifetime.
		if isPrimary {
			effectiveTimeout := uint64(val.Timeout)
			if gc.agingActive && gc.earlyAgeout > 0 && gc.earlyAgeout < effectiveTimeout {
				effectiveTimeout = gc.earlyAgeout
			}
			deadline := val.LastSeen + effectiveTimeout
			if deadline < now {
				toDelete = append(toDelete, dataplane.SessionEntryV4{Key: key, Value: val})
			} else if earliestDeadline == 0 || deadline < earliestDeadline {
				earliestDeadline = deadline
			}
		}
		// Count active (non-expired) forward sessions per src/dst IP.
		// On secondary, all sessions are active (no local expiry).
		if countSessions && (!isPrimary || val.LastSeen+uint64(val.Timeout) >= now) {
			srcKey := dataplane.SessionCountKey{
				IP:     binary.NativeEndian.Uint32(key.SrcIP[:]),
				ZoneID: val.IngressZone,
			}
			dstKey := dataplane.SessionCountKey{
				IP:     binary.NativeEndian.Uint32(key.DstIP[:]),
				ZoneID: val.IngressZone,
			}
			srcCounts[srcKey]++
			dstCounts[dstKey]++
		}
		return true
	})
	if err != nil {
		slog.Error("conntrack GC iteration failed", "err", err)
		return gc.interval
	}

	if deleted, err := gc.sessions.DeleteBatchKnownV4(toDelete, dataplane.DeleteReasonGCExpired); err != nil {
		slog.Debug("conntrack GC v4 delete failed", "err", err)
	} else {
		expired += deleted
		if gc.OnDeleteV4 != nil {
			for _, entry := range toDelete {
				gc.OnDeleteV4(entry.Key)
			}
		}
	}

	// Save scratch buffers for reuse.
	gc.toDeleteV4 = toDelete

	// IPv6 sessions — skip iteration when previous sweep found zero entries,
	// but force a check every 6th sweep (60s at default 10s interval).
	gc.sweepCount++
	toDeleteV6 := gc.toDeleteV6[:0]
	skipV6 := gc.lastV6Count == 0 && gc.sweepCount%6 != 0

	if !skipV6 {
		var v6Count int
		err = gc.sessions.ForEachV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
			v6Count++
			total++

			if val.IsReverse != 0 {
				return true
			}

			if val.State == dataplane.SessStateEstablished {
				established++
			}

			// Skip expiry on secondary — primary owns session lifetime.
			if isPrimary {
				effectiveTimeout := uint64(val.Timeout)
				if gc.agingActive && gc.earlyAgeout > 0 && gc.earlyAgeout < effectiveTimeout {
					effectiveTimeout = gc.earlyAgeout
				}
				deadline := val.LastSeen + effectiveTimeout
				if deadline < now {
					toDeleteV6 = append(toDeleteV6, dataplane.SessionEntryV6{Key: key, Value: val})
				} else if earliestDeadline == 0 || deadline < earliestDeadline {
					earliestDeadline = deadline
				}
			}
			if countSessions && (!isPrimary || val.LastSeen+uint64(val.Timeout) >= now) {
				// XOR-hash IPv6 addresses to uint32 for session count key
				srcHash := binary.NativeEndian.Uint32(key.SrcIP[0:4]) ^
					binary.NativeEndian.Uint32(key.SrcIP[4:8]) ^
					binary.NativeEndian.Uint32(key.SrcIP[8:12]) ^
					binary.NativeEndian.Uint32(key.SrcIP[12:16])
				dstHash := binary.NativeEndian.Uint32(key.DstIP[0:4]) ^
					binary.NativeEndian.Uint32(key.DstIP[4:8]) ^
					binary.NativeEndian.Uint32(key.DstIP[8:12]) ^
					binary.NativeEndian.Uint32(key.DstIP[12:16])
				srcKey := dataplane.SessionCountKey{
					IP:     srcHash,
					ZoneID: val.IngressZone,
				}
				dstKey := dataplane.SessionCountKey{
					IP:     dstHash,
					ZoneID: val.IngressZone,
				}
				srcCounts[srcKey]++
				dstCounts[dstKey]++
			}
			return true
		})
		if err != nil {
			slog.Error("conntrack GC v6 iteration failed", "err", err)
			return gc.interval
		}
		gc.lastV6Count = v6Count
	}

	if deleted, err := gc.sessions.DeleteBatchKnownV6(toDeleteV6, dataplane.DeleteReasonGCExpired); err != nil {
		slog.Debug("conntrack GC v6 delete failed", "err", err)
	} else {
		expired += deleted
		if gc.OnDeleteV6 != nil {
			for _, entry := range toDeleteV6 {
				gc.OnDeleteV6(entry.Key)
			}
		}
	}

	// Save v6 scratch buffers for reuse.
	gc.toDeleteV6 = toDeleteV6

	// Run persistent NAT table GC to expire old bindings
	var pnat *dataplane.PersistentNATTable
	if gc.persistent != nil {
		pnat = gc.persistent.GetPersistentNAT()
	}
	if pnat != nil {
		if removed := pnat.GC(); removed > 0 {
			slog.Info("persistent NAT GC", "removed", removed)
		}
	}

	if expired > 0 {
		slog.Info("conntrack GC sweep",
			"total_entries", total,
			"established", established,
			"expired_deleted", expired)
	}

	gc.lastTotal = total

	// Push per-IP session counts to BPF maps for xdp_screen limiting.
	if countSessions {
		for k, c := range srcCounts {
			_ = gc.sessionCount.UpdateSessionCountSrc(k, c)
		}
		for k, c := range dstCounts {
			_ = gc.sessionCount.UpdateSessionCountDst(k, c)
		}
	}

	// Aggressive aging watermark hysteresis.
	// total counts both forward+reverse entries; MaxSessions is the map size
	// which holds both. Compare directly against MaxSessions.
	if gc.highWatermark > 0 && gc.earlyAgeout > 0 {
		pct := total * 100 / MaxSessions
		if !gc.agingActive && pct >= gc.highWatermark {
			gc.agingActive = true
			slog.Info("aggressive session aging activated",
				"utilization_pct", pct, "high_watermark", gc.highWatermark)
		} else if gc.agingActive && pct < gc.lowWatermark {
			gc.agingActive = false
			slog.Info("aggressive session aging deactivated",
				"utilization_pct", pct, "low_watermark", gc.lowWatermark)
		}
	}

	nextDelay := gc.nextSweepDelay(earliestDeadline, countSessions, isPrimary, total)

	gc.mu.Lock()
	gc.stats = GCStats{
		LastSweepTime:       sweepStart,
		LastSweepDuration:   time.Since(sweepStart),
		TotalEntries:        total,
		EstablishedSessions: established,
		ExpiredDeleted:      expired,
		NextSweepDelay:      nextDelay,
	}
	gc.mu.Unlock()

	return nextDelay
}

func (gc *GC) nextSweepDelay(earliestDeadline uint64, countSessions, isPrimary bool, total int) time.Duration {
	return gc.nextSweepDelayAt(monotonicSeconds(), earliestDeadline, countSessions, isPrimary, total)
}

func (gc *GC) nextSweepDelayAt(now, earliestDeadline uint64, countSessions, isPrimary bool, total int) time.Duration {
	if gc.interval <= 0 {
		return 0
	}
	if countSessions {
		return gc.interval
	}
	if gc.agingActive && gc.earlyAgeout > 0 {
		return gc.interval
	}
	if !isPrimary {
		return maxAdaptiveDelay(gc.interval, maxAdaptiveInterval)
	}
	if total == 0 || earliestDeadline == 0 {
		return maxAdaptiveDelay(gc.interval, maxAdaptiveInterval)
	}

	if earliestDeadline <= now {
		return gc.interval
	}

	until := time.Duration(earliestDeadline-now) * time.Second
	if until < gc.interval {
		return gc.interval
	}
	return maxAdaptiveDelay(until, maxAdaptiveInterval)
}

func maxAdaptiveDelay(delay, limit time.Duration) time.Duration {
	if delay > limit {
		return limit
	}
	return delay
}

// monotonicSeconds returns the current monotonic clock in seconds,
// matching BPF's bpf_ktime_get_ns() / 1e9.
func monotonicSeconds() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)
}
