package fwdstatus

import (
	"context"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/dataplane/userspace"
)

// ringSize is the sampler ring capacity.  At 1s cadence it holds 6m
// of history — comfortably past the 5m window lookup, with headroom
// for occasional missed samples.
const ringSize = 360

// SampleInterval is the sampler cadence.
const SampleInterval = 1 * time.Second

// CPU window indices.
const (
	CPUWindow5s = iota
	CPUWindow1m
	CPUWindow5m
	numCPUWindows
)

// cpuSample is one tick of the cumulative-counter ring.  All
// counters are monotonic nanoseconds.
type cpuSample struct {
	wall           time.Time
	daemonCPUNs    uint64 // /proc/self/stat utime+stime, converted to ns
	workerThreadNs uint64 // Σ WorkerRuntimeStatus.thread_cpu_ns across workers
	workerWallNs   uint64 // Σ WorkerRuntimeStatus.wall_ns across workers
	workerHeld     bool   // CachedStatus miss: worker counters are stale, not zero.
}

// Sampler maintains a ring of cumulative CPU counters.  One
// instance per daemon, started at boot.  Snapshot() returns a
// read-only copy safe to hand to Build() off-lock.
type Sampler struct {
	mu    sync.Mutex
	ring  [ringSize]cpuSample
	head  int    // next write index, wraps 0..ringSize-1
	count uint64 // monotonic count of samples ever taken (no wrap)

	dp   CachedStatusProvider
	proc ProcReader

	// Snapshot of the last successfully-read worker telemetry.
	// On a failed CachedStatus() probe the sampler reuses these values
	// so the counter series stays monotonic (see plan §Error handling).
	lastWorkerThread uint64
	lastWorkerWall   uint64
}

// CachedStatusProvider is the narrowed dataplane surface the sampler
// needs (#2114): exactly one control-socket-free read of the last
// captured userspace-dp ProcessStatus. It is deliberately NOT
// DataPlaneAccessor: Build keys backend identity on Status() presence
// (builder.go), so a provider that only carries CachedStatus can never
// be misrouted into a Build path, and the daemon-side adapter is free
// to re-probe the currently published dataplane on every tick.
type CachedStatusProvider interface {
	CachedStatus() (userspace.ProcessStatus, bool)
}

// NewSampler constructs a Sampler.  The sampler is not running
// until Start() is called.
func NewSampler(dp CachedStatusProvider, proc ProcReader) *Sampler {
	return &Sampler{dp: dp, proc: proc}
}

// Start primes one sample synchronously, then launches a goroutine
// that samples every SampleInterval until ctx is canceled.
// Returns immediately after priming.
func (s *Sampler) Start(ctx context.Context) {
	s.sample(time.Now())
	go s.loop(ctx)
}

func (s *Sampler) loop(ctx context.Context) {
	t := time.NewTicker(SampleInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.sample(now)
		}
	}
}

// sample captures one row and appends it to the ring.  On
// /proc/self/stat read failure the sample is dropped entirely —
// skipping preserves monotonicity of daemonCPUNs.  On worker
// telemetry failure the worker counters are held at their
// previous values and marked invalid (not an observed zero interval).
//
// Worker CPU comes from Σthread_cpu_ns (OS thread CPU via
// CLOCK_THREAD_CPUTIME_ID) divided by Σwall_ns.  NOT Σactive_ns —
// that was tried and reverted: see #883 (workers bypassed under
// load) and #884 (active_ns idle-poll undercounting).
func (s *Sampler) sample(now time.Time) {
	selfStat, statErr := s.proc.ReadSelfStat()
	if statErr != nil {
		return
	}
	daemonNs := ticksToNanos(selfStat.UtimeTicks + selfStat.StimeTicks)

	// Worker counters — userspace-dp only.
	//
	// #3970: consume the CACHED ProcessStatus that the manager's
	// primary 1 Hz status poll (statusLoop) already fetched, rather
	// than issuing our own Status() control-socket request. Two
	// independent 1 Hz "status" requests doubled the shared
	// control-socket rate and starved session installs during bulk
	// sync (CLAUDE.md "Control socket contention"). CachedStatus()
	// MUST NOT touch the control socket; on a miss (helper not yet
	// polled) the worker counters hold at their previous values,
	// preserving series monotonicity exactly as the old Status()
	// error path did. #2114: the provider IS a CachedStatusProvider
	// now — the per-tick type assertion is gone.
	workerThread, workerWall := s.lastWorkerThread, s.lastWorkerWall
	workerHeld := false
	if s.dp != nil {
		if st, ok := s.dp.CachedStatus(); ok {
			var tc, w uint64
			for _, wr := range st.WorkerRuntime {
				tc += wr.ThreadCPUNS
				w += wr.WallNS
			}
			workerThread, workerWall = tc, w
		} else {
			workerHeld = true
		}
	}

	s.mu.Lock()
	s.ring[s.head] = cpuSample{
		wall:           now,
		daemonCPUNs:    daemonNs,
		workerThreadNs: workerThread,
		workerWallNs:   workerWall,
		workerHeld:     workerHeld,
	}
	s.head = (s.head + 1) % ringSize
	s.count++
	s.lastWorkerThread = workerThread
	s.lastWorkerWall = workerWall
	s.mu.Unlock()
}

// SamplerSnapshot is a value-type view of the ring passed to
// Build().  Samples is ordered oldest-first, newest-last.  Empty
// snapshot renders as all-windows-invalid in Build().
type SamplerSnapshot struct {
	Samples []cpuSample
	Now     time.Time
}

// Snapshot copies the ring under lock and returns it.  Always
// ordered oldest-first.
func (s *Sampler) Snapshot() SamplerSnapshot {
	s.mu.Lock()
	n := int(s.count)
	if n > ringSize {
		n = ringSize
	}
	out := make([]cpuSample, n)
	if s.count <= ringSize {
		// Ring has not yet rolled over; entries 0..count-1 are in
		// chronological order.
		copy(out, s.ring[:n])
	} else {
		// Ring has rolled over; oldest entry is at head.
		tail := ringSize - s.head
		copy(out[:tail], s.ring[s.head:])
		copy(out[tail:], s.ring[:s.head])
	}
	s.mu.Unlock()
	return SamplerSnapshot{Samples: out, Now: time.Now()}
}

// computeCPUWindows returns per-core Daemon CPU% and per-worker-average
// Worker thread CPU% for the three windows, plus parallel validity
// flags. A window is valid iff the snapshot is fresh and contains a
// sample with wall ≤ newest.wall − W. Worker windows also require that
// no counter in the interval was held after a cached-status miss.
//
// Daemon %: (Δdaemon_cpu_ns / Δwall_ns) × 100 — per-core percent;
//
//	can exceed 100% on multi-core.
//
// Worker %: (Δworker_thread_cpu_ns / Δworker_wall_ns) × 100 —
//
//	per-worker-average OS thread CPU via CLOCK_THREAD_CPUTIME_ID.
//	Busy-poll mode can show ~100% with no traffic (not a throughput
//	signal); eBPF path has no workers so Δworker_wall_ns stays 0 and
//	the window flags as invalid. See #883 / #884 for why we don't use
//	active_ns here.
func computeCPUWindows(snap SamplerSnapshot) (
	daemonPct, workerPct [numCPUWindows]float64,
	daemonValid, workerValid [numCPUWindows]bool,
) {
	if len(snap.Samples) < 2 || cpuSnapshotStale(snap) {
		return
	}
	newest := snap.Samples[len(snap.Samples)-1]
	windows := [numCPUWindows]time.Duration{
		5 * time.Second,
		1 * time.Minute,
		5 * time.Minute,
	}
	for i, w := range windows {
		target := newest.wall.Add(-w)
		idx := findSampleAtOrBefore(snap.Samples, target)
		if idx < 0 {
			continue
		}
		then := snap.Samples[idx]
		wallDelta := newest.wall.Sub(then.wall)
		if wallDelta <= 0 {
			continue
		}
		// Guard against non-monotonic counters. A userspace-dp
		// restart can reset the cumulative series; an unchecked
		// subtract on uint64 would underflow and report a bogus rate.
		wallNs := uint64(wallDelta.Nanoseconds())
		if newest.daemonCPUNs >= then.daemonCPUNs {
			daemonDelta := newest.daemonCPUNs - then.daemonCPUNs
			daemonPct[i] = float64(daemonDelta) * 100.0 / float64(wallNs)
			daemonValid[i] = true
		}

		workerHeld := false
		for j := idx; j < len(snap.Samples); j++ {
			if snap.Samples[j].workerHeld {
				workerHeld = true
				break
			}
		}
		if !workerHeld && newest.workerWallNs > then.workerWallNs &&
			newest.workerThreadNs >= then.workerThreadNs {
			workerWallDelta := newest.workerWallNs - then.workerWallNs
			workerThreadDelta := newest.workerThreadNs - then.workerThreadNs
			workerPct[i] = float64(workerThreadDelta) * 100.0 /
				float64(workerWallDelta)
			workerValid[i] = true
		}
	}
	return
}

// cpuSnapshotStale distinguishes a sampler stall from insufficient
// history. A sample may be at most two intervals old; future or
// unclocked samples are invalid rather than trusted as current.
func cpuSnapshotStale(snap SamplerSnapshot) bool {
	if len(snap.Samples) == 0 {
		return false
	}
	if snap.Now.IsZero() {
		return true
	}
	age := snap.Now.Sub(snap.Samples[len(snap.Samples)-1].wall)
	return age < 0 || age > 2*SampleInterval
}

// findSampleAtOrBefore returns the index of the sample with the
// largest wall ≤ target, or -1 if none.  Samples is ordered
// oldest-first so we scan forward and return the last element
// that satisfies the predicate.
func findSampleAtOrBefore(samples []cpuSample, target time.Time) int {
	idx := -1
	for i := range samples {
		if samples[i].wall.After(target) {
			break
		}
		idx = i
	}
	return idx
}
