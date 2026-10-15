package fwdstatus

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #13237 (D5-08): a helper restart mid-window resets cumulative worker
// counters. Even when newest counters exceed the window-start counters,
// subtracting across lifetimes produces bogus worker utilization.
func TestComputeCPUWindows_MidWindowCounterReset(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	const s = uint64(1_000_000_000)
	snap := SamplerSnapshot{Now: now, Samples: []cpuSample{
		{wall: now.Add(-60 * time.Second), daemonCPUNs: 50 * s, workerThreadNs: 50 * s, workerWallNs: 100 * s},
		{wall: now.Add(-30 * time.Second), daemonCPUNs: 75 * s, workerThreadNs: 1 * s, workerWallNs: 2 * s},
		{wall: now, daemonCPUNs: 100 * s, workerThreadNs: 90 * s, workerWallNs: 101 * s},
	}}
	_, wPct, dValid, wValid := computeCPUWindows(snap)
	if !dValid[CPUWindow1m] {
		t.Error("daemon 1m stays valid: daemon counters are monotonic across the window")
	}
	if wValid[CPUWindow1m] {
		t.Errorf("worker 1m must be invalid across mid-window reset, got %.1f%%", wPct[CPUWindow1m])
	}
	if row := formatWindowRow(wPct, wValid, true); strings.Contains(row, "4000%") {
		t.Errorf("rendered worker row must not show cross-reset percentage: %q", row)
	}
}
func TestFormatWindowRow_ClampWorkerNotDaemon(t *testing.T) {
	valid := [numCPUWindows]bool{true, false, false}
	worker := formatWindowRow([numCPUWindows]float64{150, 0, 0}, valid, true)
	if strings.Contains(worker, "150%") {
		t.Errorf("worker row rendered >100%% verbatim: %q", worker)
	}
	daemon := formatWindowRow([numCPUWindows]float64{250, 0, 0}, valid, false)
	if !strings.Contains(daemon, "250%") {
		t.Errorf("daemon per-core row must keep >100%% values: %q", daemon)
	}
}

func TestComputeCPUWindows_MidWindowDaemonReset(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	const s = uint64(1_000_000_000)
	snap := SamplerSnapshot{Now: now, Samples: []cpuSample{
		{wall: now.Add(-60 * time.Second), daemonCPUNs: 50 * s, workerThreadNs: 10 * s, workerWallNs: 100 * s},
		{wall: now.Add(-30 * time.Second), daemonCPUNs: 5 * s, workerThreadNs: 20 * s, workerWallNs: 130 * s},
		{wall: now, daemonCPUNs: 80 * s, workerThreadNs: 40 * s, workerWallNs: 160 * s},
	}}
	dPct, _, dValid, _ := computeCPUWindows(snap)
	if dValid[CPUWindow1m] {
		t.Errorf("daemon 1m must be invalid across mid-window decrease, got %.1f%%", dPct[CPUWindow1m])
	}
}

// Concurrent sample() calls must protect lastWorker* state with s.mu.
type interleavedCacheProvider struct {
	calls   int32
	entered chan struct{}
	release chan struct{}
	status  userspace.ProcessStatus
}

func (p *interleavedCacheProvider) CachedStatus() (userspace.ProcessStatus, bool) {
	if atomic.AddInt32(&p.calls, 1) == 1 {
		close(p.entered)
		<-p.release
		return userspace.ProcessStatus{}, false
	}
	return p.status, true
}

// A cache miss must load the saved counters only after acquiring the final
// lock. Otherwise a delayed miss can overwrite newer counters committed by
// another sample call while the miss is blocked in CachedStatus().
func TestSamplerCacheMissDoesNotRollbackCounters(t *testing.T) {
	now := time.Now()
	provider := &interleavedCacheProvider{
		entered: make(chan struct{}),
		release: make(chan struct{}),
		status: userspace.ProcessStatus{
			WorkerRuntime: []userspace.WorkerRuntimeStatus{
				{ThreadCPUNS: 700, WallNS: 900},
			},
		},
	}
	s := NewSampler(provider, fixedProcReader{})
	missDone := make(chan struct{})
	go func() {
		s.sample(now)
		close(missDone)
	}()

	<-provider.entered
	s.sample(now.Add(time.Second))
	close(provider.release)
	<-missDone

	snap := s.Snapshot()
	if got := snap.Samples[len(snap.Samples)-1]; got.workerThreadNs != 700 || got.workerWallNs != 900 {
		t.Errorf("delayed cache miss appended stale worker counters %d/%d; want latest 700/900",
			got.workerThreadNs, got.workerWallNs)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastWorkerThread != 700 || s.lastWorkerWall != 900 {
		t.Errorf("delayed cache miss rolled back saved counters to %d/%d; want 700/900",
			s.lastWorkerThread, s.lastWorkerWall)
	}
}
func TestSamplerConcurrentSampleRaceFree(t *testing.T) {
	s := NewSampler(nil, fixedProcReader{})
	base := time.Now()
	var wg sync.WaitGroup
	for worker := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 200 {
				s.sample(base.Add(time.Duration(worker*200+i) * time.Second))
				_ = s.Snapshot()
			}
		}()
	}
	wg.Wait()
}
