package fwdstatus

import (
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane/userspace"
)

// --- Format: label + value + order ---------------------------------

func TestFormat_LabelsAndOrderEBPF(t *testing.T) {
	fs := &ForwardingStatus{
		State:                StateOnline,
		DaemonCPUWindows:     [numCPUWindows]float64{4, 3, 2},
		DaemonCPUWindowValid: [numCPUWindows]bool{true, true, true},
		WorkerCPUMode:        CPUModeEBPFNoWorkers,
		HeapPercent:          72.0,
		HeapPercentValid:     true,
		BufferPercent:        83.0,
		BufferKnown:          true,
		Uptime:               474635 * time.Second,
	}
	out := Format(fs)
	wantLabelsInOrder := []string{
		"State",
		"Daemon CPU utilization",
		"Worker threads CPU utilization",
		"Heap utilization",
		"Buffer utilization",
		"Uptime:",
	}
	last := -1
	for _, l := range wantLabelsInOrder {
		idx := strings.Index(out, l)
		if idx < 0 {
			t.Errorf("missing label %q in output:\n%s", l, out)
			continue
		}
		if idx <= last {
			t.Errorf("label %q appeared out of order (idx=%d last=%d):\n%s", l, idx, last, out)
		}
		last = idx
	}
	if !strings.Contains(out, "Online") {
		t.Errorf("State missing: %s", out)
	}
	if !strings.Contains(out, "N/A") {
		t.Errorf("eBPF worker row should mention N/A: %s", out)
	}
	if !regexp.MustCompile(`\d+%`).MatchString(out) {
		t.Errorf("expected percentage: %s", out)
	}
}

func TestFormat_BufferUnknownUserspace(t *testing.T) {
	fs := &ForwardingStatus{
		State:                StateOnline,
		WorkerCPUMode:        CPUModeWorkers,
		WorkerCPUWindows:     [numCPUWindows]float64{45, 40, 35},
		WorkerCPUWindowValid: [numCPUWindows]bool{true, true, true},
		BufferKnown:          false,
		BufferFollowupRef:    878,
	}
	out := Format(fs)
	if !strings.Contains(out, "unknown (see #878)") {
		t.Errorf("expected unknown buffer with follow-up: %s", out)
	}
}

// BufferFollowupRef == 0 suppresses the "(see #N)" suffix — callers
// that don't have a follow-up issue shouldn't see `#0` rendered.
func TestFormat_BufferUnknownNoRef(t *testing.T) {
	fs := &ForwardingStatus{
		State:             StateOnline,
		BufferKnown:       false,
		BufferFollowupRef: 0,
	}
	out := Format(fs)
	if !regexp.MustCompile(`Buffer utilization\s+unknown$`).MatchString(strings.TrimRight(out, "\n")) &&
		!strings.Contains(out, "Buffer utilization                 unknown\n") {
		t.Errorf("expected plain 'unknown' with no #N, got: %s", out)
	}
	if strings.Contains(out, "#0") {
		t.Errorf("should not render #0: %s", out)
	}
}

func TestFormat_BufferKnownPercent(t *testing.T) {
	fs := &ForwardingStatus{
		State:         StateOnline,
		BufferKnown:   true,
		BufferPercent: 50.3,
	}
	out := Format(fs)
	if !regexp.MustCompile(`Buffer utilization\s+50 percent`).MatchString(out) {
		t.Errorf("expected buffer percent: %s", out)
	}
}

// TestFormat_NoClusterNote — fwdstatus is a pure single-block
// formatter post-#879. The cluster framing (node0:/node1: headers,
// peer block) is now composed in the gRPC handler, not here.
func TestFormat_NoClusterNote(t *testing.T) {
	fs := &ForwardingStatus{State: StateOnline}
	out := Format(fs)
	if strings.Contains(out, "peer-node rendering deferred") {
		t.Errorf("fwdstatus should no longer emit cluster note: %s", out)
	}
	if strings.Contains(out, "node0:") || strings.Contains(out, "node1:") {
		t.Errorf("fwdstatus should not render node headers: %s", out)
	}
}

func TestFormat_UptimeShape(t *testing.T) {
	fs := &ForwardingStatus{Uptime: (5*24+12)*time.Hour + 50*time.Minute + 35*time.Second}
	out := Format(fs)
	// "5 days, 12 hours, 50 minutes, 35 seconds"
	if !strings.Contains(out, "5 days, 12 hours, 50 minutes, 35 seconds") {
		t.Errorf("uptime shape wrong: %s", out)
	}
}

func TestFormat_HeapAndBufferClampButCPUDoesNot(t *testing.T) {
	fs := &ForwardingStatus{
		DaemonCPUWindows:     [numCPUWindows]float64{230.4, 230.4, 230.4}, // multi-core >100
		DaemonCPUWindowValid: [numCPUWindows]bool{true, true, true},
		WorkerCPUMode:        CPUModeWorkers,
		WorkerCPUWindows:     [numCPUWindows]float64{-3.0, -3.0, -3.0}, // negatives floor to 0
		WorkerCPUWindowValid: [numCPUWindows]bool{true, true, true},
		HeapPercent:          150.0,
		HeapPercentValid:     true,
		BufferKnown:          true,
		BufferPercent:        -5.0,
	}
	out := Format(fs)
	// 230% is honest per-core utilization — must not clamp
	if !regexp.MustCompile(`Daemon CPU utilization\s+230%\s*/\s*230%\s*/\s*230%`).MatchString(out) {
		t.Errorf("daemon CPU must not clamp to 100 (per-core): %s", out)
	}
	// negative worker CPU floors to 0
	if !regexp.MustCompile(`Worker threads CPU utilization\s+0%\s*/\s*0%\s*/\s*0%`).MatchString(out) {
		t.Errorf("expected worker CPU floored to 0: %s", out)
	}
	// 150% heap clamps to 100
	if !regexp.MustCompile(`Heap utilization\s+100 percent`).MatchString(out) {
		t.Errorf("expected heap clamped to 100: %s", out)
	}
	// -5% buffer clamps to 0
	if !regexp.MustCompile(`Buffer utilization\s+0 percent`).MatchString(out) {
		t.Errorf("expected buffer clamped to 0: %s", out)
	}
}

// --- State transitions: Build ---------------------------------------

// fakeDP is a DataPlaneAccessor for tests.  Set isUserspace=true to
// make Build treat it as userspace-dp (adds the Status method).
type fakeDP struct {
	loaded   bool
	mapStats []MapStats
}

func (f *fakeDP) IsLoaded() bool          { return f.loaded }
func (f *fakeDP) GetMapStats() []MapStats { return f.mapStats }

type fakeUserspaceDP struct {
	fakeDP
	status userspace.ProcessStatus
	err    error
}

func (f *fakeUserspaceDP) Status() (userspace.ProcessStatus, error) {
	return f.status, f.err
}

// fakeProcReader injects canned /proc contents.
type fakeProcReader struct {
	selfStat     ProcSelfStat
	selfStatErr  error
	selfStatm    ProcSelfStatm
	selfStatmErr error
	stat         ProcStat
	statErr      error
	memInfo      ProcMemInfo
	memInfoErr   error
	cgroupMax    uint64
	cgroupErr    error
}

func (f *fakeProcReader) ReadSelfStat() (ProcSelfStat, error) {
	return f.selfStat, f.selfStatErr
}
func (f *fakeProcReader) ReadSelfStatm() (ProcSelfStatm, error) {
	return f.selfStatm, f.selfStatmErr
}
func (f *fakeProcReader) ReadStat() (ProcStat, error) { return f.stat, f.statErr }
func (f *fakeProcReader) ReadMemInfo() (ProcMemInfo, error) {
	return f.memInfo, f.memInfoErr
}
func (f *fakeProcReader) ReadCgroupMemoryMax() (uint64, error) {
	return f.cgroupMax, f.cgroupErr
}

// freshProcReader returns a reader that parses clean with plausible
// values: ~100s uptime, moderate CPU accumulation, 16 GiB MemTotal.
func freshProcReader() *fakeProcReader {
	now := time.Now().Unix()
	// Daemon started 100 ticks (=1s when userHZ=100) after boot, and
	// boot was now-1000s ago, so daemon has been up ~999s.
	return &fakeProcReader{
		selfStat: ProcSelfStat{
			UtimeTicks:     50,
			StimeTicks:     50,
			StartTimeTicks: 100,
		},
		stat:      ProcStat{BootTime: uint64(now - 1000)},
		selfStatm: ProcSelfStatm{ResidentPages: 10000},
		memInfo:   ProcMemInfo{MemTotalBytes: 16 * 1024 * 1024 * 1024},
	}
}

func TestBuild_Online_eBPF(t *testing.T) {
	dp := &fakeDP{loaded: true, mapStats: []MapStats{
		{MaxEntries: 100, UsedCount: 30},
	}}
	fs, err := Build(dp, freshProcReader(), time.Now(), SamplerSnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	if fs.State != StateOnline {
		t.Errorf("state: got %q, want Online", fs.State)
	}
	if fs.WorkerCPUMode != CPUModeEBPFNoWorkers {
		t.Error("eBPF path should set CPUModeEBPFNoWorkers")
	}
	if !fs.BufferKnown {
		t.Error("eBPF path: BufferKnown should be true")
	}
	if fs.BufferPercent != 30 {
		t.Errorf("Buffer%%: got %v, want 30", fs.BufferPercent)
	}
}

func TestBuild_Unknown_DpNil(t *testing.T) {
	fs, _ := Build(nil, freshProcReader(), time.Now(), SamplerSnapshot{})
	if fs.State != StateUnknown {
		t.Errorf("dp==nil: state %q, want Unknown", fs.State)
	}
}

func TestBuild_Unknown_NotLoaded(t *testing.T) {
	dp := &fakeDP{loaded: false}
	fs, _ := Build(dp, freshProcReader(), time.Now(), SamplerSnapshot{})
	if fs.State != StateUnknown {
		t.Errorf("!IsLoaded: state %q, want Unknown", fs.State)
	}
}

func TestBuild_Unknown_SelfStatErr(t *testing.T) {
	dp := &fakeDP{loaded: true}
	proc := freshProcReader()
	proc.selfStatErr = os.ErrNotExist
	fs, _ := Build(dp, proc, time.Now(), SamplerSnapshot{})
	if fs.State != StateUnknown {
		t.Errorf("selfStat err: state %q, want Unknown", fs.State)
	}
}

func TestBuild_Unknown_StatmErr(t *testing.T) {
	dp := &fakeDP{loaded: true}
	proc := freshProcReader()
	proc.selfStatmErr = os.ErrNotExist
	fs, _ := Build(dp, proc, time.Now(), SamplerSnapshot{})
	if fs.State != StateUnknown {
		t.Errorf("statm err: state %q, want Unknown", fs.State)
	}
}

func TestBuild_Unknown_UserspaceStatusErr(t *testing.T) {
	dp := &fakeUserspaceDP{
		fakeDP: fakeDP{loaded: true},
		err:    errors.New("status unavailable"),
	}
	fs, _ := Build(dp, freshProcReader(), time.Now(), SamplerSnapshot{})
	if fs.State != StateUnknown {
		t.Errorf("userspace Status err: state %q, want Unknown", fs.State)
	}
}

func TestBuild_Degraded_StaleHeartbeat(t *testing.T) {
	now := time.Now()
	dp := &fakeUserspaceDP{
		fakeDP: fakeDP{loaded: true},
		status: userspace.ProcessStatus{
			WorkerHeartbeats: []time.Time{
				now.Add(-500 * time.Millisecond),
				now.Add(-5 * time.Second), // stale
			},
		},
	}
	fs, _ := Build(dp, freshProcReader(), time.Now(), SamplerSnapshot{})
	if fs.State != StateDegraded {
		t.Errorf("stale hb: state %q, want Degraded", fs.State)
	}
}

func TestBuild_Online_UserspaceFreshHeartbeats(t *testing.T) {
	now := time.Now()
	dp := &fakeUserspaceDP{
		fakeDP: fakeDP{loaded: true},
		status: userspace.ProcessStatus{
			WorkerHeartbeats: []time.Time{
				now.Add(-100 * time.Millisecond),
				now.Add(-200 * time.Millisecond),
			},
			WorkerRuntime: []userspace.WorkerRuntimeStatus{
				{WallNS: 10_000_000_000, ThreadCPUNS: 3_000_000_000},
				{WallNS: 10_000_000_000, ThreadCPUNS: 2_000_000_000},
			},
		},
	}
	fs, _ := Build(dp, freshProcReader(), time.Now(), SamplerSnapshot{})
	if fs.State != StateOnline {
		t.Errorf("fresh hb: state %q, want Online", fs.State)
	}
	if fs.WorkerCPUMode != CPUModeWorkers {
		t.Error("userspace should set CPUModeWorkers")
	}
	// Worker CPU values now come from the sampler, not sum of
	// cumulative thread_cpu_ns at Build time. With an empty
	// SamplerSnapshot, all windows should be invalid.
	for i, v := range fs.WorkerCPUWindowValid {
		if v {
			t.Errorf("empty snapshot: WorkerCPUWindowValid[%d] should be false", i)
		}
	}
	if fs.BufferKnown {
		t.Error("userspace-dp Buffer should be unknown")
	}
	if fs.BufferFollowupRef != followupUMEMBuffer {
		t.Errorf("buffer follow-up: got %d, want %d", fs.BufferFollowupRef, followupUMEMBuffer)
	}
}

// #878 Buffer% derivation tests for the userspace-dp path. Pin the
// contract that:
//   - No bindings → BufferKnown=false (legacy "unknown" rendering).
//   - Pre-#878 helper (UmemTotalFrames=0) → still BufferKnown=false.
//   - Mixed bindings → only those with capacities count; max wins.
//   - max(umem%, tx%) per binding; max across bindings overall.

func TestBuild_UserspaceBuffer_NoBindings_StaysUnknown(t *testing.T) {
	now := time.Now()
	dp := &fakeUserspaceDP{
		fakeDP: fakeDP{loaded: true},
		status: userspace.ProcessStatus{
			WorkerHeartbeats: []time.Time{now.Add(-100 * time.Millisecond)},
		},
	}
	fs, _ := Build(dp, freshProcReader(), time.Now(), SamplerSnapshot{})
	if fs.BufferKnown {
		t.Error("no bindings: BufferKnown must stay false")
	}
	if fs.BufferFollowupRef != followupUMEMBuffer {
		t.Errorf("no bindings: BufferFollowupRef=%d, want %d", fs.BufferFollowupRef, followupUMEMBuffer)
	}
}

func TestBuild_UserspaceBuffer_PreHelper_StaysUnknown(t *testing.T) {
	now := time.Now()
	dp := &fakeUserspaceDP{
		fakeDP: fakeDP{loaded: true},
		status: userspace.ProcessStatus{
			WorkerHeartbeats: []time.Time{now.Add(-100 * time.Millisecond)},
			Bindings: []userspace.BindingStatus{
				// Pre-#878 helper: capacities zero. Even with
				// nonzero OutstandingTX, must stay unknown.
				{UmemTotalFrames: 0, TxRingCapacity: 0, OutstandingTX: 100},
			},
		},
	}
	fs, _ := Build(dp, freshProcReader(), time.Now(), SamplerSnapshot{})
	if fs.BufferKnown {
		t.Error("pre-#878 helper: BufferKnown must stay false")
	}
}

func TestBuild_UserspaceBuffer_UMEMHeavy(t *testing.T) {
	now := time.Now()
	dp := &fakeUserspaceDP{
		fakeDP: fakeDP{loaded: true},
		status: userspace.ProcessStatus{
			WorkerHeartbeats: []time.Time{now.Add(-100 * time.Millisecond)},
			Bindings: []userspace.BindingStatus{
				// UMEM 80%, TX 5% → max = 80.
				{UmemTotalFrames: 1000, UmemInflightFrames: 800, TxRingCapacity: 200, OutstandingTX: 10},
			},
		},
	}
	fs, _ := Build(dp, freshProcReader(), time.Now(), SamplerSnapshot{})
	if !fs.BufferKnown {
		t.Fatal("BufferKnown must be true")
	}
	if fs.BufferFollowupRef != 0 {
		t.Errorf("BufferFollowupRef=%d, want 0 once known", fs.BufferFollowupRef)
	}
	if fs.BufferPercent != 80.0 {
		t.Errorf("BufferPercent=%v, want 80", fs.BufferPercent)
	}
}

func TestBuild_UserspaceBuffer_TXHeavy(t *testing.T) {
	now := time.Now()
	dp := &fakeUserspaceDP{
		fakeDP: fakeDP{loaded: true},
		status: userspace.ProcessStatus{
			WorkerHeartbeats: []time.Time{now.Add(-100 * time.Millisecond)},
			Bindings: []userspace.BindingStatus{
				// UMEM 10%, TX 90% → max = 90.
				{UmemTotalFrames: 1000, UmemInflightFrames: 100, TxRingCapacity: 100, OutstandingTX: 90},
			},
		},
	}
	fs, _ := Build(dp, freshProcReader(), time.Now(), SamplerSnapshot{})
	if !fs.BufferKnown {
		t.Fatal("BufferKnown must be true")
	}
	if fs.BufferPercent != 90.0 {
		t.Errorf("BufferPercent=%v, want 90", fs.BufferPercent)
	}
}

func TestBuild_UserspaceBuffer_MaxAcrossBindings(t *testing.T) {
	now := time.Now()
	dp := &fakeUserspaceDP{
		fakeDP: fakeDP{loaded: true},
		status: userspace.ProcessStatus{
			WorkerHeartbeats: []time.Time{now.Add(-100 * time.Millisecond)},
			Bindings: []userspace.BindingStatus{
				{UmemTotalFrames: 1000, UmemInflightFrames: 100, TxRingCapacity: 100, OutstandingTX: 10}, // 10%
				{UmemTotalFrames: 1000, UmemInflightFrames: 750, TxRingCapacity: 100, OutstandingTX: 20}, // 75%
				{UmemTotalFrames: 1000, UmemInflightFrames: 50, TxRingCapacity: 100, OutstandingTX: 5},   // 5%
			},
		},
	}
	fs, _ := Build(dp, freshProcReader(), time.Now(), SamplerSnapshot{})
	if !fs.BufferKnown {
		t.Fatal("BufferKnown must be true")
	}
	if fs.BufferPercent != 75.0 {
		t.Errorf("BufferPercent=%v, want 75 (max across bindings)", fs.BufferPercent)
	}
}

func TestBuild_UserspaceBuffer_MixedKnownAndUnknown(t *testing.T) {
	now := time.Now()
	dp := &fakeUserspaceDP{
		fakeDP: fakeDP{loaded: true},
		status: userspace.ProcessStatus{
			WorkerHeartbeats: []time.Time{now.Add(-100 * time.Millisecond)},
			Bindings: []userspace.BindingStatus{
				// Skipped (UmemTotalFrames=0).
				{UmemTotalFrames: 0, OutstandingTX: 999},
				// Counted: 50%.
				{UmemTotalFrames: 200, UmemInflightFrames: 100, TxRingCapacity: 100, OutstandingTX: 30},
			},
		},
	}
	fs, _ := Build(dp, freshProcReader(), time.Now(), SamplerSnapshot{})
	if !fs.BufferKnown {
		t.Fatal("at least one binding has capacities; BufferKnown must be true")
	}
	if fs.BufferPercent != 50.0 {
		t.Errorf("BufferPercent=%v, want 50 (only the binding with capacities counts)", fs.BufferPercent)
	}
}

func TestBuild_UserspaceBuffer_ClampedTo100(t *testing.T) {
	now := time.Now()
	dp := &fakeUserspaceDP{
		fakeDP: fakeDP{loaded: true},
		status: userspace.ProcessStatus{
			WorkerHeartbeats: []time.Time{now.Add(-100 * time.Millisecond)},
			Bindings: []userspace.BindingStatus{
				// Pathological: OutstandingTX > capacity (cross-field tearing or bug).
				{UmemTotalFrames: 100, UmemInflightFrames: 50, TxRingCapacity: 100, OutstandingTX: 200},
			},
		},
	}
	fs, _ := Build(dp, freshProcReader(), time.Now(), SamplerSnapshot{})
	if !fs.BufferKnown {
		t.Fatal("BufferKnown must be true")
	}
	if fs.BufferPercent != 100.0 {
		t.Errorf("BufferPercent=%v, want 100 (clamped)", fs.BufferPercent)
	}
}

// #4875: Online requires positive, in-window heartbeat evidence.  An
// empty heartbeat set (worker startup / wire-version drift omitting the
// field) and a future-dated heartbeat (malformed clock conversion) must
// NOT read as Online — both were previously treated as "trivially
// fresh" and fell straight through to Online (false-green).

func TestBuild_Degraded_EmptyHeartbeats(t *testing.T) {
	dp := &fakeUserspaceDP{
		fakeDP: fakeDP{loaded: true},
		status: userspace.ProcessStatus{
			// No heartbeats published yet.
			WorkerHeartbeats: []time.Time{},
		},
	}
	fs, _ := Build(dp, freshProcReader(), time.Now(), SamplerSnapshot{})
	if fs.State == StateOnline {
		t.Errorf("empty heartbeats: state %q, must not be Online", fs.State)
	}
	if fs.State != StateDegraded {
		t.Errorf("empty heartbeats: state %q, want Degraded", fs.State)
	}
}

func TestBuild_Degraded_NilHeartbeats(t *testing.T) {
	dp := &fakeUserspaceDP{
		fakeDP: fakeDP{loaded: true},
		// WorkerHeartbeats field omitted entirely (nil slice).
		status: userspace.ProcessStatus{},
	}
	fs, _ := Build(dp, freshProcReader(), time.Now(), SamplerSnapshot{})
	if fs.State == StateOnline {
		t.Errorf("nil heartbeats: state %q, must not be Online", fs.State)
	}
	if fs.State != StateDegraded {
		t.Errorf("nil heartbeats: state %q, want Degraded", fs.State)
	}
}

func TestBuild_Degraded_FutureHeartbeat(t *testing.T) {
	now := time.Now()
	dp := &fakeUserspaceDP{
		fakeDP: fakeDP{loaded: true},
		status: userspace.ProcessStatus{
			WorkerHeartbeats: []time.Time{
				now.Add(-100 * time.Millisecond),
				now.Add(30 * time.Second), // malformed/future conversion
			},
		},
	}
	fs, _ := Build(dp, freshProcReader(), time.Now(), SamplerSnapshot{})
	if fs.State == StateOnline {
		t.Errorf("future heartbeat: state %q, must not be Online", fs.State)
	}
	if fs.State != StateDegraded {
		t.Errorf("future heartbeat: state %q, want Degraded", fs.State)
	}
}

func TestHeartbeatsHealthy(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cases := []struct {
		name string
		hbs  []time.Time
		want bool
	}{
		{"nil", nil, false},
		{"empty", []time.Time{}, false},
		{"one-fresh", []time.Time{now.Add(-100 * time.Millisecond)}, true},
		{"all-fresh", []time.Time{now.Add(-100 * time.Millisecond), now.Add(-1 * time.Second)}, true},
		{"one-stale", []time.Time{now.Add(-100 * time.Millisecond), now.Add(-5 * time.Second)}, false},
		{"boundary-eq-maxage", []time.Time{now.Add(-2 * time.Second)}, true},
		{"future", []time.Time{now.Add(1 * time.Second)}, false},
		{"future-among-fresh", []time.Time{now.Add(-100 * time.Millisecond), now.Add(500 * time.Millisecond)}, false},
	}
	for _, tc := range cases {
		if got := heartbeatsHealthy(tc.hbs, now, 2*time.Second); got != tc.want {
			t.Errorf("%s: heartbeatsHealthy=%v, want %v", tc.name, got, tc.want)
		}
	}
}

// (Cluster-mode rendering moved to the gRPC handler in #879;
// fwdstatus.Build no longer takes a clusterMode flag. Cluster
// composition tests live in pkg/grpcapi/.)

// --- #7250: the helper crash/restart block ---------------------------
//
// #5838's last acceptance bullet asked operational status to expose exit
// code/signal, restart count, timestamps, backoff deadline and a crash-loop
// verdict. Before this, a crash-looping helper rendered as `State  Unknown`
// and nothing else, because `resetAfterHelperGoneLocked` clears the cached
// ProcessStatus and every surface degraded to a generic "unavailable".

// fakeCrashDP is a userspace dataplane that also answers the #7250 crash
// accessor. Separate from fakeUserspaceDP so the cells below can assert what
// Build does when the accessor is ABSENT — which is what every pre-#7250
// implementor looks like, and what the eBPF path looks like today.
type fakeCrashDP struct {
	fakeUserspaceDP
	rec   userspace.HelperCrashRecord
	known bool
}

func (f *fakeCrashDP) HelperCrashState() (userspace.HelperCrashRecord, bool) {
	return f.rec, f.known
}

// crashBuild runs Build against a helper whose Status() errors, which is the
// real post-crash shape: the supervisor clears the cached status, so a crash
// and a "helper never started" look identical to every other surface.
func crashBuild(t *testing.T, dp DataPlaneAccessor) *ForwardingStatus {
	t.Helper()
	fs, err := Build(dp, freshProcReader(), time.Now(), SamplerSnapshot{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return fs
}

func TestHelperCrashBlockIsRenderedWhenTheHelperCrashed7250(t *testing.T) {
	now := time.Now()
	dp := &fakeCrashDP{
		fakeUserspaceDP: fakeUserspaceDP{
			fakeDP: fakeDP{loaded: true},
			err:    errors.New("userspace dataplane helper not running"),
		},
		known: true,
		rec: userspace.HelperCrashRecord{
			LastExitWasCrash: true,
			RestartPending:   true,
			Detail:           "exit status 101",
			ExitCode:         101,
			PID:              4242,
			At:               now.Add(-30 * time.Second),
			Restarts:         3,
			NextRestart:      now.Add(4 * time.Second),
		},
	}
	fs := crashBuild(t, dp)

	// Build must carry the record across. Asserted separately from the render
	// so a failure says which half broke.
	if !fs.HelperCrashKnown {
		t.Fatal("Build did not consult the crash accessor; the block cannot render")
	}
	if fs.HelperExitCode != 101 || fs.HelperRestarts != 3 || fs.HelperPID != 4242 {
		t.Errorf("Build dropped crash fields: %+v", fs)
	}

	out := Format(fs)
	for _, want := range []string{
		"Helper",
		"restart pending",
		"Helper exit code",
		"101",
		"Helper last PID",
		"4242",
		"Helper restart attempts",
		"Helper next restart",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("crash render is missing %q.\n--- got ---\n%s", want, out)
		}
	}
	// The whole point: this is the surface whose ONLY output during a crash
	// loop used to be `State  Unknown`.
	if !strings.Contains(out, "State") {
		t.Error("State row vanished")
	}
}

// The zero-value trap. A never-crashed HelperCrashRecord is byte-identical to a
// healthy one AND has ExitCode == 0, which satisfies the `ExitCode >= 0`
// discriminator — so a renderer keyed on the record alone prints "exit code 0"
// for a helper that never crashed. This is the same hazard BufferKnown exists
// for, and it is why HelperCrashKnown is not redundant with LastExitWasCrash.
func TestHealthyHelperRendersNoCrashBlockAndNoExitCodeZero7250(t *testing.T) {
	dp := &fakeCrashDP{
		fakeUserspaceDP: fakeUserspaceDP{fakeDP: fakeDP{loaded: true}},
		known:           true,
		rec:             userspace.HelperCrashRecord{}, // never crashed
	}
	out := Format(crashBuild(t, dp))

	if strings.Contains(out, "Helper exit code") {
		t.Errorf("a helper that never crashed rendered an exit code — ExitCode 0 "+
			"satisfies the `ExitCode >= 0` discriminator, so the block must gate on "+
			"the record being an actual crash.\n--- got ---\n%s", out)
	}
	if strings.Contains(out, "Helper restart attempts") {
		t.Errorf("healthy helper rendered a restart row.\n--- got ---\n%s", out)
	}
	if strings.Contains(out, "CRASH LOOPING") {
		t.Errorf("healthy helper rendered a crash-loop verdict.\n--- got ---\n%s", out)
	}
}

// An unreachable manager must not render as a healthy helper. `known=false`
// carries "could not ask", which is NOT a claim that the helper is well.
func TestUnknownCrashStateRendersNothingRatherThanHealth7250(t *testing.T) {
	dp := &fakeCrashDP{
		fakeUserspaceDP: fakeUserspaceDP{fakeDP: fakeDP{loaded: true}},
		known:           false,
		// A populated record that must NOT leak through the known=false gate.
		rec: userspace.HelperCrashRecord{LastExitWasCrash: true, Restarts: 9, PID: 77},
	}
	fs := crashBuild(t, dp)
	if fs.HelperCrashKnown {
		t.Error("known=false leaked through as HelperCrashKnown")
	}
	out := Format(fs)
	if strings.Contains(out, "77") || strings.Contains(out, "Helper restart attempts") {
		t.Errorf("a record the accessor refused to vouch for was rendered anyway.\n"+
			"--- got ---\n%s", out)
	}
}

// Format is EXPORTED and takes a flat struct, so it must be correct for any
// ForwardingStatus it is handed — not only for one Build produced.
//
// This cell exists because a mutation ESCAPED without it. Deleting
// `if !fs.HelperCrashKnown { return }` from writeHelperCrash left the whole
// suite green, because every other cell reaches that gate THROUGH Build, and
// Build never populates LastExitWasCrash/RestartPending unless known is true —
// so the renderer's second gate absorbed the mutation and the first one was
// never actually bound. The record fields are set here directly, which is the
// only way to reach the site the production path sanitizes on the way in.
func TestFormatDoesNotRenderAnUnvouchedRecordEvenIfPopulated7250(t *testing.T) {
	fs := &ForwardingStatus{
		State:            StateUnknown,
		HelperCrashKnown: false, // "could not ask" — NOT a claim of health
		// Populated as if a crash had been recorded. A caller that set these
		// without vouching for them must not get a crash render.
		LastExitWasCrash:  true,
		RestartPending:    true,
		HelperExitCode:    101,
		HelperPID:         4242,
		HelperRestarts:    3,
		HelperNextRestart: time.Now().Add(time.Second),
	}
	out := Format(fs)
	for _, unwanted := range []string{
		"Helper exit code", "4242", "Helper restart attempts",
		"Helper next restart", "restart pending",
	} {
		if strings.Contains(out, unwanted) {
			t.Errorf("Format rendered %q from a record the caller did not vouch for "+
				"(HelperCrashKnown=false). The renderer must gate on that flag itself; "+
				"relying on Build to sanitize leaves Format wrong for every other "+
				"caller.\n--- got ---\n%s", unwanted, out)
		}
	}
}

// A dataplane with no crash accessor at all — every pre-#7250 implementor, and
// the eBPF path. Build must not panic and must not invent a crash.
func TestDataPlaneWithoutTheCrashAccessorIsTolerated7250(t *testing.T) {
	dp := &fakeUserspaceDP{fakeDP: fakeDP{loaded: true}}
	fs := crashBuild(t, dp)
	if fs.HelperCrashKnown {
		t.Error("a dataplane with no HelperCrashState method reported a known crash state")
	}
	if strings.Contains(Format(fs), "Helper restart attempts") {
		t.Error("crash block rendered for a dataplane that cannot report one")
	}
}

// The conflation the #7250 data half removed from the DATA must not be
// reintroduced at the SURFACE. After an intentional stop LastExitWasCrash is
// still true (the retry path reads it as debt) and Restarts survives with it,
// so CrashLooping() keeps reporting "not coming back" while NO retry is armed.
// The render must not promise a restart, and must not show a deadline that has
// no timer behind it.
func TestStoppedHelperIsNotRenderedAsRestartPending7250(t *testing.T) {
	now := time.Now()
	dp := &fakeCrashDP{
		fakeUserspaceDP: fakeUserspaceDP{
			fakeDP: fakeDP{loaded: true},
			err:    errors.New("userspace dataplane helper not running"),
		},
		known: true,
		rec: userspace.HelperCrashRecord{
			LastExitWasCrash: true,
			RestartPending:   false,                 // stop advanced procGen; timer orphaned
			Restarts:         12,                    // deep enough that CrashLooping() is true
			NextRestart:      now.Add(-time.Minute), // in the PAST, no timer behind it
			ExitCode:         101,
		},
	}
	fs := crashBuild(t, dp)

	// Precondition: without this the assertions below could pass on a record
	// that never reported crash-looping in the first place.
	if !fs.HelperCrashLooping {
		t.Fatalf("precondition: Restarts=%d must put CrashLooping() at the backoff cap; "+
			"got HelperCrashLooping=false", fs.HelperRestarts)
	}

	out := Format(fs)
	if strings.Contains(out, "restart pending") {
		t.Errorf("a helper with no armed retry was rendered as restart-pending — this is "+
			"the LastExitWasCrash/RestartPending conflation #7958 removed from the data, "+
			"reintroduced at the surface.\n--- got ---\n%s", out)
	}
	if strings.Contains(out, "Helper next restart") {
		t.Errorf("rendered a restart deadline with no timer behind it; after an "+
			"intentional stop NextRestart is a time in the past.\n--- got ---\n%s", out)
	}
	if !strings.Contains(out, "no restart armed") {
		t.Errorf("the render must SAY that no retry is armed rather than staying "+
			"silent about it.\n--- got ---\n%s", out)
	}
	// The HEADLINE must be "stopped", not the loop verdict. An operator reads
	// the first line and acts on it, and "CRASH LOOPING" here sends them
	// hunting a crash that is not currently happening.
	if strings.Contains(out, "CRASH LOOPING") {
		t.Errorf("a stopped helper was headlined as CRASH LOOPING. The loop predicate "+
			"is true here (backoff is at the cap and LastExitWasCrash survives a stop), "+
			"but the actionable fact is that nothing is retrying.\n--- got ---\n%s", out)
	}
	if !strings.Contains(out, "stopped") {
		t.Errorf("a helper with no armed retry must be headlined as stopped.\n"+
			"--- got ---\n%s", out)
	}
	// The loop history is still worth carrying, subordinate to the headline.
	if !strings.Contains(out, "after a crash loop") {
		t.Errorf("the crash-loop history was dropped entirely; it is subordinate "+
			"detail, not noise.\n--- got ---\n%s", out)
	}
}

// #5838's "crash-loop reason", satisfied BY DERIVATION rather than by a stored
// string: CrashLooping() is `LastExitWasCrash && helperRestartDelay(Restarts)
// >= helperRestartBackoffMax`, so the reason is determined by the restart count
// plus the schedule reaching its ceiling — both already on the struct. A
// derived reason cannot drift from the predicate it explains.
func TestCrashLoopReasonIsDerivedFromTheRestartCount7250(t *testing.T) {
	now := time.Now()
	dp := &fakeCrashDP{
		fakeUserspaceDP: fakeUserspaceDP{
			fakeDP: fakeDP{loaded: true},
			err:    errors.New("helper not running"),
		},
		known: true,
		rec: userspace.HelperCrashRecord{
			LastExitWasCrash: true,
			RestartPending:   true,
			Restarts:         9,
			ExitCode:         101,
			NextRestart:      now.Add(time.Minute),
		},
	}
	fs := crashBuild(t, dp)
	if !fs.HelperCrashLooping {
		t.Fatalf("precondition: Restarts=9 must reach the backoff cap")
	}
	out := Format(fs)
	if !strings.Contains(out, "Helper crash-loop reason") {
		t.Errorf("no crash-loop reason rendered.\n--- got ---\n%s", out)
	}
	// The COUNT must appear: that is the input the derivation is built from,
	// and a hardcoded sentence would pass a mere "reason row exists" check.
	if !strings.Contains(out, "9 restarts") {
		t.Errorf("the reason must name the restart count it was derived from, so an "+
			"operator can see WHY the verdict fired rather than being asserted at.\n"+
			"--- got ---\n%s", out)
	}

	// And it must NOT appear when the helper is not looping — otherwise the
	// row is decoration rather than a verdict.
	quiet := &fakeCrashDP{
		fakeUserspaceDP: fakeUserspaceDP{
			fakeDP: fakeDP{loaded: true},
			err:    errors.New("helper not running"),
		},
		known: true,
		rec: userspace.HelperCrashRecord{
			LastExitWasCrash: true, RestartPending: true, Restarts: 1, ExitCode: 101,
		},
	}
	qfs := crashBuild(t, quiet)
	if qfs.HelperCrashLooping {
		t.Fatalf("precondition: Restarts=1 must NOT reach the backoff cap")
	}
	if strings.Contains(Format(qfs), "crash-loop reason") {
		t.Error("a crash-loop reason was rendered for a helper that is not looping")
	}
}

// THE MIDDLE ROW. A healthy box and an `exit status 101` crash are the two
// ends, and a two-row table passes against a total flip of the discriminator.
// The fixture that actually separates "keyed on the crash flag" from "keyed on
// the exit code being non-zero" is a GENUINE crash whose exit code is 0.
func TestAGenuineCrashWithExitCodeZeroStillRenders7250(t *testing.T) {
	dp := &fakeCrashDP{
		fakeUserspaceDP: fakeUserspaceDP{
			fakeDP: fakeDP{loaded: true},
			err:    errors.New("helper not running"),
		},
		known: true,
		rec: userspace.HelperCrashRecord{
			LastExitWasCrash: true,
			RestartPending:   true,
			ExitCode:         0, // the helper exited 0 when it should not have
			Detail:           "exit status 0",
			PID:              4242,
			Restarts:         1,
		},
	}
	out := Format(crashBuild(t, dp))
	if !strings.Contains(out, "Helper exit code") {
		t.Errorf("a real crash with exit code 0 rendered NO exit code row. The row must "+
			"be gated on the crash being real, not on the code being non-zero — an "+
			"unexpected clean exit is still an unexpected exit.\n--- got ---\n%s", out)
	}
	if !strings.Contains(out, "restart pending") {
		t.Errorf("a real crash with exit code 0 was not reported as a crash at all.\n"+
			"--- got ---\n%s", out)
	}
}

// Signal is the discriminator: exactly one of ExitCode >= 0 and Signal != "" is
// meaningful, and ExitCode is -1 when the child was signalled. Rendering both
// would print "exit code -1" beside a signal name.
func TestSignalAndExitCodeAreRenderedExclusively7250(t *testing.T) {
	base := func(rec userspace.HelperCrashRecord) string {
		dp := &fakeCrashDP{
			fakeUserspaceDP: fakeUserspaceDP{
				fakeDP: fakeDP{loaded: true},
				err:    errors.New("helper not running"),
			},
			known: true,
			rec:   rec,
		}
		return Format(crashBuild(t, dp))
	}

	signalled := base(userspace.HelperCrashRecord{
		LastExitWasCrash: true, RestartPending: true,
		Signal: "killed", ExitCode: -1, Restarts: 1,
	})
	if !strings.Contains(signalled, "Helper exit signal") || !strings.Contains(signalled, "killed") {
		t.Errorf("signalled exit did not render the signal.\n--- got ---\n%s", signalled)
	}
	if strings.Contains(signalled, "Helper exit code") {
		t.Errorf("signalled exit ALSO rendered an exit code; ExitCode is -1 here, so the "+
			"row would read \"exit code -1\".\n--- got ---\n%s", signalled)
	}

	// The `else` in the render is only OBSERVABLE when both fields are set at
	// once — and the producer never does that (`exitCodeAndSignal` returns
	// (-1, sig) or (code, "")), so the two cells above pass identically with
	// the discriminator removed. A second escaped mutation found exactly that:
	// the fixtures used the values production emits, so the guard they were
	// written for was never exercised.
	//
	// Format is exported and takes a flat struct, so it owes a defined answer
	// for a state its usual producer cannot construct. Signal wins.
	both := Format(&ForwardingStatus{
		State:            StateUnknown,
		HelperCrashKnown: true,
		LastExitWasCrash: true,
		RestartPending:   true,
		HelperSignal:     "killed",
		HelperExitCode:   101, // contradictory on purpose
		HelperRestarts:   1,
	})
	if !strings.Contains(both, "Helper exit signal") {
		t.Errorf("signal must win when both are set.\n--- got ---\n%s", both)
	}
	if strings.Contains(both, "Helper exit code") {
		t.Errorf("both an exit signal and an exit code were rendered. Signal is the "+
			"discriminator — exactly one of the two is meaningful — so rendering both "+
			"tells an operator the helper did two contradictory things.\n--- got ---\n%s", both)
	}

	exited := base(userspace.HelperCrashRecord{
		LastExitWasCrash: true, RestartPending: true,
		ExitCode: 101, Restarts: 1,
	})
	if !strings.Contains(exited, "Helper exit code") || !strings.Contains(exited, "101") {
		t.Errorf("exited helper did not render the exit code.\n--- got ---\n%s", exited)
	}
	if strings.Contains(exited, "Helper exit signal") {
		t.Errorf("exited helper rendered a signal row.\n--- got ---\n%s", exited)
	}
}
