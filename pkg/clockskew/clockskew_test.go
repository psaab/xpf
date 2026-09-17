package clockskew

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// emitRec is a thread-safe recorder for emitted syslog lines, used as the
// mutation seam: if the emit call is removed from a transition path, the
// corresponding assertion fails. Mirrors natpoolalarm_test.go.
type emitRec struct {
	mu    sync.Mutex
	lines []recLine
}

type recLine struct {
	sev int
	msg string
}

func (r *emitRec) emit(sev int, msg string) {
	r.mu.Lock()
	r.lines = append(r.lines, recLine{sev: sev, msg: msg})
	r.mu.Unlock()
}

func (r *emitRec) snapshot() []recLine {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]recLine, len(r.lines))
	copy(out, r.lines)
	return out
}

func (r *emitRec) reset() {
	r.mu.Lock()
	r.lines = nil
	r.mu.Unlock()
}

func countMatch(lines []recLine, substr string) int {
	n := 0
	for _, l := range lines {
		if strings.Contains(l.msg, substr) {
			n++
		}
	}
	return n
}

const (
	raisedTag10025  = "CLOCK_SKEW_ALARM_RAISED"
	clearedTag10025 = "CLOCK_SKEW_ALARM_CLEARED"
)

// sampleBox is the mocked time source: tests script the reference-clock
// readings the sampler returns between evaluate() calls. Nothing here touches
// the machine clock. Mirrors natpoolalarm's viewBox.
type sampleBox struct {
	mu sync.Mutex
	s  Sample
}

func (b *sampleBox) set(s Sample) {
	b.mu.Lock()
	b.s = s
	b.mu.Unlock()
}

func (b *sampleBox) get() Sample {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.s
}

func healthySample() Sample {
	return Sample{
		Available:      true,
		Cluster:        true,
		NTPConfigured:  true,
		ReferenceKnown: true,
		Synced:         true,
		HaveOffset:     true,
		OffsetSecs:     0.001,
	}
}

func newSkewMon() (*Monitor, *emitRec, *sampleBox) {
	rec := &emitRec{}
	sb := &sampleBox{}
	sb.set(healthySample())
	return New(func(context.Context) Sample { return sb.get() }, rec.emit), rec, sb
}

// TestHealthyClockStaysSilent10025: a clustered node tightly synced to its NTP
// reference raises nothing. The default scripted sample is exactly that.
func TestHealthyClockStaysSilent10025(t *testing.T) {
	m, rec, _ := newSkewMon()
	m.evaluate()
	if alarms := m.ActiveAlarms(); len(alarms) != 0 {
		t.Fatalf("healthy clock raised %+v", alarms)
	}
	if lines := rec.snapshot(); len(lines) != 0 {
		t.Fatalf("healthy clock emitted %v", lines)
	}
}

// TestAlarmThresholdBoundary10025 pins the raise boundary at 15s of reference
// offset — with margin under the auth-break skew — and proves the alarm fires
// BEFORE fabric auth breaks: 59s of skew still verifies in the best alignment
// (windows differ by 1) and only always rejects at 60s, yet the alarm is
// already active there. The #10025 field value (125s) is the far-side anchor.
func TestAlarmThresholdBoundary10025(t *testing.T) {
	cases := []struct {
		offset     float64
		wantActive bool
		why        string
	}{
		{0, false, "a synced clock is silent"},
		{14.999, false, "just under the threshold stays silent"},
		{-14.999, false, "the threshold is on the magnitude, both signs"},
		{15.0, true, "at the threshold raises (>=)"},
		{-15.0, true, "a clock behind its reference raises too"},
		{59.0, true, "PRE-BREAK: 59s can still verify (best alignment), alarm already active"},
		{-59.0, true, "PRE-BREAK on the behind side"},
		{125.0, true, "the #10025 field skew (fw0 ~125s behind)"},
		{-125.0, true, "symmetric"},
	}
	for _, tc := range cases {
		t.Run("", func(t *testing.T) {
			m, rec, sb := newSkewMon()
			s := healthySample()
			s.OffsetSecs = tc.offset
			sb.set(s)
			m.evaluate()
			alarms := m.ActiveAlarms()
			if active := len(alarms) == 1; active != tc.wantActive {
				t.Fatalf("offset %gs: active=%v, want %v — %s", tc.offset, active, tc.wantActive, tc.why)
			}
			wantLines := 0
			if tc.wantActive {
				wantLines = 1
			}
			if got := countMatch(rec.snapshot(), raisedTag10025); got != wantLines {
				t.Fatalf("offset %gs: %d raise lines, want %d — %s", tc.offset, got, wantLines, tc.why)
			}
			if tc.wantActive && alarms[0].Kind != KindOffset {
				t.Fatalf("offset %gs: kind=%v, want KindOffset", tc.offset, alarms[0].Kind)
			}
		})
	}
}

// TestRaiseFiresOnce10025: a persisting over-threshold offset emits exactly one
// raise line (a transition, not a per-tick event) and keeps FirstSeen.
func TestRaiseFiresOnce10025(t *testing.T) {
	m, rec, sb := newSkewMon()
	s := healthySample()
	s.OffsetSecs = 20
	sb.set(s)
	m.evaluate()
	first := m.ActiveAlarms()
	if len(first) != 1 {
		t.Fatalf("precondition: offset 20s must raise, got %+v", first)
	}
	if first[0].FirstSeen.IsZero() {
		t.Fatal("raised alarm must carry FirstSeen")
	}
	m.evaluate()
	m.evaluate()
	if got := countMatch(rec.snapshot(), raisedTag10025); got != 1 {
		t.Fatalf("3 over-threshold ticks emitted %d raise lines, want exactly 1", got)
	}
	if again := m.ActiveAlarms(); !again[0].FirstSeen.Equal(first[0].FirstSeen) {
		t.Fatalf("FirstSeen moved %v -> %v on a persisting alarm", first[0].FirstSeen, again[0].FirstSeen)
	}
}

// TestOffsetClearHysteresis10025 keeps a raised numeric alarm active while
// the reference recovers only into the 10–15 second band, then clears below
// the lower bound. This prevents transition spam around the raise threshold.
func TestOffsetClearHysteresis10025(t *testing.T) {
	m, rec, sb := newSkewMon()
	s := healthySample()
	s.OffsetSecs = 20
	sb.set(s)
	m.evaluate()
	rec.reset()

	s.OffsetSecs = 12
	sb.set(s)
	m.evaluate()
	alarms := m.ActiveAlarms()
	if len(alarms) != 1 || alarms[0].OffsetSecs != 12 {
		t.Fatalf("hysteresis band must retain and refresh alarm, got %+v", alarms)
	}
	if got := countMatch(rec.snapshot(), clearedTag10025); got != 0 {
		t.Fatalf("hysteresis band emitted %d clear lines", got)
	}

	s.OffsetSecs = 9.999
	sb.set(s)
	m.evaluate()
	if alarms := m.ActiveAlarms(); len(alarms) != 0 {
		t.Fatalf("offset below clear threshold must clear, got %+v", alarms)
	}
	if got := countMatch(rec.snapshot(), clearedTag10025); got != 1 {
		t.Fatalf("offset below clear threshold emitted %d clear lines", got)
	}
}

// TestClearFiresOnce10025: recovery emits exactly one clear line naming the
// fresh sub-threshold sample, and later healthy ticks stay quiet.
func TestClearFiresOnce10025(t *testing.T) {
	m, rec, sb := newSkewMon()
	s := healthySample()
	s.OffsetSecs = 20
	sb.set(s)
	m.evaluate()
	if len(m.ActiveAlarms()) != 1 {
		t.Fatal("precondition: offset 20s must raise")
	}
	rec.reset()
	s.OffsetSecs = 0.002
	sb.set(s)
	m.evaluate()
	if alarms := m.ActiveAlarms(); len(alarms) != 0 {
		t.Fatalf("recovery must clear, still active: %+v", alarms)
	}
	lines := rec.snapshot()
	if got := countMatch(lines, clearedTag10025); got != 1 {
		t.Fatalf("recovery emitted %d clear lines, want 1 (%v)", got, lines)
	}
	if !strings.Contains(lines[0].msg, "0.002") {
		t.Fatalf("clear line must name the fresh sub-threshold sample: %q", lines[0].msg)
	}
	m.evaluate()
	if got := countMatch(rec.snapshot(), clearedTag10025); got != 1 {
		t.Fatalf("a second healthy tick re-emitted the clear (%d lines)", got)
	}
}

// TestUnknownSamplesHold10025: no data is not a decision. An active alarm
// survives unknown samples (sampler failure, unparseable reference), and an
// unknown sample on a fresh monitor raises nothing.
func TestUnknownSamplesHold10025(t *testing.T) {
	m, rec, sb := newSkewMon()
	s := healthySample()
	s.OffsetSecs = 20
	sb.set(s)
	m.evaluate()
	if len(m.ActiveAlarms()) != 1 {
		t.Fatal("precondition: offset 20s must raise")
	}
	// Sampler failure (no config yet, exec failed and unrecorded).
	sb.set(Sample{Available: false})
	m.evaluate()
	m.evaluate()
	if len(m.ActiveAlarms()) != 1 {
		t.Fatal("an unavailable sample must HOLD a raised alarm, not clear it")
	}
	// Reference unreadable (chronyc and timedatectl both failed).
	unknown := healthySample()
	unknown.ReferenceKnown = false
	unknown.Synced = false
	unknown.HaveOffset = false
	sb.set(unknown)
	m.evaluate()
	if len(m.ActiveAlarms()) != 1 {
		t.Fatal("an unknown reference must HOLD a raised alarm, not clear it")
	}
	if n := len(rec.snapshot()); n != 1 {
		t.Fatalf("hold ticks emitted %d lines total, want exactly the 1 raise", n)
	}

	fresh, freshRec, freshBox := newSkewMon()
	freshBox.set(Sample{Available: false})
	fresh.evaluate()
	if alarms := fresh.ActiveAlarms(); len(alarms) != 0 {
		t.Fatalf("unknown samples must not RAISE: %+v", alarms)
	}
	if lines := freshRec.snapshot(); len(lines) != 0 {
		t.Fatalf("unknown samples must not emit: %v", lines)
	}
}

// TestTimedatectlHealthyClearsQualitative10025 proves the boolean fallback can
// clear no-source/unsynchronized conditions, while it conservatively holds a
// numeric-offset alarm because timedatectl does not provide an offset.
func TestTimedatectlHealthyClearsQualitative10025(t *testing.T) {
	m, rec, sb := newSkewMon()
	unsync := Sample{
		Available: true, Cluster: true, NTPConfigured: true,
		ReferenceKnown: true, Synced: false,
	}
	sb.set(unsync)
	m.evaluate()
	if len(m.ActiveAlarms()) != 1 || m.ActiveAlarms()[0].Kind != KindUnsynced {
		t.Fatalf("precondition: unsynchronized reference must raise, got %+v", m.ActiveAlarms())
	}
	rec.reset()
	unsync.Synced = true
	sb.set(unsync)
	m.evaluate()
	if len(m.ActiveAlarms()) != 0 {
		t.Fatalf("timedatectl=yes equivalent must clear unsync, got %+v", m.ActiveAlarms())
	}
	if got := countMatch(rec.snapshot(), clearedTag10025); got != 1 {
		t.Fatalf("timedatectl=yes equivalent emitted %d clear lines", got)
	}

	noSourceMon, noSourceRec, noSourceBox := newSkewMon()
	noSource := Sample{Available: true, Cluster: true}
	noSourceBox.set(noSource)
	noSourceMon.evaluate()
	if len(noSourceMon.ActiveAlarms()) != 1 || noSourceMon.ActiveAlarms()[0].Kind != KindNoSource {
		t.Fatalf("precondition: no-source condition must raise, got %+v", noSourceMon.ActiveAlarms())
	}
	noSourceRec.reset()
	noSource.NTPConfigured = true
	noSource.ReferenceKnown = true
	noSource.Synced = true
	noSourceBox.set(noSource)
	noSourceMon.evaluate()
	if len(noSourceMon.ActiveAlarms()) != 0 {
		t.Fatalf("timedatectl=yes equivalent must clear no-source, got %+v", noSourceMon.ActiveAlarms())
	}
	if got := countMatch(noSourceRec.snapshot(), clearedTag10025); got != 1 {
		t.Fatalf("timedatectl=yes equivalent emitted %d no-source clear lines", got)
	}

	offsetMon, offsetRec, offsetBox := newSkewMon()
	offset := healthySample()
	offset.OffsetSecs = 20
	offsetBox.set(offset)
	offsetMon.evaluate()
	offsetRec.reset()
	offset.HaveOffset = false
	offsetBox.set(offset)
	offsetMon.evaluate()
	if alarms := offsetMon.ActiveAlarms(); len(alarms) != 1 || alarms[0].Kind != KindOffset {
		t.Fatalf("boolean-only healthy sample must hold numeric offset alarm, got %+v", alarms)
	}
	if got := countMatch(offsetRec.snapshot(), clearedTag10025); got != 0 {
		t.Fatalf("boolean-only healthy sample emitted %d false clear lines", got)
	}
}

// TestNoSourceRaisesWithoutReference10025 is the #10025 arm: a chassis cluster
// with no `system ntp server` has no time source by construction, so the alarm
// raises WITHOUT needing any reference reading — long before skew grows.
func TestNoSourceRaisesWithoutReference10025(t *testing.T) {
	m, rec, sb := newSkewMon()
	sb.set(Sample{Available: true, Cluster: true, NTPConfigured: false})
	m.evaluate()
	alarms := m.ActiveAlarms()
	if len(alarms) != 1 || alarms[0].Kind != KindNoSource {
		t.Fatalf("cluster with no NTP source must raise KindNoSource, got %+v", alarms)
	}
	if got := countMatch(rec.snapshot(), raisedTag10025); got != 1 {
		t.Fatalf("expected 1 raise line, got %d", got)
	}
	if !strings.Contains(alarms[0].Summary(), "no `system ntp server`") {
		t.Fatalf("summary must name the missing time source: %q", alarms[0].Summary())
	}
}

// TestUnsyncedRaises10025: NTP configured but the reference reports not
// synchronized (unreachable server, unselected source) raises.
func TestUnsyncedRaises10025(t *testing.T) {
	m, rec, sb := newSkewMon()
	s := healthySample()
	s.Synced = false
	s.HaveOffset = false
	sb.set(s)
	m.evaluate()
	alarms := m.ActiveAlarms()
	if len(alarms) != 1 || alarms[0].Kind != KindUnsynced {
		t.Fatalf("unsynchronized reference must raise KindUnsynced, got %+v", alarms)
	}
	if !strings.Contains(alarms[0].Summary(), "not synchronized") {
		t.Fatalf("summary must name the unsynchronized clock: %q", alarms[0].Summary())
	}
	if got := countMatch(rec.snapshot(), raisedTag10025); got != 1 {
		t.Fatalf("expected 1 raise line, got %d", got)
	}
}

// TestKindChangeRefreshesWithoutReemit10025: no-source -> unsynchronized ->
// offset is ONE ongoing condition ("this clock is at risk") with evolving
// detail as the operator remediates, not three alarms. The summary tracks the
// latest sample; FirstSeen and the single raise line are preserved.
func TestKindChangeRefreshesWithoutReemit10025(t *testing.T) {
	m, rec, sb := newSkewMon()
	sb.set(Sample{Available: true, Cluster: true, NTPConfigured: false})
	m.evaluate()
	first := m.ActiveAlarms()
	if len(first) != 1 || first[0].Kind != KindNoSource {
		t.Fatalf("precondition: no-source must raise, got %+v", first)
	}
	// Operator configures NTP; chrony not yet synchronized.
	s := healthySample()
	s.Synced = false
	s.HaveOffset = false
	sb.set(s)
	m.evaluate()
	// Reference syncs but the clock is still 20.5s out.
	s.Synced = true
	s.HaveOffset = true
	s.OffsetSecs = 20.5
	sb.set(s)
	m.evaluate()
	alarms := m.ActiveAlarms()
	if len(alarms) != 1 {
		t.Fatalf("kind changes must keep exactly one alarm, got %+v", alarms)
	}
	if alarms[0].Kind != KindOffset {
		t.Fatalf("latest kind must be KindOffset, got %v", alarms[0].Kind)
	}
	if !strings.Contains(alarms[0].Summary(), "20.5s ahead of") {
		t.Fatalf("summary must track the latest sample: %q", alarms[0].Summary())
	}
	if !alarms[0].FirstSeen.Equal(first[0].FirstSeen) {
		t.Fatal("FirstSeen must survive kind changes (one ongoing condition)")
	}
	if got := countMatch(rec.snapshot(), raisedTag10025); got != 1 {
		t.Fatalf("kind changes re-emitted the raise (%d lines); remediation would spam the log", got)
	}
	// Recovery still clears exactly once.
	sb.set(healthySample())
	m.evaluate()
	if len(m.ActiveAlarms()) != 0 {
		t.Fatal("recovery after kind changes must clear")
	}
	if got := countMatch(rec.snapshot(), clearedTag10025); got != 1 {
		t.Fatalf("expected 1 clear line, got %d", got)
	}
}

// TestOffsetRefreshWhileActive10025: a growing skew refreshes the displayed
// offset without re-emitting (mirrors natpoolalarm's HOLD-refresh).
func TestOffsetRefreshWhileActive10025(t *testing.T) {
	m, rec, sb := newSkewMon()
	s := healthySample()
	s.OffsetSecs = 20
	sb.set(s)
	m.evaluate()
	s.OffsetSecs = 45
	sb.set(s)
	m.evaluate()
	alarms := m.ActiveAlarms()
	if len(alarms) != 1 || alarms[0].OffsetSecs != 45 {
		t.Fatalf("held alarm must refresh to the latest offset, got %+v", alarms)
	}
	if got := countMatch(rec.snapshot(), raisedTag10025); got != 1 {
		t.Fatalf("offset growth re-emitted the raise (%d lines)", got)
	}
}

// TestStandaloneNeverRaises10025: without a chassis cluster there is no
// cross-node fabric RPC to protect, so even a huge offset stays silent — and
// de-clustering clears a raised alarm.
func TestStandaloneNeverRaises10025(t *testing.T) {
	m, rec, sb := newSkewMon()
	s := healthySample()
	s.OffsetSecs = 20
	sb.set(s)
	m.evaluate()
	if len(m.ActiveAlarms()) != 1 {
		t.Fatal("precondition: clustered offset 20s must raise")
	}
	s.Cluster = false
	sb.set(s)
	m.evaluate()
	if alarms := m.ActiveAlarms(); len(alarms) != 0 {
		t.Fatalf("de-clustering must clear, still active: %+v", alarms)
	}
	if got := countMatch(rec.snapshot(), clearedTag10025); got != 1 {
		t.Fatalf("expected 1 clear line, got %d", got)
	}

	fresh, freshRec, freshBox := newSkewMon()
	alone := healthySample()
	alone.Cluster = false
	alone.OffsetSecs = 999
	freshBox.set(alone)
	fresh.evaluate()
	if alarms := fresh.ActiveAlarms(); len(alarms) != 0 {
		t.Fatalf("standalone must never raise, got %+v", alarms)
	}
	if lines := freshRec.snapshot(); len(lines) != 0 {
		t.Fatalf("standalone must never emit: %v", lines)
	}
}

// TestSummaryText10025 pins the exact operator-facing summaries: they name the
// fault, the 15s alarm threshold, the 30s/60s auth bound, and the remedy.
func TestSummaryText10025(t *testing.T) {
	cases := []struct {
		alarm ActiveAlarm
		want  string
	}{
		{
			ActiveAlarm{Kind: KindNoSource},
			"cluster clock has no `system ntp server` time source; fabric RPC fails past 30s of inter-node skew (always past 60s) — configure `set system ntp server` on both nodes",
		},
		{
			ActiveAlarm{Kind: KindUnsynced},
			"node clock is not synchronized to its NTP reference; fabric RPC fails past 30s of inter-node skew (always past 60s) — check NTP reachability",
		},
		{
			ActiveAlarm{Kind: KindOffset, OffsetSecs: 20.5},
			"node clock is 20.5s ahead of its NTP reference (alarm at 15s; fabric RPC fails past 30-60s of inter-node skew) — check NTP",
		},
		{
			ActiveAlarm{Kind: KindOffset, OffsetSecs: -15},
			"node clock is 15s behind its NTP reference (alarm at 15s; fabric RPC fails past 30-60s of inter-node skew) — check NTP",
		},
	}
	for _, tc := range cases {
		if got := tc.alarm.Summary(); got != tc.want {
			t.Errorf("kind %v offset %g:\n got: %q\nwant: %q", tc.alarm.Kind, tc.alarm.OffsetSecs, got, tc.want)
		}
	}
}

// TestSyslogShape10025: raise/clear lines carry the raise/clear severities and
// the RT_SYSTEM shape (formatter contract, mirroring natpoolalarm's RT_NAT).
func TestSyslogShape10025(t *testing.T) {
	m, rec, sb := newSkewMon()
	s := healthySample()
	s.OffsetSecs = 20.5
	sb.set(s)
	m.evaluate()
	lines := rec.snapshot()
	if len(lines) != 1 {
		t.Fatalf("raise must emit exactly 1 line, got %v", lines)
	}
	if lines[0].sev != 4 { // RFC 3164 warning (Junos "minor"), mirroring natpoolalarm raise
		t.Fatalf("raise severity = %d, want 4", lines[0].sev)
	}
	if !strings.HasPrefix(lines[0].msg, "RT_SYSTEM - CLOCK_SKEW_ALARM_RAISED") ||
		!strings.Contains(lines[0].msg, `cause="offset"`) ||
		!strings.Contains(lines[0].msg, `detail="20.5s ahead of NTP reference"`) {
		t.Fatalf("raise line shape wrong: %q", lines[0].msg)
	}
	sb.set(healthySample())
	m.evaluate()
	lines = rec.snapshot()
	if len(lines) != 2 {
		t.Fatalf("clear must emit exactly 1 more line, got %v", lines)
	}
	if lines[1].sev != 5 { // RFC 3164 notice, mirroring natpoolalarm clear
		t.Fatalf("clear severity = %d, want 5", lines[1].sev)
	}
	if !strings.HasPrefix(lines[1].msg, "RT_SYSTEM - CLOCK_SKEW_ALARM_CLEARED") ||
		!strings.Contains(lines[1].msg, "reason=") {
		t.Fatalf("clear line shape wrong: %q", lines[1].msg)
	}
}

// TestStartStopLifecycle10025: the #4909 discipline — Stop before Start,
// double Stop, and double Start are safe; Start evaluates promptly.
func TestStartStopLifecycle10025(t *testing.T) {
	pre := New(nil, nil)
	pre.Stop() // unstarted: must return without joining anything
	pre.Stop() // idempotent
	m, rec, sb := newSkewMon()
	s := healthySample()
	s.OffsetSecs = 20
	sb.set(s)
	m.Start()
	m.Start() // second Start is a no-op, not a second goroutine
	deadline := time.Now().Add(time.Second)
	for len(m.ActiveAlarms()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(m.ActiveAlarms()) != 1 {
		t.Fatal("started monitor did not evaluate its sampler")
	}
	if got := countMatch(rec.snapshot(), raisedTag10025); got != 1 {
		t.Fatalf("double Start emitted %d raise lines, want exactly one", got)
	}
	m.Stop()
	m.Stop()
}

// TestStartEvaluatesPromptly10025: the run loop evaluates once at startup so
// an already-broken clock alarms within the first tick, not after 30s.
func TestStartEvaluatesPromptly10025(t *testing.T) {
	rec := &emitRec{}
	sb := &sampleBox{}
	s := healthySample()
	s.OffsetSecs = 40
	sb.set(s)
	m := New(func(context.Context) Sample { return sb.get() }, rec.emit)
	m.SetTickForTest(10 * time.Millisecond)
	m.Start()
	defer m.Stop()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if len(m.ActiveAlarms()) == 1 {
			break
		}
		if !time.Now().Before(deadline) {
			t.Fatal("started monitor never evaluated its sampler")
		}
		time.Sleep(time.Millisecond)
	}
	if got := countMatch(rec.snapshot(), raisedTag10025); got != 1 {
		t.Fatalf("expected 1 raise line from the prompt evaluation, got %d", got)
	}
}

// TestStopCancelsInFlightSampler10025 proves ordered shutdown does not wait
// for a sampler's full external-command timeout. The injected sampler blocks
// until the run-owned context is canceled, then returns an unknown sample.
func TestStopCancelsInFlightSampler10025(t *testing.T) {
	entered := make(chan struct{})
	canceled := make(chan struct{})
	var once sync.Once
	m := New(func(ctx context.Context) Sample {
		once.Do(func() { close(entered) })
		<-ctx.Done()
		close(canceled)
		return Sample{}
	}, nil)
	m.SetTickForTest(time.Hour)
	m.Start()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("monitor did not enter sampler")
	}
	start := time.Now()
	m.Stop()
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Stop waited %s for sampler cancellation", elapsed)
	}
	select {
	case <-canceled:
	default:
		t.Fatal("Stop returned before sampler observed cancellation")
	}
}

// TestNilSafety10025: nil monitor and nil dependencies never panic; renderers
// call ActiveAlarms on whatever the daemon accessor returns.
func TestNilSafety10025(t *testing.T) {
	var m *Monitor
	if alarms := m.ActiveAlarms(); alarms != nil {
		t.Fatalf("nil monitor ActiveAlarms = %+v, want nil", alarms)
	}
	m.Stop() // must not panic
	empty := New(nil, nil)
	empty.Start() // nil sampler: no-op, mirroring natpoolalarm
	empty.Stop()
	if alarms := empty.ActiveAlarms(); len(alarms) != 0 {
		t.Fatalf("unstarted monitor ActiveAlarms = %+v, want empty", alarms)
	}
}
