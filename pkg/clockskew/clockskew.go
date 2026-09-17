// Package clockskew monitors the time prerequisites of clustered fabric RPC
// authentication. Each node samples its configured NTP reference locally; a
// pair of nodes that are each close to the same reference cannot drift into
// the fabric-auth failure band without raising an alarm first.
package clockskew

import (
	"context"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// AuthWindowSecs is the fabric bearer-token window used by pkg/grpcapi.
	// Verification accepts the current window and one adjacent window on each
	// side.
	AuthWindowSecs int64 = 30
	// AuthBreakSkewSecs is the guaranteed-break bound: once two wall clocks
	// differ by at least two complete token windows, their window indices differ
	// by at least two regardless of where either clock is inside its window.
	AuthBreakSkewSecs int64 = 2 * AuthWindowSecs
	// RaiseAtSecs is the per-node reference-offset magnitude that raises an
	// alarm. If both nodes share a reference and stay below this bound, their
	// inter-node skew is at most one AuthWindowSecs, which is inside the
	// verifier's always-accepted band. It is deliberately four times below the
	// guaranteed-break bound and two times below the minimum 30s failure edge.
	RaiseAtSecs float64 = 15
	// ClearAtSecs is the lower hysteresis bound. A raised numeric-offset alarm
	// remains active while a recovered reference is between this value and the
	// raise threshold, preventing log/render flapping around 15 seconds.
	ClearAtSecs float64 = 10
	// DefaultTickInterval bounds how long a newly crossed threshold waits for
	// the next sample. The monitor is diagnostic and intentionally slower than
	// the fabric heartbeat, but five seconds leaves useful margin below the
	// 60-second guaranteed-break bound.
	DefaultTickInterval = 5 * time.Second
	// CommandTimeout bounds the shared sample deadline covering the primary
	// and fallback reference-clock commands. A wedged chrony client must not
	// pin the monitor goroutine or daemon stop.
	CommandTimeout = 5 * time.Second
)

// SeverityRaise and SeverityClear are RFC 3164 severities used by Emitter.
// They match the existing runtime alarm monitors: warning on raise and notice
// on clear.
const (
	SeverityRaise = 4
	SeverityClear = 5
)

// Kind classifies the one active clock alarm condition.
type Kind uint8

const (
	KindNoSource Kind = iota + 1
	KindUnsynced
	KindOffset
)

// Sample is one daemon-side reference-clock sample. Unknown fields are
// represented explicitly: an unavailable or unparseable sample is not a
// decision to clear an already active alarm.
type Sample struct {
	Available      bool
	Cluster        bool
	NTPConfigured  bool
	ReferenceKnown bool
	Synced         bool
	HaveOffset     bool
	OffsetSecs     float64 // local wall clock minus the NTP reference
}

// ActiveAlarm is a read-only snapshot of the single active clock alarm.
type ActiveAlarm struct {
	Kind       Kind
	OffsetSecs float64
	FirstSeen  time.Time
}

// Summary returns the operator-facing alarm description. It intentionally
// carries the authentication bound: the operator should know both why the
// alarm is raised and what failure it prevents.
func (a ActiveAlarm) Summary() string {
	switch a.Kind {
	case KindNoSource:
		return fmt.Sprintf("cluster clock has no `system ntp server` time source; fabric RPC fails past %ds of inter-node skew (always past %ds) — configure `set system ntp server` on both nodes",
			AuthWindowSecs, AuthBreakSkewSecs)
	case KindUnsynced:
		return fmt.Sprintf("node clock is not synchronized to its NTP reference; fabric RPC fails past %ds of inter-node skew (always past %ds) — check NTP reachability",
			AuthWindowSecs, AuthBreakSkewSecs)
	case KindOffset:
		dir := "ahead of"
		mag := a.OffsetSecs
		if mag < 0 {
			dir = "behind"
			mag = -mag
		}
		return fmt.Sprintf("node clock is %gs %s its NTP reference (alarm at %gs; fabric RPC fails past %d-%ds of inter-node skew) — check NTP",
			mag, dir, RaiseAtSecs, AuthWindowSecs, AuthBreakSkewSecs)
	default:
		return "cluster clock synchronization alarm"
	}
}

func (a ActiveAlarm) detail() string {
	switch a.Kind {
	case KindNoSource:
		return "cluster has no system ntp server time source"
	case KindUnsynced:
		return "NTP reference is not synchronized"
	case KindOffset:
		dir := "ahead of"
		mag := a.OffsetSecs
		if mag < 0 {
			dir = "behind"
			mag = -mag
		}
		return fmt.Sprintf("%gs %s NTP reference", mag, dir)
	default:
		return "unknown clock synchronization condition"
	}
}

// Sampler returns one local reference-clock sample. It must honor ctx
// cancellation and stay bounded; it should read only the daemon's configured
// state plus a local reference tool.
type Sampler func(ctx context.Context) Sample

// Emitter receives one preformatted syslog line for each raise/clear
// transition. A nil emitter is permitted; the active alarm remains visible to
// read-only surfaces.
type Emitter func(severity int, msg string)

// Monitor evaluates reference-clock samples on a daemon-resident loop and
// retains the active condition for read-only alarm surfaces.
type Monitor struct {
	sample Sampler
	emit   Emitter
	tick   time.Duration
	nowFn  func() time.Time
	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	active  *ActiveAlarm
	started bool

	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}
}

// New constructs a monitor. sample and emit are dependency-injected so the
// monitor can be tested without chrony, systemd, or a live cluster. The sampler
// receives the monitor's cancellation context on every run-loop evaluation.
func New(sample Sampler, emit Emitter) *Monitor {

	ctx, cancel := context.WithCancel(context.Background())
	return &Monitor{
		sample: sample,
		emit:   emit,
		tick:   DefaultTickInterval,
		nowFn:  time.Now,
		ctx:    ctx,
		cancel: cancel,
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
}

// SetTickForTest overrides the evaluation cadence before Start. It is a test
// seam only; production uses DefaultTickInterval.
func (m *Monitor) SetTickForTest(d time.Duration) {
	if m == nil || d <= 0 {
		return
	}
	m.mu.Lock()
	if !m.started {
		m.tick = d
	}
	m.mu.Unlock()
}

// Start launches the monitor. It is a no-op for a nil sampler and is safe to
// call repeatedly.
func (m *Monitor) Start() {
	if m == nil || m.sample == nil {
		return
	}
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return
	}
	m.started = true
	m.mu.Unlock()
	go m.run()
}

// Stop terminates the monitor and joins its loop. It is safe before Start and
// safe to call more than once. Cancellation is propagated to the sampler
// before joining, so a bounded command cannot hold up daemon shutdown.
func (m *Monitor) Stop() {
	if m == nil {
		return
	}
	m.mu.Lock()
	started := m.started
	cancel := m.cancel
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	m.stopOnce.Do(func() { close(m.stop) })
	if started {
		<-m.done
	}
}

func (m *Monitor) run() {
	defer close(m.done)
	m.mu.Lock()
	tick := m.tick
	ctx := m.ctx
	m.mu.Unlock()
	select {
	case <-ctx.Done():
		return
	default:
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	// Evaluate promptly: a daemon that starts while the clock is already out of
	// bounds must raise within startup, not after a full interval.
	m.evaluateContext(ctx)
	for {
		select {
		case <-t.C:
			m.evaluateContext(ctx)
		case <-m.stop:
			return
		case <-ctx.Done():
			return
		}
	}
}

// evaluate runs one sample and transition pass. It is intentionally kept
// unexported; daemon tests exercise the public lifecycle, while package tests
// drive this deterministic seam directly.
func (m *Monitor) evaluate() {
	m.evaluateContext(context.Background())
}

func (m *Monitor) evaluateContext(ctx context.Context) {
	if m == nil || m.sample == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return
	}
	sample := m.sample(ctx)
	candidate, known := candidateFor(sample)

	m.mu.Lock()
	previous := m.active
	if !known &&
		(previous == nil || previous.Kind == KindOffset || !healthyReferenceWithoutOffset(sample)) {
		// No data is not a decision to clear: chrony can be temporarily wedged,
		// a source can be in flight, or the command can be unavailable. The
		// timedatectl fallback is different: it can prove a previously
		// unsynchronized/no-source condition recovered, but cannot prove a
		// numeric offset alarm recovered without an offset value.
		m.mu.Unlock()
		return
	}
	if candidate == nil && previous != nil && previous.Kind == KindOffset {
		if recoveredOffsetWithinHysteresis(sample) {
			candidate = &ActiveAlarm{
				Kind:       KindOffset,
				OffsetSecs: sample.OffsetSecs,
			}
		}
	}
	if candidate == nil {
		if previous == nil {
			m.mu.Unlock()
			return
		}
		m.active = nil
		m.mu.Unlock()
		clearDetail := "reference recovered"
		if sample.ReferenceKnown && sample.Synced && sample.HaveOffset &&
			!math.IsNaN(sample.OffsetSecs) && !math.IsInf(sample.OffsetSecs, 0) {
			clearDetail = fmt.Sprintf("offset=%gs", sample.OffsetSecs)
		}
		m.emitLine(SeverityClear, fmt.Sprintf(
			"RT_SYSTEM - CLOCK_SKEW_ALARM_CLEARED reason=%q detail=%q",
			"reference recovered", clearDetail))
		return
	}
	if previous != nil {
		// One ongoing condition: update details (kind/offset) without emitting a
		// second raise while the operator is remediating it.
		candidate.FirstSeen = previous.FirstSeen
	} else {
		if m.nowFn != nil {
			candidate.FirstSeen = m.nowFn()
		} else {
			candidate.FirstSeen = time.Now()
		}
	}
	m.active = candidate
	first := previous == nil
	m.mu.Unlock()
	if first {
		m.emitLine(SeverityRaise, fmt.Sprintf(
			"RT_SYSTEM - CLOCK_SKEW_ALARM_RAISED cause=%q detail=%q",
			causeFor(candidate.Kind), candidate.detail()))
	}
}

func candidateFor(s Sample) (*ActiveAlarm, bool) {
	if !s.Available {
		return nil, false
	}
	if !s.Cluster {
		// A standalone node has no cross-node fabric RPC to protect.
		return nil, true
	}
	if !s.NTPConfigured {
		return &ActiveAlarm{Kind: KindNoSource}, true
	}
	if !s.ReferenceKnown {
		return nil, false
	}
	if !s.Synced {
		return &ActiveAlarm{Kind: KindUnsynced}, true
	}
	if !s.HaveOffset || math.IsNaN(s.OffsetSecs) || math.IsInf(s.OffsetSecs, 0) {
		return nil, false
	}
	if math.Abs(s.OffsetSecs) >= RaiseAtSecs {
		return &ActiveAlarm{Kind: KindOffset, OffsetSecs: s.OffsetSecs}, true
	}
	return nil, true
}

func recoveredOffsetWithinHysteresis(s Sample) bool {
	if !s.Available || !s.Cluster || !s.NTPConfigured ||
		!s.ReferenceKnown || !s.Synced || !s.HaveOffset ||
		math.IsNaN(s.OffsetSecs) || math.IsInf(s.OffsetSecs, 0) {
		return false
	}
	magnitude := math.Abs(s.OffsetSecs)
	return magnitude >= ClearAtSecs && magnitude < RaiseAtSecs
}

func healthyReferenceWithoutOffset(s Sample) bool {
	return s.Available && s.Cluster && s.NTPConfigured &&
		s.ReferenceKnown && s.Synced && !s.HaveOffset
}

func causeFor(k Kind) string {
	switch k {
	case KindNoSource:
		return "no-source"
	case KindUnsynced:
		return "unsynchronized"
	case KindOffset:
		return "offset"
	default:
		return "unknown"
	}
}

func (m *Monitor) emitLine(severity int, msg string) {
	if m.emit != nil {
		m.emit(severity, msg)
	}
}

// ActiveAlarms returns a sorted-compatible read-only snapshot. There is at
// most one clock alarm, but a slice keeps the API identical to the other alarm
// monitors and makes both render sites composable.
func (m *Monitor) ActiveAlarms() []ActiveAlarm {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active == nil {
		return nil
	}
	return []ActiveAlarm{*m.active}
}

// RenderAlarms writes clock alarms in the shared `show security alarms` detail
// format. Summary callers count the returned entries and print their own
// aggregate line, matching natpoolalarm.RenderAlarms.
func RenderAlarms(w io.Writer, alarms []ActiveAlarm, startCount int, detail bool) int {
	count := startCount
	for _, a := range alarms {
		count++
		if detail {
			fmt.Fprintf(w, "Alarm %d:\n  Class: System\n  Severity: Critical\n  Description: %s\n", count, a.Summary())
			if !a.FirstSeen.IsZero() {
				fmt.Fprintf(w, "  First seen: %s\n", a.FirstSeen.Format("2006-01-02 15:04:05"))
			}
			fmt.Fprintln(w)
		}
	}
	return count
}

// ParseTimedatectlSync parses the fixed-property fallback used when chrony
// tracking cannot be read. It returns unknown for anything except exact yes/no.
func ParseTimedatectlSync(output string) (synced bool, ok bool) {
	switch strings.ToLower(strings.TrimSpace(output)) {
	case "yes":
		return true, true
	case "no":
		return false, true
	default:
		return false, false
	}
}

// Tracking is the parsed subset of `chronyc tracking` used by the monitor.
type Tracking struct {
	Known      bool
	Synced     bool
	HaveOffset bool
	OffsetSecs float64 // local wall clock minus NTP reference
}

// ParseChronyTracking parses chrony's stable "Key : Value" tracking output.
// It deliberately ignores presentation-only fields and never treats malformed
// text as a healthy or synchronized reference.
func ParseChronyTracking(output string) (Tracking, bool) {
	fields := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		idx := strings.Index(line, " : ")
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+3:])
		switch key {
		case "Stratum", "Leap status", "System time":
			fields[key] = value
		}
	}
	if len(fields) == 0 {
		return Tracking{}, false
	}

	var (
		stratum    int64
		stratumSet bool
	)
	if raw, ok := fields["Stratum"]; ok {
		parsed, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil {
			return Tracking{}, false
		}
		stratum = parsed
		stratumSet = true
	}

	leap, leapSet := fields["Leap status"]
	lowerLeap := strings.ToLower(leap)
	leapSynced, leapKnown := false, false
	if leapSet {
		switch {
		case strings.Contains(lowerLeap, "not synchron") ||
			strings.Contains(lowerLeap, "unsynchron"):
			leapKnown = true
		case strings.Contains(lowerLeap, "normal"):
			leapKnown = true
			leapSynced = true
		}
	}
	if !stratumSet && !leapKnown {
		return Tracking{}, false
	}

	synced := false
	if stratumSet {
		synced = stratum > 0
	}
	if leapKnown {
		if !leapSynced {
			synced = false
		} else if !stratumSet || stratum > 0 {
			synced = true
		}
	}

	tracking := Tracking{Known: true, Synced: synced}
	if raw, ok := fields["System time"]; ok {
		parts := strings.Fields(raw)
		if len(parts) > 0 {
			value, err := strconv.ParseFloat(parts[0], 64)
			if err == nil && !math.IsNaN(value) && !math.IsInf(value, 0) {
				lower := strings.ToLower(raw)
				switch {
				case strings.Contains(lower, "slow of"):
					value = -math.Abs(value)
				case strings.Contains(lower, "fast of"):
					value = math.Abs(value)
				}
				tracking.OffsetSecs = value
				tracking.HaveOffset = tracking.Synced
			}
		}
	}
	return tracking, true
}
