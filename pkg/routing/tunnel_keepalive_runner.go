package routing

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// KeepaliveState tracks the status of a GRE tunnel keepalive probe.
type KeepaliveState struct {
	mu          sync.Mutex
	Up          bool // true if tunnel is considered up
	Failures    int  // consecutive probe failures
	LastSuccess time.Time
	LastFailure time.Time
	RemoteAddr  string // underlay remote endpoint being probed
	SourceAddr  string // tunnel local endpoint IP bound for the probe (§5c)
	Interval    int    // probe interval in seconds
	MaxRetries  int    // failures before declaring down

	// #1918 hold-on-unknown bookkeeping. When the prober cannot perform a
	// probe (ProbeUnsupported), the loop holds the prior Up value and
	// reports the link liveness as unknown (KeepaliveUp == nil) rather
	// than tearing the link down for a self-inflicted reason.
	//   Unknown       — last tick could not probe (status renders "unknown").
	//   UnknownKind   — structural (hold indefinitely) vs transient.
	//   UnknownErrno  — human errno string for the escalated status.
	//   unknownStreak — consecutive unknown ticks; gates transient
	//                   escalation after MaxRetries consecutive ticks.
	//   warnedUnknown — one-shot guard for the structural slog.Warn.
	Unknown       bool
	UnknownKind   UnsupportedKind
	UnknownErrno  string
	unknownStreak int
	warnedUnknown bool

	// seq is the monotonic 16-bit ICMP echo sequence counter (§5a). Each
	// probe increments it; the reply must match Seq AND the per-probe
	// Data-nonce.
	seq int
}

// keepaliveRunner manages the goroutine for a single tunnel's keepalive.
//
// #848: `done` is closed by keepaliveLoop just before it returns.
// Close() / stopAll drain on this channel so the netlink handle is not
// closed while a keepalive goroutine is still in flight (use-after-close
// on the shared netlink handle).
type keepaliveRunner struct {
	cancel context.CancelFunc
	state  *KeepaliveState
	done   chan struct{}

	// Config identity at start time (#1884 A.7): the reconcile keeps an
	// unchanged runner alive across applies instead of restarting it
	// (which would reset probe state every commit).
	remote     string
	source     string // tunnel local endpoint IP probed-from (#1918 §5c)
	interval   int
	maxRetries int // normalized: <=0 config value stored as 3

	// linkGen is the per-tunnel generation token captured at start
	// (#1918 §6 Axis D, defense-in-depth). The runner reads it LOCK-FREE
	// (.Load()) before each netlink op and drops the action if it no
	// longer matches the manager's current generation — so a stale runner
	// cannot down/up a recreated link. The runner NEVER takes t.mu (AGY
	// r5 deadlock note: a tick blocked on t.mu while Apply blocks on the
	// drain would deadlock).
	linkGen  *atomic.Uint64
	startGen uint64
}

// matches reports whether the runner's identity equals the config's
// NORMALIZED keepalive parameters. KeepaliveRetry <= 0 normalizes to 3
// BEFORE comparison (#1884 r1 Codex F5: comparing a raw config 0
// against the stored default 3 would restart the runner every apply).
// The tunnel SOURCE is part of the identity (#1918 §5c): a source-only
// change must restart the runner so the probe binds the new endpoint.
func (r *keepaliveRunner) matches(tc *config.TunnelConfig) bool {
	retries := tc.KeepaliveRetry
	if retries <= 0 {
		retries = 3
	}
	return r.remote == tc.Destination &&
		r.source == tc.Source &&
		r.interval == tc.Keepalive &&
		r.maxRetries == retries
}

// keepaliveProber resolves the prober used by keepalive goroutines: the
// injected test fake when set, else the production datagram-ICMP prober.
func (t *tunnelManager) keepaliveProber() tunnelProber {
	if t.prober != nil {
		return t.prober
	}
	return icmpProber{}
}

// stopAll cancels all running keepalive goroutines and waits for them
// to exit. Acquires mu.
//
// #848: draining (not just cancelling) is required because
// keepaliveLoop touches the netlink handle on bring-up/down. The
// façade Close() then closes the handle, so any in-flight tick that
// hadn't yet checked ctx.Done() would use-after-close. The done
// channel makes the drain explicit.
func (t *tunnelManager) stopAll() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stopAllKeepalivesLocked()
}

// stopAllKeepalivesLocked cancels all keepalive goroutines and waits
// for them to exit. Caller MUST hold mu.
func (t *tunnelManager) stopAllKeepalivesLocked() {
	runners := t.keepalives
	t.keepalives = make(map[string]*keepaliveRunner)
	for name, runner := range runners {
		runner.cancel()
		<-runner.done
		slog.Debug("stopped keepalive", "tunnel", name)
	}
}

// stopKeepaliveLocked cancels, drains, and REMOVES the keepalive
// runner for one tunnel, if any. Removing the map entry matters
// (#1884 SMR2-2): a cancelled runner left behind would make
// GetKeepaliveState report a dead probe and would let the apply
// reconcile "retain" a corpse. Caller MUST hold mu.
func (t *tunnelManager) stopKeepaliveLocked(name string) {
	runner, ok := t.keepalives[name]
	if !ok {
		return
	}
	runner.cancel()
	<-runner.done
	delete(t.keepalives, name)
	slog.Debug("stopped keepalive", "tunnel", name)
}

// startKeepalive starts a keepalive probe goroutine for a tunnel.
// source is the tunnel local endpoint IP the probe binds to (#1918
// §5c); "" → wildcard. Caller MUST hold mu.
func (t *tunnelManager) startKeepalive(tunnelName, source, remoteAddr string, interval, maxRetries int) {
	// Stop existing keepalive for this tunnel if any. Drain on done
	// so the replacement doesn't race the old goroutine on the handle.
	t.stopKeepaliveLocked(tunnelName)

	if maxRetries <= 0 {
		maxRetries = 3
	}

	state := &KeepaliveState{
		Up:         true,
		RemoteAddr: remoteAddr,
		SourceAddr: source,
		Interval:   interval,
		MaxRetries: maxRetries,
	}

	// Capture the current generation token (#1918 §6 Axis D
	// defense-in-depth). The runner reads it LOCK-FREE — it never takes
	// t.mu — so an Apply blocked on the drain can never deadlock a tick.
	gen := t.linkGenForLocked(tunnelName)
	startGen := gen.Load()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	t.keepalives[tunnelName] = &keepaliveRunner{
		cancel:     cancel,
		state:      state,
		done:       done,
		remote:     remoteAddr,
		source:     source,
		interval:   interval,
		maxRetries: maxRetries,
		linkGen:    gen,
		startGen:   startGen,
	}

	prober := t.keepaliveProber()
	go t.keepaliveLoop(ctx, done, tunnelName, state, prober, gen, startGen)
	slog.Info("started keepalive", "tunnel", tunnelName,
		"source", source, "remote", remoteAddr, "interval", interval, "retries", maxRetries)
}

// maxKeepaliveIntervalSec bounds the tunnel keepalive interval before it
// is multiplied into a time.Duration. time.Duration is int64 nanoseconds,
// so time.Duration(sec)*time.Second overflows once sec exceeds ~9.2e9;
// an overflowed product wraps non-positive, and time.NewTicker panics on
// a non-positive interval, crashing xpfd (#5705). The commit-check schema
// rejects an out-of-range keepalive at admission (pkg/config
// tunnelSchemaChildren, ValidateInteger(0, 32767)); this ceiling mirrors
// that bound as a runtime clamp so an un-gated value (stale DB, a path
// that bypasses SchemaValidate) still cannot overflow or panic. 32767 s
// matches the de-facto GRE keepalive ceiling and 32767*1e9 ns is far
// under the int64 limit.
const maxKeepaliveIntervalSec = 32767

// clampKeepaliveIntervalSec constrains a keepalive interval to a
// positive, non-overflowing range [1, maxKeepaliveIntervalSec]. The
// keepalive loop only starts for intervals > 0, so the min-1 floor is
// purely defensive against a degenerate non-positive value reaching
// time.NewTicker (which would panic).
func clampKeepaliveIntervalSec(sec int) int {
	if sec < 1 {
		return 1
	}
	if sec > maxKeepaliveIntervalSec {
		return maxKeepaliveIntervalSec
	}
	return sec
}

// keepaliveProbeDeadline returns the per-probe round-trip budget: a
// fraction of the interval, capped at 800ms (R5). Keeps the probe well
// inside the tick so a slow/lost reply cannot overrun the next tick. The
// interval is clamped first so a huge value cannot overflow the
// Duration multiply into a bogus (potentially in-range positive) budget.
func keepaliveProbeDeadline(intervalSec int) time.Duration {
	const maxDeadline = 800 * time.Millisecond
	half := time.Duration(clampKeepaliveIntervalSec(intervalSec)) * time.Second / 2
	if half <= 0 || half > maxDeadline {
		return maxDeadline
	}
	return half
}

// keepaliveLoop runs periodic ICMP echo probes to the tunnel underlay
// endpoint and drives the link admin state off REAL liveness (#1918).
// Closes `done` when it returns so stopAll can drain.
//
// Tick body is the §6 Axis D COMMIT-AFTER-SUCCESS sequence:
//  1. Under state.mu: classify the probe; commit pure counters
//     (Failures/LastSuccess/LastFailure/unknown bookkeeping); compute
//     the transition INTENT (wantUp/wantDown) WITHOUT writing Up; Unlock.
//     A racing GetStatus/Apply therefore never observes an uncommitted Up.
//  2. No intent → done (no netlink, no Up write).
//  3. LinkByName; on error do nothing (Up unchanged → retried next tick).
//  4. Lock-free gen.Load() guard: if the generation changed, the link
//     was recreated under us → DROP the action (do not down/up the
//     replacement). Never takes t.mu (AGY r5).
//  5. The single LinkSetUp/LinkSetDown, OUTSIDE state.mu, capturing err.
//  6. Commit Up ONLY on netlink success; on error leave Up unchanged so
//     the transition retries.
func (t *tunnelManager) keepaliveLoop(ctx context.Context, done chan struct{}, tunnelName string, state *KeepaliveState, prober tunnelProber, gen *atomic.Uint64, startGen uint64) {
	defer close(done)
	// Clamp before the Duration multiply: an un-gated / overflowing
	// interval would wrap non-positive and panic time.NewTicker (#5705).
	ticker := time.NewTicker(time.Duration(clampKeepaliveIntervalSec(state.Interval)) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.keepaliveTick(tunnelName, state, prober, gen, startGen)
		}
	}
}

// keepaliveTick runs one §6 Axis D commit-after-success probe cycle. It
// is the per-tick body of keepaliveLoop, extracted so tests can drive a
// single deterministic tick without a real ticker. It NEVER takes t.mu
// (AGY r5): only state.mu (two short sections) and a lock-free gen.Load().
func (t *tunnelManager) keepaliveTick(tunnelName string, state *KeepaliveState, prober tunnelProber, gen *atomic.Uint64, startGen uint64) {
	deadline := keepaliveProbeDeadline(state.Interval)
	seq := nextSeq(state)
	nonce := makeNonce()
	result, kind, reason := prober.Probe(state.SourceAddr, state.RemoteAddr, seq, nonce, deadline)

	// ---- Step 1: classify + commit counters, compute intent ----
	state.mu.Lock()
	var wantUp, wantDown bool
	switch result {
	case ProbeAlive:
		state.LastSuccess = time.Now()
		state.clearUnknownLocked()
		if !state.Up {
			wantUp = true // recovery edge
		}
		state.Failures = 0
	case ProbeDead:
		state.LastFailure = time.Now()
		state.clearUnknownLocked()
		state.Failures++
		if state.Up && state.Failures >= state.MaxRetries {
			wantDown = true
		}
	case ProbeUnsupported:
		// Hold-on-unknown (§6 Axis C, C1): do NOT touch Failures,
		// do NOT transition the link. Surface as unknown; escalate a
		// sustained TRANSIENT unknown after MaxRetries ticks. The prober's
		// reason (real syscall/config detail) is recorded so the status and
		// escalation log are actionable (Copilot PR #1947).
		detail := reason
		if detail == "" {
			detail = classifyErrnoString(kind)
		}
		state.markUnknownLocked(tunnelName, kind, detail)
	}
	state.mu.Unlock()

	// ---- Step 2: no transition intent → nothing to do ----
	if !wantUp && !wantDown {
		return
	}

	// ---- Step 3: resolve the link; error → retry next tick ----
	link, err := t.ops.LinkByName(tunnelName)
	if err != nil {
		// Do NOT write Up; the guard in step 1 fires again next
		// tick (Up unchanged). No spurious latch from a transient
		// netlink lookup hiccup (§4.6).
		slog.Debug("keepalive transition deferred: link lookup failed",
			"tunnel", tunnelName, "err", err)
		return
	}

	// ---- Step 4: lock-free generation guard (defense-in-depth) --
	if gen.Load() != startGen {
		// The link was recreated by Apply since this runner started.
		// Drop the action so we never down/up the replacement link.
		slog.Debug("keepalive transition dropped: link generation changed",
			"tunnel", tunnelName)
		return
	}

	// ---- Step 5: the single netlink op, OUTSIDE state.mu --------
	var nlErr error
	if wantUp {
		nlErr = t.ops.LinkSetUp(link)
	} else {
		nlErr = t.ops.LinkSetDown(link)
	}

	// ---- Step 6: commit Up only on netlink success -------------
	if nlErr != nil {
		// Up retains its pre-transition value → the transition is
		// retried next tick until the kernel op succeeds. Never a
		// lost transition (Codex r3 counterexample).
		slog.Warn("keepalive netlink transition failed; will retry",
			"tunnel", tunnelName, "want_up", wantUp, "err", nlErr)
		return
	}
	state.mu.Lock()
	if wantUp {
		state.Up = true
		state.Failures = 0
		slog.Info("tunnel keepalive recovered", "tunnel", tunnelName,
			"remote", state.RemoteAddr)
	} else {
		state.Up = false
		slog.Warn("tunnel keepalive failed, marking down",
			"tunnel", tunnelName, "remote", state.RemoteAddr,
			"failures", state.Failures)
	}
	state.mu.Unlock()
	if callback := t.livenessChange.Load(); callback != nil {
		(*callback)(tunnelName, wantUp)
	}
}

// nextSeq returns a fresh monotonic 16-bit sequence number for a probe
// (§5a). Wraps at 0xffff; the per-probe nonce disambiguates a wrapped
// collision. Mutates Failures-adjacent state under its own lock.
func nextSeq(state *KeepaliveState) int {
	state.mu.Lock()
	state.seq = (state.seq + 1) & 0xffff
	s := state.seq
	state.mu.Unlock()
	return s
}

// clearUnknownLocked resets the hold-on-unknown bookkeeping after a
// definitive Alive/Dead probe. Caller MUST hold state.mu.
func (s *KeepaliveState) clearUnknownLocked() {
	s.Unknown = false
	s.UnknownKind = UnsupportedNone
	s.UnknownErrno = ""
	s.unknownStreak = 0
	s.warnedUnknown = false
}

// markUnknownLocked records a ProbeUnsupported tick. Structural emits a
// one-shot Warn and holds indefinitely; transient holds but escalates to
// slog.Error after MaxRetries consecutive unknown ticks (§6 Axis C,
// transient escalation). Never changes Up or Failures. Caller MUST hold
// state.mu.
func (s *KeepaliveState) markUnknownLocked(tunnelName string, kind UnsupportedKind, errStr string) {
	s.Unknown = true
	s.UnknownKind = kind
	s.UnknownErrno = errStr
	s.unknownStreak++
	switch kind {
	case UnsupportedStructural:
		if !s.warnedUnknown {
			s.warnedUnknown = true
			slog.Warn("tunnel keepalive cannot probe (ICMP unavailable); holding prior state",
				"tunnel", tunnelName, "remote", s.RemoteAddr,
				"hint", "set net.ipv4.ping_group_range or grant CAP_NET_RAW")
		}
	case UnsupportedTransient:
		if s.unknownStreak >= s.MaxRetries && !s.warnedUnknown {
			s.warnedUnknown = true
			slog.Error("tunnel keepalive probe failing on local resource error; cannot verify peer liveness",
				"tunnel", tunnelName, "remote", s.RemoteAddr,
				"errno", errStr, "consecutive", s.unknownStreak)
		}
	}
}

// classifyErrnoString renders a short label for the unknown kind used in
// the status string.
func classifyErrnoString(kind UnsupportedKind) string {
	switch kind {
	case UnsupportedTransient:
		return "probe socket error"
	case UnsupportedStructural:
		return "ICMP probe unavailable"
	default:
		return "unknown"
	}
}

// GetKeepaliveState returns the keepalive state for a tunnel, or nil
// if no keepalive is configured.
//
// #848: mu protects the keepalives map against concurrent
// startKeepalive / stopAll mutations from Apply / Clear. The returned
// *KeepaliveState pointer is safe to dereference outside the lock —
// Go GC keeps the value alive even if a subsequent stopAll removes it
// from the map.
func (t *tunnelManager) GetKeepaliveState(tunnelName string) *KeepaliveState {
	t.mu.Lock()
	defer t.mu.Unlock()
	runner, ok := t.keepalives[tunnelName]
	if !ok {
		return nil
	}
	return runner.state
}
