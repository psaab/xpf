package frr

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"time"
)

// #19050 option B: install a promoted node's owned static lines ahead of the
// coalesced HA reload.
//
// The invariant is WHEN, never WHAT. The fast path installs only static lines
// that the node's next HA render contains verbatim. FRR (staticd, through
// vtysh) stays the only writer, and the coalesced frr-reload stays the
// authority: every ownership edge already schedules it, it finds a fast line
// present (a no-op) or absent from frr.conf (it deletes it).
//
// The protocol (design: #19050 issuecomment-6763838572 and the v2.1-v2.3
// addenda):
//   - Lock: reloadMu ONLY, never buildMu. Every other FRR writer (apply, Clear,
//     the degraded retry) serializes on it, so no reload can read the running
//     config while a fast vtysh is in flight.
//   - Counters: the fast path never touches confGen, writeGen or
//     unconditionalWriteGen. A bump would make a pending demotion reload's
//     staleness predicate false; that reload would then skip itself and leak
//     the line (review R4 B4).
//   - Pre-check: the caller's predicate runs under reloadMu, right before the
//     exec. Any failure skips; the scheduled reload installs.
//   - Fast set: the wanted lines minus the managed section AS LAST WRITTEN (read
//     from frr.conf under reloadMu), v6 lines first.
//   - Bound: the exec runs on a lifetimeCtx-derived context with the same
//     reloadTimeout as every other writer under reloadMu, and reloadMu is held
//     until vtysh exits. fastInstallSlowAlarm is only a logged latency alarm.
//   - In doubt: a kill at the bound, a non-zero exit or a partial batch leaves
//     the lines IN DOUBT (fastInDoubt, guarded by reloadMu). A normal
//     successful reload neither clears it nor cancels the retry it armed; only
//     a successful barrier followed by a frr-reload.py --test whose diff names
//     none of the in-doubt lines clears it (review R4 B1, F1, F2).
//   - Shutdown: fastStopped and fastWG.Add are both under retryMu, the same
//     pattern Stop uses for retryEnabled, so no install starts behind Stop's
//     Wait (review R4 N3, R14).

// FastInstallOutcome reports what FastInstallStatics did.
type FastInstallOutcome int

const (
	// FastRefused: the manager is stopping or stopped, has no lifetime
	// context, or its executor has no fast-path support. Nothing ran.
	FastRefused FastInstallOutcome = iota
	// FastSkipped: the caller's pre-check failed under reloadMu, or the
	// managed section could not be read. Nothing ran.
	FastSkipped
	// FastNothingToDo: every wanted line is already in the managed section.
	FastNothingToDo
	// FastInstalled: vtysh applied the fast set and exited 0.
	FastInstalled
	// FastInDoubt: vtysh failed, was killed, or exited non-zero. The lines may
	// or may not be applied; the retry loop resolves them.
	FastInDoubt
)

func (o FastInstallOutcome) String() string {
	switch o {
	case FastRefused:
		return "refused"
	case FastSkipped:
		return "skipped"
	case FastNothingToDo:
		return "nothing-to-do"
	case FastInstalled:
		return "installed"
	case FastInDoubt:
		return "in-doubt"
	}
	return "unknown"
}

// fastInstallSlowAlarm is a latency alarm only: a fast install slower than
// this is logged. The hard bound is reloadTimeout (measured on udp: 21-48 ms).
const fastInstallSlowAlarm = 500 * time.Millisecond

// fastExecutor19050 is the executor surface the fast path needs. The
// production realExecutor implements it; a test double that does not is
// refused, never shelled out.
type fastExecutor19050 interface {
	// VtyshConfigLines runs `vtysh -c "configure terminal" -c <line>... -c end`.
	// With no lines it is the barrier: a fresh configuration session through
	// mgmtd that must succeed.
	VtyshConfigLines(ctx context.Context, lines []string) ([]byte, error)
	// FrrReloadPyTestOutput runs `frr-reload.py --test --stdout <conf>` and
	// returns its output (the diff) without judging it.
	FrrReloadPyTestOutput(ctx context.Context, conf string) ([]byte, error)
}

type fastInDoubtState19050 struct {
	lines []string
	since time.Time
}

// RenderStaticLines returns the static-route lines the managed section would
// contain for fc, in render order: the global statics, the rib inet6.0
// statics, and every instance's statics. It uses the SAME per-line renderer as
// buildManagedSection, and it reads no mutable Manager state, so it is safe
// without buildMu. Generate (aggregate) routes, DHCP defaults, the cluster
// defaults and ip-monitoring preferred routes are not statics, and are not part
// of the fast set.
func (m *Manager) RenderStaticLines(fc *FullConfig) []string {
	if fc == nil {
		return nil
	}
	var out []string
	add := func(rendered string) {
		for _, line := range strings.Split(rendered, "\n") {
			if line = strings.TrimSpace(line); isStaticRouteLine19050(line) {
				out = append(out, line)
			}
		}
	}
	for _, sr := range fc.StaticRoutes {
		add(renderStaticRouteWithISISDistanceGuard17735(m, sr, "", 0, fc.RethMap, fc.IPv6NextHopInterfaces, fc.DeclaredNetdevs, fc.ISIS))
	}
	for _, sr := range fc.Inet6StaticRoutes {
		add(renderStaticRouteWithISISDistanceGuard17735(m, sr, "", 0, fc.RethMap, fc.IPv6NextHopInterfaces, fc.DeclaredNetdevs, fc.ISIS))
	}
	for _, inst := range fc.Instances {
		isis := inst.ISIS
		if inst.VRFName == "" && inst.TableID > 0 {
			isis = nil
		}
		for _, sr := range inst.StaticRoutes {
			add(renderStaticRouteWithISISDistanceGuard17735(m, sr, inst.VRFName, inst.TableID, fc.RethMap, fc.IPv6NextHopInterfaces, fc.DeclaredNetdevs, isis))
		}
		for _, sr := range inst.Inet6StaticRoutes {
			add(renderStaticRouteWithISISDistanceGuard17735(m, sr, inst.VRFName, inst.TableID, fc.RethMap, fc.IPv6NextHopInterfaces, fc.DeclaredNetdevs, isis))
		}
	}
	return out
}

func isStaticRouteLine19050(line string) bool {
	return strings.HasPrefix(line, "ip route ") || strings.HasPrefix(line, "ipv6 route ")
}

// FastInstallStatics installs, ahead of the coalesced HA reload, the lines of
// want that the managed section as last written lacks. precheck runs under
// reloadMu right before the exec; it must not call into this Manager. It
// returns the outcome and the lines it attempted.
func (m *Manager) FastInstallStatics(want []string, precheck func() bool) (FastInstallOutcome, []string) {
	fx, ok := m.executor().(fastExecutor19050)
	if !ok {
		return FastRefused, nil
	}
	m.retryMu.Lock()
	if m.fastStopped || m.mgrCtx == nil {
		m.retryMu.Unlock()
		return FastRefused, nil
	}
	m.fastWG.Add(1)
	m.fastJoined.Add(1)
	m.retryMu.Unlock()
	defer m.fastWG.Done()

	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()
	if m.lifetimeCtx().Err() != nil {
		return FastRefused, nil
	}
	if precheck != nil && !precheck() {
		return FastSkipped, nil
	}
	written, err := m.writtenStaticLines19050()
	if err != nil {
		slog.Debug("frr: fast install skipped: managed section unreadable", "err", err)
		return FastSkipped, nil
	}
	lines := fastSet19050(want, written)
	if len(lines) == 0 {
		return FastNothingToDo, nil
	}
	ctx, cancel := context.WithTimeout(m.lifetimeCtx(), reloadTimeout)
	defer cancel()
	start := time.Now()
	out, err := fx.VtyshConfigLines(ctx, lines)
	elapsed := time.Since(start)
	if elapsed > fastInstallSlowAlarm {
		slog.Warn("frr: fast static install was slow (#19050)", "elapsed", elapsed, "lines", len(lines))
	}
	if err != nil {
		m.markFastInDoubtLocked(lines)
		slog.Warn("frr: fast static install failed; lines are in doubt until a verified reload (#19050)",
			"err", err, "output", strings.TrimSpace(string(out)), "lines", lines)
		return FastInDoubt, lines
	}
	slog.Info("frr: fast static install (#19050)", "elapsed", elapsed, "lines", lines)
	return FastInstalled, lines
}

// FastInDoubt reports whether fast-installed lines are still awaiting
// verification.
func (m *Manager) FastInDoubt() bool {
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()
	return m.fastInDoubt != nil
}

// markFastInDoubtLocked records lines as in doubt and arms the retry loop.
// Caller holds reloadMu.
func (m *Manager) markFastInDoubtLocked(lines []string) {
	if m.fastInDoubt == nil {
		m.fastInDoubt = &fastInDoubtState19050{since: time.Now()}
	}
	m.fastInDoubt.lines = append(m.fastInDoubt.lines, lines...)
	m.ensureRetryLocked(false)
}

// fastSet19050 returns the lines of want absent from written, deduplicated,
// with v6 lines first (v6 waited behind v4 when installed second).
func fastSet19050(want, written []string) []string {
	have := make(map[string]bool, len(written))
	for _, l := range written {
		have[normalizeRouteLine19050(l)] = true
	}
	var v6, v4 []string
	seen := map[string]bool{}
	for _, l := range want {
		key := normalizeRouteLine19050(l)
		if key == "" || have[key] || seen[key] {
			continue
		}
		seen[key] = true
		if strings.HasPrefix(key, "ipv6 route ") {
			v6 = append(v6, l)
		} else {
			v4 = append(v4, l)
		}
	}
	return append(v6, v4...)
}

func normalizeRouteLine19050(l string) string {
	return strings.Join(strings.Fields(l), " ")
}

// writtenStaticLines19050 reads the static lines of the managed section from
// frr.conf as last written. Caller holds reloadMu, the lock every managed-
// section write is made under.
func (m *Manager) writtenStaticLines19050() ([]string, error) {
	data, err := os.ReadFile(m.frrConf)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	text := string(data)
	start := strings.Index(text, markerBegin)
	if start < 0 {
		return nil, nil
	}
	section := text[start+len(markerBegin):]
	if end := strings.Index(section, markerEnd); end >= 0 {
		section = section[:end]
	}
	var out []string
	for _, line := range strings.Split(section, "\n") {
		if line = strings.TrimSpace(line); isStaticRouteLine19050(line) {
			out = append(out, line)
		}
	}
	return out, nil
}

// resolveFastInDoubtLocked runs one in-doubt resolution step from the retry
// loop. Caller holds reloadMu. It clears fastInDoubt only after a successful
// barrier and a frr-reload.py --test whose diff names none of the in-doubt
// lines; otherwise it runs the authoritative reload and asks to be called
// again. It reports whether the retry episode may stop.
func (m *Manager) resolveFastInDoubtLocked(ctx context.Context) bool {
	fx, ok := m.executor().(fastExecutor19050)
	if !ok {
		return false
	}
	rctx, cancel := context.WithTimeout(ctx, reloadTimeout)
	defer cancel()
	// Barrier: a fresh configuration session through mgmtd must succeed, so the
	// killed session's transaction is no longer pending (FRR behaviour to be
	// pinned by the #19050 SIGSTOP lab cell).
	if out, err := fx.VtyshConfigLines(rctx, nil); err != nil {
		slog.Warn("frr: in-doubt barrier failed; retrying (#19050)", "err", err, "output", strings.TrimSpace(string(out)))
		return false
	}
	diff, err := fx.FrrReloadPyTestOutput(rctx, m.frrConf)
	if err != nil {
		slog.Warn("frr: in-doubt --test failed; retrying (#19050)", "err", err)
		return false
	}
	if !reloadTestDiffMentions19050(diff, m.fastInDoubt.lines) {
		slog.Info("frr: in-doubt fast lines verified (#19050)",
			"lines", m.fastInDoubt.lines, "since", m.fastInDoubt.since)
		m.fastInDoubt = nil
		return !m.degraded.Load()
	}
	if err := m.executor().FrrReloadPy(rctx, m.frrConf); err != nil {
		slog.Warn("frr: in-doubt authoritative reload failed; retrying (#19050)", "err", err)
	}
	if rerr := m.reconcileQNHMetricOverlaysLocked(ctx); rerr != nil {
		slog.Warn("frr: in-doubt reload could not reconcile QNH metric overlays", "err", rerr)
	}
	return false
}

// reloadTestDiffMentions19050 reports whether `frr-reload.py --test --stdout`
// output names any of lines, in either its "Lines To Add" or "Lines To Delete"
// section. A diff line names an in-doubt line when the two are equal after
// whitespace normalization, with a leading "no " ignored. FRR prints a VRF
// static under a `vrf NAME` context, while the managed section renders it
// inline (`ip route ... vrf NAME`), so an indented line under a `vrf` context
// is also compared in its inline form. Over-matching only delays the clear
// (fail-closed); unrelated drift, such as the memory-only QNH metric overlay
// (#15183), does not block it (review R4 F2). The exact shapes are pinned by
// testdata fixtures captured from FRR 10.5.1.
func reloadTestDiffMentions19050(out []byte, lines []string) bool {
	want := make(map[string]bool, len(lines))
	for _, l := range lines {
		if n := normalizeRouteLine19050(l); n != "" {
			want[n] = true
		}
	}
	if len(want) == 0 {
		return false
	}
	inSection := false
	vrfContext := ""
	for _, raw := range strings.Split(string(out), "\n") {
		t := strings.TrimSpace(raw)
		switch {
		case t == "Lines To Add" || t == "Lines To Delete":
			inSection, vrfContext = true, ""
			continue
		case t == "" || strings.HasPrefix(t, "="):
			continue
		}
		if !inSection {
			continue
		}
		indented := len(raw) > 0 && (raw[0] == ' ' || raw[0] == '\t')
		if !indented {
			vrfContext = ""
			if f := strings.Fields(t); len(f) == 2 && f[0] == "vrf" {
				vrfContext = f[1]
				continue
			}
		}
		n := normalizeRouteLine19050(strings.TrimPrefix(t, "no "))
		if want[n] {
			return true
		}
		if indented && vrfContext != "" && want[n+" vrf "+vrfContext] {
			return true
		}
	}
	return false
}
