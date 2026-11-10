package frr

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #19083: in cluster mode a static route may not resolve its next hop through
// a BLACKHOLE route.
//
// Why: after a graceful HA stop (or a planned move away) the node's VIPs are
// gone, and an owned static's gateway (on the RETH subnet) then resolves
// recursively through the cluster Null0 default (renderClusterModeDefaults):
// FRR installed it as an ACTIVE kernel blackhole that redistribution exported
// from a node that forwards nothing (#19083, measured on loss). The fix does
// not depend on a shutdown write (Stop writes only to settle an owed
// re-evaluation, settleOwedStaticNHTRebind19083); instead the render binds
// staticd's next-hop tracking to a route-map that denies resolution through any
// blackhole next hop, so a static rendered as a PLAIN gateway goes inactive by
// itself the moment its gateway's connected route leaves.
//
// Coverage boundary (R22 #1, TestStaticNHTMapCoverageBoundary19083): staticd
// consults next-hop tracking only for a plain gateway; a gateway WITH an
// interface, or an interface alone, installs whenever the interface exists
// (FRR 10.5.1 staticd/static_zebra.c:479-497). The default v4 shape is a plain
// gateway (covered); the default v6 shape on a RETH subnet is interface-
// qualified by inference and goes inactive through zebra's connected check
// instead. Operator-qualified v4, interface-only and v6 link-local next hops
// stay active after a graceful stop: the residual filed as #19122.
//
// FRR mechanism (read at tag frr-10.5.1, zebra/zebra_rnh.c and
// zebra_routemap.c): zebra applies a client protocol's NHT route-map to a COPY
// of the route resolving the next hop (copy_state, which copies the nexthop
// group but NOT the tag — a `match tag 2500` map can never match); `match ip|
// ipv6 next-hop type blackhole` compares the resolving route's nexthop type
// (NEXTHOP_TYPE_BLACKHOLE); a deny marks the client's resolution filtered and
// staticd installs no path. Premise cells on udp (FRR 10.5.1): bound over
// existing statics, the blackhole-only ones were withdrawn and `(filtered)`
// within 3 s while one resolving through a real interface route stayed; a
// static whose gateway route then LEFT (the graceful-stop shape) was withdrawn
// within 3 s. docs/log/19083.md has the cells.
//
// Scope: cluster mode only (the cluster default and VIP ownership are cluster
// constructs), the DEFAULT VRF only (the top-level binding is per VRF and the
// cluster defaults exist only in the default VRF; virtual-router `vrf NAME`
// statics are unchanged, while forwarding-instance `table N` statics are
// default-VRF statics and ARE filtered), and the map filters staticd only (BGP
// and every other NHT client keep their own resolution; a REBIND re-evaluates
// every client, see ReevaluateStaticNHT19083). Recursion
// through a real gateway route — a real default included, #12613's contract —
// is unchanged. A static whose gateway resolves only through an operator
// discard/reject or a generate-route aggregate also goes inactive: that
// agrees with the userspace helper, whose recursion already returns no target
// on a discard/reject row, and with Junos (the next hop is unreachable); the
// compiler warns about that pattern (validateStaticDiscardAnchorWarnings19083).
//
// Residual: zebra answers a NEWLY registering client without applying the map
// (zebra_add_rnh_client), so a static that registers while its gateway
// already resolves only through a blackhole is unfiltered until the next NHT
// event for that next hop. ReevaluateStaticNHT19083 forces one; production
// callers request it through RequestStaticNHTReeval19083, which coalesces a
// burst into one rebind (the daemon after a demotion's VIP removal). Residual:
// (i) FRR
// restarting without xpfd; (ii) a commit or an FRR/xpfd start that registers a
// static already blackhole-resolved, notably a non-RETH recursive static kept
// on both nodes, on the standby; (iii) a registration completing after the
// shutdown VIP removal (which runs after frr.Stop). An interrupted rebind is
// restored before the next diff reload (restoreStaticNHTBindingLocked19083).

const (
	// clusterStaticNHTRouteMap19083 is the bound map. The reserved
	// ReservedRedistSuffix keeps operator policy names out of it (strict
	// commit refuses the suffix; the tolerant path is fenced by the final-
	// name belt, emittedRouteMapFinalCollision16867).
	clusterStaticNHTRouteMap19083 = "xpf-static-nht" + config.ReservedRedistSuffix
	// clusterStaticNHTRouteMapAlt19083 is an identical, normally unbound map.
	// Rebinding to it and back forces zebra to re-evaluate every static next
	// hop without an unbound window (ip_nht_rm_add evaluates only when the
	// bound NAME changes; unbinding would re-install the filtered statics
	// for a moment).
	clusterStaticNHTRouteMapAlt19083 = "xpf-static-nht-b" + config.ReservedRedistSuffix
)

// staticNHTReevalTimeout19083 bounds one rebind or restore WRITE; each binding
// READ has its own staticNHTReadTimeout19083 (R24 P3-2: no shared budget).
// staticNHTRebindDebounce19083 is how long a requested rebind waits for the rest
// of its burst (RequestStaticNHTReeval19083). Vars so cells can shorten them.
// staticNHTStopBudget19083 bounds Stop's settle of an owed rebind: the wait for
// reloadMu, and the rebind exec, each get this long.
var (
	staticNHTReevalTimeout19083  = 5 * time.Second
	staticNHTReadTimeout19083    = 3 * time.Second
	staticNHTRebindDebounce19083 = 100 * time.Millisecond
	staticNHTStopBudget19083     = 2 * time.Second
	// staticNHTHeldLogEvery19083 spaces the WARNs of one held episode.
	staticNHTHeldLogEvery19083 = time.Minute
)

func clusterStaticNHTMapBody19083(name string) string {
	n := frrName(name)
	return fmt.Sprintf("route-map %s deny 10\n match ip next-hop type blackhole\nexit\n"+
		"route-map %s deny 20\n match ipv6 next-hop type blackhole\nexit\n"+
		"route-map %s permit 30\nexit\n", n, n, n)
}

// staticNHTBindLines19083 are the two bindings of name, v4 then v6.
func staticNHTBindLines19083(name string) []string {
	n := frrName(name)
	return []string{"ip nht static route-map " + n, "ipv6 nht static route-map " + n}
}

// renderClusterStaticNHT19083 renders both maps and binds staticd's v4 and v6
// next-hop tracking to the primary one. Cluster mode only.
func renderClusterStaticNHT19083(fc *FullConfig) string {
	if fc == nil || !fc.ClusterMode {
		return ""
	}
	var b strings.Builder
	b.WriteString(clusterStaticNHTMapBody19083(clusterStaticNHTRouteMap19083))
	b.WriteString(clusterStaticNHTMapBody19083(clusterStaticNHTRouteMapAlt19083))
	b.WriteString("!\n")
	for _, l := range staticNHTBindLines19083(clusterStaticNHTRouteMap19083) {
		b.WriteString(l + "\n")
	}
	b.WriteString("!\n")
	return b.String()
}

// vtyshConfigExecutor19083 runs a batch of configuration lines in one vtysh
// configuration session.
type vtyshConfigExecutor19083 interface {
	VtyshConfigLines(ctx context.Context, lines []string) ([]byte, error)
}

// ReevaluateStaticNHT19083 forces zebra to re-evaluate every static next hop
// against the #19083 map, closing the fresh-registration bypass for statics
// that registered since the last NHT event (see the file comment). It binds
// the identical alternate map and then the primary again, so the running
// config ends as frr.conf renders it. It runs under reloadMu like every FRR
// writer, never touches confGen/writeGen, and is a no-op when the managed
// section as last written does not bind the map (not cluster mode) or the
// manager is stopping.
//
// Cost (R22 #2): each bound-name change makes zebra re-evaluate EVERY tracked
// next hop of that family for EVERY client (zebra_evaluate_rnh with force):
// staticd re-sends its statics and bgpd re-runs bestpath for the paths on
// those next hops. A rebind is two such evaluations per family, so production
// callers go through RequestStaticNHTReeval19083, which coalesces them.
//
// It has no production caller: production goes through
// RequestStaticNHTReeval19083 and its drain, which takes reloadMu itself
// (pinned by TestStaticNHTRequestedDrainSerializesWithRetryReload19083). This
// synchronous form serves cells and diagnostics.
func (m *Manager) ReevaluateStaticNHT19083() error {
	ex, ok := m.executor().(vtyshConfigExecutor19083)
	if !ok {
		return nil
	}
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()
	if m.lifetimeCtx().Err() != nil {
		return nil
	}
	return m.reevaluateStaticNHTLocked19083(ex)
}

// RequestStaticNHTReeval19083 asks for one static-NHT re-evaluation without
// blocking: it is safe on the VIP path and under reloadMu (lock order reloadMu
// -> nhtRebindMu, a leaf). Requests COALESCE (R22 #2, R24 P2-1/P3-4):
//   - the first schedules a drain staticNHTRebindDebounce19083 later;
//   - every request until that drain holds reloadMu rides on it (no pile-up
//     of callbacks queued behind a long reload);
//   - a request that arrives while the drain is rebinding schedules exactly
//     one more: one running plus one pending, never a dropped request.
//
// A failed rebind is logged, not retried: the binding restore keeps filtering
// safe, and the next request re-evaluates. A stopping manager drains nothing.
func (m *Manager) RequestStaticNHTReeval19083() {
	m.nhtRebindMu.Lock()
	m.nhtRebindOwed = true
	schedule := !m.nhtRebindScheduled
	m.nhtRebindScheduled = true
	m.nhtRebindMu.Unlock()
	if schedule {
		time.AfterFunc(staticNHTRebindDebounce19083, m.drainStaticNHTRebind19083)
	}
}

// drainStaticNHTRebind19083 runs one coalesced rebind under reloadMu.
func (m *Manager) drainStaticNHTRebind19083() {
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()
	if m.lifetimeCtx().Err() != nil {
		// Stopping: leave what is owed for Stop to settle
		// (settleOwedStaticNHTRebind19083), never drop it (Codex P2 on
		// 137fea64f9).
		return
	}
	m.nhtRebindMu.Lock()
	owed := m.nhtRebindOwed
	m.nhtRebindOwed, m.nhtRebindScheduled = false, false
	// running is set in the SAME critical section that clears owed, so Stop's
	// settle always sees one or the other (it then waits for reloadMu).
	m.nhtRebindRunning = owed
	m.nhtRebindMu.Unlock()
	if !owed {
		return
	}
	defer func() {
		m.nhtRebindMu.Lock()
		m.nhtRebindRunning = false
		m.nhtRebindMu.Unlock()
	}()
	ex, ok := m.executor().(vtyshConfigExecutor19083)
	if !ok {
		return
	}
	if err := m.reevaluateStaticNHTLocked19083(ex); err != nil {
		if m.lifetimeCtx().Err() != nil {
			// Stop cancelled this rebind mid-flight: owe it again, so Stop
			// settles it with its own context.
			m.nhtRebindMu.Lock()
			m.nhtRebindOwed = true
			m.nhtRebindMu.Unlock()
			return
		}
		slog.Warn("frr: static NHT re-evaluation failed; a static registered since the last NHT event may stay unfiltered until the next one (#19083)", "err", err)
	}
}

// settleOwedStaticNHTRebind19083 runs at the END of Stop, after every worker
// that could register a static has exited. A requested rebind no drain has
// completed is OWED: a static may have registered (unfiltered, on FRR 10.5.1)
// after the event that asked for it, for example a fast-install line that
// registered after a concurrent demotion removed its VIP. Abandoning it would
// leave that static active and exportable on a stopping node (Codex P2 on
// 137fea64f9). So Stop runs it here, under reloadMu, with its own context (the
// lifetime is already cancelled). Bounded: reloadMu is polled for at most
// staticNHTStopBudget19083 and the rebind exec gets the same; on either
// failing, the residue is logged at ERROR and Stop returns.
//
// This is the one FRR write Stop can make (R24 NEW-C), and only when a rebind
// is owed or running: the rebind's binding lines (alternate, then primary).
// Its worst-case addition to Stop is staticNHTStopBudget19083 for the lock,
// the same again for the exec, plus the exec's WaitDelay (5 s): about 9 s,
// inside the unit's TimeoutStopSec=20. With nothing owed or running, Stop
// writes nothing to FRR.
func (m *Manager) settleOwedStaticNHTRebind19083() {
	m.nhtRebindMu.Lock()
	busy := m.nhtRebindOwed || m.nhtRebindRunning
	m.nhtRebindMu.Unlock()
	if !busy {
		return
	}
	ex, ok := m.executor().(vtyshConfigExecutor19083)
	if !ok {
		return
	}
	deadline := time.Now().Add(staticNHTStopBudget19083)
	for !m.reloadMu.TryLock() {
		if time.Now().After(deadline) {
			slog.Error("frr: stopping with a static NHT re-evaluation owed while the FRR writer lock is busy; a static registered since the last NHT event may stay an active, exportable route (#19083)")
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	defer m.reloadMu.Unlock()
	m.nhtRebindMu.Lock()
	owed := m.nhtRebindOwed
	m.nhtRebindOwed = false
	m.nhtRebindMu.Unlock()
	if !owed {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), staticNHTStopBudget19083)
	defer cancel()
	if err := m.rebindStaticNHTLocked19083(ctx, ex); err != nil {
		slog.Error("frr: the static NHT re-evaluation owed at stop failed; a static registered since the last NHT event may stay an active, exportable route (#19083)", "err", err)
		return
	}
	slog.Info("frr: settled the static NHT re-evaluation owed at stop (#19083)")
}

// reevaluateStaticNHTLocked19083 is the rebind itself. Caller holds reloadMu
// and has checked the lifetime. It runs under its own bound, so a caller whose
// own context expired can still force the re-evaluation.
//
// Any partial application (a rejected line, a kill, a timeout) can leave the
// ALTERNATE map bound. Filtering is identical, but frr-reload.py's delete pass
// runs before its add pass, so the next diff reload would unbind the alternate
// before binding the primary: an unbound window in which every filtered static
// re-installs as an active, exportable blackhole (Codex P1 / R22 #5 on
// 959251c9ee). So the binding restore is PENDING from before the batch until
// the whole batch is known applied; restoreStaticNHTBindingLocked19083 settles
// it before any diff reload.
func (m *Manager) reevaluateStaticNHTLocked19083(ex vtyshConfigExecutor19083) error {
	ctx, cancel := context.WithTimeout(m.lifetimeCtx(), staticNHTReevalTimeout19083)
	defer cancel()
	return m.rebindStaticNHTLocked19083(ctx, ex)
}

// rebindStaticNHTLocked19083 runs the rebind batch under ctx. Caller holds
// reloadMu.
func (m *Manager) rebindStaticNHTLocked19083(ctx context.Context, ex vtyshConfigExecutor19083) error {
	bound, err := m.writtenSectionBindsStaticNHT19083()
	if err != nil || !bound {
		return err
	}
	lines := append(staticNHTBindLines19083(clusterStaticNHTRouteMapAlt19083),
		staticNHTBindLines19083(clusterStaticNHTRouteMap19083)...)
	m.staticNHTRestorePending19083 = true
	if out, err := ex.VtyshConfigLines(ctx, lines); err != nil {
		return fmt.Errorf("re-evaluate static NHT (#19083): %w: %s", err, strings.TrimSpace(string(out)))
	}
	m.staticNHTRestorePending19083 = false
	return nil
}

// writtenSectionBindsStaticNHT19083 reports whether frr.conf as last written
// binds the primary map (cluster mode). Caller holds reloadMu.
func (m *Manager) writtenSectionBindsStaticNHT19083() (bool, error) {
	data, err := os.ReadFile(m.frrConf)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return strings.Contains(string(data), staticNHTBindLines19083(clusterStaticNHTRouteMap19083)[0]+"\n"), nil
}

// restoreStaticNHTBindingLocked19083 runs before every diff reload
// (reloadLocked, retryReloadOnce, and #19050's in-doubt authoritative reload).
// Caller holds reloadMu. While a restore is pending (an interrupted rebind, or a
// new Manager: a previous xpfd may have been killed mid-rebind) and the section
// being applied binds the primary map, the reload may start only once zebra is
// POSITIVELY observed with the primary (or nothing) bound in both families:
//   - both families read as the primary or none (a fresh FRR, whose reload
//     adds the binding): settled, no write;
//   - anything else, including an unreadable family: bind the primary by
//     direct replacement (one name change, no unbound moment; idempotent when
//     already bound, R24 P3-1), then read both families back.
//
// What lets the reload start after that write (R24 NEW-1 on 9d7abd581a):
//   - a read-back of the primary in both families: verified;
//   - a read-back zebra ANSWERED but whose output has no parseable static row
//     (a parse miss): the reload starts with an ERROR log. The write was a
//     direct replacement of both families and vtysh reported success, which
//     is the evidence. Failing closed here would wedge every FRR apply on
//     every cluster node from startup (New sets the restore pending) the
//     moment an FRR update changes the output's layout, and a restart would
//     not clear it.
//
// Fails closed (pending kept, error returned, the caller does not start the
// reload; the degraded retry repeats it):
//   - the write failed;
//   - a read-back exec failed (zebra did not answer in time);
//   - a family was positively read back as anything but the primary.
//
// (Codex P1 on d8b6021582: an unreadable state used to let the reload delete
// the alternate's binding before adding the primary's.) Liveness (R24 P3-2,
// Codex P3 on 137fea64f9): each read has its own staticNHTReadTimeout19083
// and the write its own staticNHTReevalTimeout19083, so one restore holds
// reloadMu for at most 4 reads + 1 write (+ the exec WaitDelay). Every FRR
// apply stays held while the direct write fails, a `show ip|ipv6 nht
// route-map` read-back exec fails or exceeds its budget, or zebra positively
// reports a non-primary binding after the write: zebra not answering, or not
// accepting the binding. That is NOT the same condition as frr-reload.py
// failing (a different command, a longer budget). There is NO operator
// override: an override file was tried and removed after two review rounds
// found defects in the mechanism itself (Codex P2s on 18eb95d167 and
// afd8ae325c). Recovery is restoring zebra's ability to answer. The held
// apply has armed the degraded retry, which then restores the binding and
// reloads, with no xpfd restart; heldStaticNHTRestoreLocked19083 says so at
// ERROR, rate-limited per held episode.
// A successful rebind also clears the pending state. Output zebra returns but
// the parser cannot read, or a read command vtysh does not know, never holds
// applies once the write succeeded.
func (m *Manager) restoreStaticNHTBindingLocked19083() error {
	err := m.restoreStaticNHTBindingOnceLocked19083()
	if err == nil && m.staticNHTHeldAttempts19083 > 0 {
		slog.Info("frr: the static NHT binding restore succeeded; FRR applies resume (#19083)",
			"held_attempts", m.staticNHTHeldAttempts19083)
		m.staticNHTHeldAttempts19083 = 0
	}
	return err
}

// restoreStaticNHTBindingOnceLocked19083 is one restore attempt (see
// restoreStaticNHTBindingLocked19083). Caller holds reloadMu.
func (m *Manager) restoreStaticNHTBindingOnceLocked19083() error {
	if !m.staticNHTRestorePending19083 {
		return nil
	}
	bound, err := m.writtenSectionBindsStaticNHT19083()
	if err != nil {
		return fmt.Errorf("restore static NHT binding (#19083): %w", err)
	}
	if !bound {
		// Standalone: the reload removes every binding and both maps. Pending
		// is NOT cleared (R24 P3-3): a failed or additive-fallback reload can
		// leave the alternate bound, and a later cluster apply must still
		// restore first. While no map is bound this costs nothing.
		return nil
	}
	ex, ok := m.executor().(vtyshConfigExecutor19083)
	if !ok {
		return nil
	}
	if m.lifetimeCtx().Err() != nil {
		return fmt.Errorf("restore static NHT binding (#19083): manager stopping")
	}
	want := frrName(clusterStaticNHTRouteMap19083)
	primaryOrNone := func(v string) bool { return v == "" || v == want }
	v4, r4 := m.readStaticNHTBinding19083("show ip nht route-map")
	v6, r6 := m.readStaticNHTBinding19083("show ipv6 nht route-map")
	if r4 == nhtReadOK19083 && r6 == nhtReadOK19083 && primaryOrNone(v4) && primaryOrNone(v6) {
		m.staticNHTRestorePending19083 = false
		return nil
	}
	ctx, cancel := context.WithTimeout(m.lifetimeCtx(), staticNHTReevalTimeout19083)
	out, werr := ex.VtyshConfigLines(ctx, staticNHTBindLines19083(clusterStaticNHTRouteMap19083))
	cancel()
	if werr != nil {
		return m.heldStaticNHTRestoreLocked19083(fmt.Errorf("restore static NHT binding (#19083): zebra had %s/%s: %w: %s",
			r4.show(v4), r6.show(v6), werr, strings.TrimSpace(string(out))))
	}
	a4, q4 := m.readStaticNHTBinding19083("show ip nht route-map")
	a6, q6 := m.readStaticNHTBinding19083("show ipv6 nht route-map")
	if q4 == nhtReadExecFailed19083 || q6 == nhtReadExecFailed19083 ||
		(q4 == nhtReadOK19083 && a4 != want) || (q6 == nhtReadOK19083 && a6 != want) {
		return m.heldStaticNHTRestoreLocked19083(fmt.Errorf("restore static NHT binding (#19083): not verified after binding %q: zebra reports %s/%s",
			want, q4.show(a4), q6.show(a6)))
	}
	if q4 == nhtReadParseMiss19083 || q6 == nhtReadParseMiss19083 {
		slog.Error("frr: cannot parse zebra's `show ip|ipv6 nht route-map` after binding the static NHT primary; trusting vtysh's success and starting the reload (#19083)",
			"was_v4", r4.show(v4), "was_v6", r6.show(v6), "read_back_v4", q4.show(a4), "read_back_v6", q6.show(a6), "now", want)
		m.staticNHTRestorePending19083 = false
		return nil
	}
	slog.Info("frr: restored the static NHT binding before the reload (#19083)",
		"was_v4", r4.show(v4), "was_v6", r6.show(v6), "now", want)
	m.staticNHTRestorePending19083 = false
	return nil
}

// heldStaticNHTRestoreLocked19083 logs a restore that holds FRR applies, with
// the operator's recovery action, and returns err. Caller holds reloadMu.
//
// Rate-limited per held episode (coordinator, CLAUDE.md logging rule). A held
// apply is retried by the degraded retry (15 s, 30 s, 60 s, then every 5 min),
// but ALSO by the ip-monitoring actuator every DefaultThrottle (3 s) while its
// state is dirty, and once per commit or HA reconcile. A zebra that fails
// fast (vtysh cannot connect) would otherwise log an ERROR every 3 s. So:
//   - the first held attempt of an episode logs the ERROR;
//   - later ones log a WARN at most once per staticNHTHeldLogEvery19083, with
//     the count, and are Debug otherwise;
//   - the restore succeeding ends the episode with one INFO
//     (restoreStaticNHTBindingLocked19083).
func (m *Manager) heldStaticNHTRestoreLocked19083(err error) error {
	m.staticNHTHeldAttempts19083++
	now := time.Now()
	switch {
	case m.staticNHTHeldAttempts19083 == 1:
		slog.Error("frr: FRR applies HELD: zebra did not answer or accept the static NHT binding restore. "+
			"Recover zebra (find the fault; if zebra is wedged, `systemctl restart frr`, which withdraws FRR's routes until it is back). "+
			"The degraded retry then restores the binding and reloads, with no xpfd restart (#19083)", "err", err)
		m.staticNHTHeldLastLog19083 = now
	case now.Sub(m.staticNHTHeldLastLog19083) >= staticNHTHeldLogEvery19083:
		slog.Warn("frr: FRR applies still HELD: zebra does not answer or accept the static NHT binding restore; recover zebra (see the first ERROR) (#19083)",
			"held_attempts", m.staticNHTHeldAttempts19083, "err", err)
		m.staticNHTHeldLastLog19083 = now
	default:
		slog.Debug("frr: FRR applies still held by the static NHT binding restore (#19083)",
			"held_attempts", m.staticNHTHeldAttempts19083, "err", err)
	}
	return err
}

// nhtRead19083 is the outcome of one binding read: the exec failing (zebra did
// not answer in time) is told apart from output with no parseable static row
// (R24 NEW-1).
type nhtRead19083 int

const (
	nhtReadOK19083 nhtRead19083 = iota
	nhtReadExecFailed19083
	nhtReadParseMiss19083
)

func (r nhtRead19083) show(v string) string {
	switch r {
	case nhtReadExecFailed19083:
		return "<no answer>"
	case nhtReadParseMiss19083:
		return "<unparseable>"
	}
	if v == "" {
		return "none"
	}
	return v
}

// readStaticNHTBinding19083 reads the map bound to staticd's next-hop tracking
// for one family from zebra (`show ip|ipv6 nht route-map`: a "%-24s  : %-10s"
// row per protocol, "none" when unset; FRR zebra_routemap.c show_vrf_nht_rm.
// The real 10.5.1 and 10.6.0 outputs are the testdata fixtures
// show_*_nht_routemap_*_19083.txt). "" means none. Each read has its own
// staticNHTReadTimeout19083.
//
// It calls the executor directly, deliberately BYPASSING the vtysh funnel
// (m.vtysh and its diagcmd.VtyshLimiter; R24 NEW-D): the restore runs under
// reloadMu ahead of every FRR apply, so an ErrVtyshBusy from diagnostic
// commands saturating the limiter must never be able to hold applies. The
// read is two bounded commands per restore, not a diagnostic stream.
//
// A command vtysh itself does not know (`% Unknown command`, exit 1, FRR 10.5.1
// probe on udp fw1) is COMMAND DRIFT, not a daemon that did not answer: it is a
// parse miss (R24 NEW-A). It will never succeed, so failing closed on it would
// wedge every apply from startup.
func (m *Manager) readStaticNHTBinding19083(cmd string) (string, nhtRead19083) {
	ctx, cancel := context.WithTimeout(m.lifetimeCtx(), staticNHTReadTimeout19083)
	defer cancel()
	out, err := m.executor().Vtysh(ctx, cmd)
	if err != nil {
		if ctx.Err() == nil && strings.Contains(err.Error(), "% Unknown command") {
			return "", nhtReadParseMiss19083
		}
		return "", nhtReadExecFailed19083
	}
	v, ok := parseStaticNHTBinding19083(out)
	if !ok {
		return "", nhtReadParseMiss19083
	}
	return v, nhtReadOK19083
}

// parseStaticNHTBinding19083 returns the default VRF's static row of a
// `show ip|ipv6 nht route-map` output.
func parseStaticNHTBinding19083(out string) (string, bool) {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[0] == "static" && f[1] == ":" {
			if f[2] == "none" {
				return "", true
			}
			return f[2], true
		}
	}
	return "", false
}
