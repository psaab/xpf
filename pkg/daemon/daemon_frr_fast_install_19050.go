package daemon

import (
	"context"
	"log/slog"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/frr"
)

// #19050 option B, daemon half. On a promotion edge (the !prev && want edge of
// applyDirectVIPOwnershipWith, after the VIPs are added) the node installs its
// owned static lines through frr.Manager.FastInstallStatics, ahead of the
// coalesced HA reload that the same edge schedules. Measured on udp: the
// kernel default lands 39.5 ms (v4) / 57 ms (v6) after the VIP, against 618 /
// 610 ms on the reload path. Demotion needs nothing new: zebra NHT drops an
// owned default within ~20 ms of the VIP leaving, and the demotion reload
// removes the lines (design: #19050 issuecomment-6763838572 and the v2.1-v2.3
// addenda).
//
// The fast path changes WHEN, never WHAT: every line it installs is a line the
// next HA render contains verbatim, because the pre-check (under the FRR
// manager's reloadMu) requires every input of that render to be unchanged:
// the RG's ownership epoch, the cluster mastership generation of every RG
// whose ownership the render READ (recorded during the render itself), the
// active config, the FRR unconditional write generation, and no factory reset
// in progress.

// fastRenderSemTimeout19050 bounds the wait for applySem around the render. A
// commit holding applySem longer means the fast path simply skips: the
// scheduled reload installs the lines.
const fastRenderSemTimeout19050 = 500 * time.Millisecond

// bumpDirectVIPEpoch19050 advances rgID's ownership epoch and returns the new
// value. Called under directVIPMu, ONLY on a real ownership edge (prev !=
// want); a safety-net re-add of an owned RG must not move it (review R4 B2).
// directVIPEpochMu is a leaf lock.
func (d *Daemon) bumpDirectVIPEpoch19050(rgID int) uint64 {
	d.directVIPEpochMu.Lock()
	defer d.directVIPEpochMu.Unlock()
	if d.directVIPEpoch == nil {
		d.directVIPEpoch = make(map[int]uint64)
	}
	d.directVIPEpoch[rgID]++
	return d.directVIPEpoch[rgID]
}

func (d *Daemon) directVIPEpoch19050(rgID int) uint64 {
	d.directVIPEpochMu.Lock()
	defer d.directVIPEpochMu.Unlock()
	return d.directVIPEpoch[rgID]
}

// triggerFRRFastInstall19050 starts the fast install for a promotion edge.
// It never blocks the VIP path.
func (d *Daemon) triggerFRRFastInstall19050(rgID int, epoch uint64) {
	if fn := d.frrFastInstallFn; fn != nil {
		fn(rgID, epoch)
		return
	}
	if d.frr == nil {
		return
	}
	go func() { _ = d.frrFastInstall19050(rgID, epoch) }()
}

// rgMastership19050 is one RG's local ownership and its cluster mastership
// generation (cluster.Manager.LocalMastershipSnapshot, one read lock, no
// callback). The generation is monotonic and moves, under the cluster lock,
// on EVERY local primary edge (setLocalRGStateLocked); a group created gets a
// fresh non-zero one, and an unknown group reads 0. So an RG whose generation
// is equal at two instants did not change ownership in between, which
// comparing the answers alone cannot show: an RG that went secondary ->
// primary -> secondary reads the same at both ends (review Codex P1-1, the
// ABA).
type rgMastership19050 struct {
	primary bool
	gen     uint64
}

// ownershipRecorder19050 serves the fast render's cluster-ownership reads
// (frrHAOwnership) and records, per RG, the FIRST answer with its generation.
// The pre-check then requires every recorded RG to be unchanged, so the fence
// is exactly the render's own dependency set: an RG the render never read
// cannot change a line, and one it did read, directly or not, is fenced. The
// first version listed the RGs it judged able to change a static line (RETH
// owners) and missed RG0, which reaches statics through the IS-IS distance
// guard (globalActive -> filterISIS -> renderStaticRouteWithISISDistanceGuard,
// review Codex on 11e4c6f47e).
//
// Recording the FIRST read is enough when an RG is read more than once: if
// any later read saw another state, the RG changed after the first read, so
// its generation now differs from the recorded one. The "any RG primary" read
// (the RG0-unknown fallback) needs no record of its own: the capture records
// the trigger RG, and the pre-check requires it primary at that same
// generation, so it was primary throughout and "any" was true throughout.
//
// Every method uses only callback-free cluster reads: never GroupStates(),
// whose transfer-readiness callback can import routes and query FRR, and
// which would run under reloadMu at the pre-check (review Codex P2-4). One
// goroutine renders and then runs the pre-check, so it needs no lock.
type ownershipRecorder19050 struct {
	c     *cluster.Manager
	reads map[int]rgMastership19050
}

func newOwnershipRecorder19050(c *cluster.Manager) *ownershipRecorder19050 {
	return &ownershipRecorder19050{c: c, reads: map[int]rgMastership19050{}}
}

func (r *ownershipRecorder19050) read(rgID int) rgMastership19050 {
	primary, gen := r.c.LocalMastershipSnapshot(rgID)
	m := rgMastership19050{primary: primary, gen: gen}
	if _, seen := r.reads[rgID]; !seen {
		r.reads[rgID] = m
	}
	return m
}

func (r *ownershipRecorder19050) IsLocalPrimary(rgID int) bool { return r.read(rgID).primary }

// LocalGroupPrimary answers known from the generation: a known group's is
// never 0 and an unknown group's always is (TestMastershipGenerationKnown19050).
func (r *ownershipRecorder19050) LocalGroupPrimary(rgID int) (bool, bool) {
	m := r.read(rgID)
	return m.primary, m.gen != 0
}

// IsLocalPrimaryAny is fenced by the trigger RG's record (see the type).
func (r *ownershipRecorder19050) IsLocalPrimaryAny() bool { return r.c.IsLocalPrimaryAny() }

// current reports whether every ownership answer the render read still holds.
func (r *ownershipRecorder19050) current() bool {
	for rgID, m := range r.reads {
		primary, gen := r.c.LocalMastershipSnapshot(rgID)
		if (rgMastership19050{primary: primary, gen: gen}) != m {
			return false
		}
	}
	return true
}

// fastInstallInputs19050 is every input of the render the fast set came from.
type fastInstallInputs19050 struct {
	rgID     int
	epoch    uint64
	cfg      *config.Config
	writeGen uint64
	owners   *ownershipRecorder19050
}

// fastInstallPrecheck19050 runs under the FRR manager's reloadMu, right
// before the exec. It takes no FRR manager lock (UnconditionalWriteGeneration
// is an atomic load), so the order is reloadMu -> cluster lock /
// directVIPEpochMu, and nothing takes them the other way round.
func (d *Daemon) fastInstallPrecheck19050(in fastInstallInputs19050) bool {
	if d.isResetting() { // C1 (R14): the reset barrier fences buildMu, not reloadMu
		return false
	}
	if d.directVIPEpoch19050(in.rgID) != in.epoch { // the RG changed ownership since the trigger
		return false
	}
	if d.store == nil || d.store.ActiveConfig() != in.cfg { // config promoted since the render
		return false
	}
	if d.frr == nil || d.frr.UnconditionalWriteGeneration() != in.writeGen { // C1 belt: a Clear or commit write
		return false
	}
	if d.cluster == nil || in.owners == nil {
		return false
	}
	if primary, _ := d.cluster.LocalMastershipSnapshot(in.rgID); !primary { // the render's own predicate (R4 B3)
		return false
	}
	return in.owners.current() // no RG the render read moved, not even and back (Codex P1-1)
}

// frrFastInstall19050 renders and fast-installs; it returns the outcome
// (FastSkipped when it gave up before reaching the FRR manager).
func (d *Daemon) frrFastInstall19050(rgID int, epoch uint64) frr.FastInstallOutcome {
	if d.frr == nil || d.store == nil || d.cluster == nil || d.applySem == nil || d.isResetting() {
		return frr.FastSkipped
	}
	in := fastInstallInputs19050{rgID: rgID, epoch: epoch}
	in.cfg = d.store.ActiveConfig()
	if in.cfg == nil {
		return frr.FastSkipped
	}
	in.writeGen = d.frr.UnconditionalWriteGeneration()
	in.owners = newOwnershipRecorder19050(d.cluster)
	if !in.owners.IsLocalPrimary(rgID) { // records the trigger RG's generation
		return frr.FastSkipped
	}
	d.fastInstallTestHook19050("captured")
	// N1: render under applySem, as the HA reconcile does, and release it
	// BEFORE the FRR manager's reloadMu (commit takes applySem then reloadMu).
	ctx, cancel := context.WithTimeout(d.applyCancelCtx(), fastRenderSemTimeout19050)
	defer cancel()
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		slog.Debug("frr fast install skipped: applySem busy (#19050)", "rg", rgID, "err", err)
		return frr.FastSkipped
	}
	fc := d.assembleFRRConfigForActiveConfigOwned(in.cfg, d.commitOverlayForConfig(in.cfg), in.owners)
	d.applySem.Release(1)
	want := d.frr.RenderStaticLines(fc)
	d.fastInstallTestHook19050("rendered")
	outcome, lines := d.frr.FastInstallStatics(want, func() bool { return d.fastInstallPrecheck19050(in) })
	slog.Debug("frr fast install (#19050)", "rg", rgID, "epoch", epoch, "outcome", outcome.String(), "lines", len(lines))
	return outcome
}

// fastInstallTestHook19050 runs the test seam, if any, at a named point of
// frrFastInstall19050: "captured" (inputs captured, before the render) and
// "rendered" (after the render, before the FRR manager's reloadMu). Nil in
// production.
func (d *Daemon) fastInstallTestHook19050(stage string) {
	if fn := d.frrFastInstallHook; fn != nil {
		fn(stage)
	}
}
