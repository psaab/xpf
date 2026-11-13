package daemon

import (
	"context"
	"log/slog"
	"maps"
	"time"

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
// the RG's ownership epoch, the cluster mastership generation of every RG the
// static render reads, the active config, the FRR unconditional write
// generation, and no factory reset in progress.

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
// generation (cluster.Manager.LocalMastershipSnapshot). The generation is
// monotonic and moves, under the cluster lock, on EVERY local primary edge
// (setLocalRGStateLocked), and a group created or deleted changes it too
// (a fresh generation, or 0 for an unknown RG). So two equal snapshots of an
// RG prove its IsLocalPrimary answer did not change in between, which
// comparing the answers alone cannot: an RG that went secondary -> primary ->
// secondary reads the same at both ends (review Codex P1-1, the ABA).
type rgMastership19050 struct {
	primary bool
	gen     uint64
}

// contributingMastership19050 snapshots the mastership of every RG whose
// ownership the static render reads, plus the trigger RG. The static render
// reads ownership only through newFRRHADemotionState, which keys
// IsLocalPrimary by cfg.RethRGOwners(); RG0 and IsLocalPrimaryAny never demote
// a static hop (staticHopActive), so an RG that owns no RETH cannot change a
// static line and is not fenced: a peer-loss takeover that promotes RG0 beside
// the data RG must not cost the data RG its fast install.
//
// It takes the cluster read lock per RG and NOTHING else: no GroupStates(),
// whose transfer-readiness callback can import routes and query FRR, and no
// other I/O (review Codex P2-4). The pre-check runs it under the FRR
// manager's reloadMu. Per-RG reads suffice without one coherent cut: each
// RG's generation is monotonic, so equal values at the capture and at the
// pre-check prove that RG constant over the whole render between them.
func (d *Daemon) contributingMastership19050(cfg *config.Config, rgID int) map[int]rgMastership19050 {
	out := map[int]rgMastership19050{}
	if d.cluster == nil {
		return out
	}
	add := func(rg int) {
		if _, ok := out[rg]; ok {
			return
		}
		primary, gen := d.cluster.LocalMastershipSnapshot(rg)
		out[rg] = rgMastership19050{primary: primary, gen: gen}
	}
	add(rgID)
	if cfg != nil {
		for _, rg := range cfg.RethRGOwners() {
			add(rg)
		}
	}
	return out
}

// fastInstallInputs19050 is every input of the render the fast set came from.
type fastInstallInputs19050 struct {
	rgID       int
	epoch      uint64
	cfg        *config.Config
	writeGen   uint64
	mastership map[int]rgMastership19050
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
	now := d.contributingMastership19050(in.cfg, in.rgID)
	if !now[in.rgID].primary { // the render's own predicate (R4 B3)
		return false
	}
	return maps.Equal(now, in.mastership) // no contributing RG moved, not even and back (Codex P1-1)
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
	in.mastership = d.contributingMastership19050(in.cfg, rgID)
	if !in.mastership[rgID].primary {
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
	fc := d.assembleFRRConfigForActiveConfig(in.cfg, d.commitOverlayForConfig(in.cfg))
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
