package daemon

import (
	"context"
	"log/slog"
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
// the RG's ownership epoch, the live cluster predicate the render reads
// (IsLocalPrimary), the whole local ownership vector, the active config, the
// FRR unconditional write generation, and no factory reset in progress.

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

// localOwnershipVector19050 snapshots IsLocalPrimary for every configured RG.
func (d *Daemon) localOwnershipVector19050() map[int]bool {
	out := map[int]bool{}
	if d.cluster == nil {
		return out
	}
	for _, rg := range d.cluster.GroupStates() {
		out[rg.GroupID] = d.cluster.IsLocalPrimary(rg.GroupID)
	}
	return out
}

// fastInstallInputs19050 is every input of the render the fast set came from.
type fastInstallInputs19050 struct {
	rgID     int
	epoch    uint64
	cfg      *config.Config
	writeGen uint64
	owners   map[int]bool
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
	if d.cluster == nil || !d.cluster.IsLocalPrimary(in.rgID) { // the render's own predicate (R4 B3)
		return false
	}
	if d.store == nil || d.store.ActiveConfig() != in.cfg { // config promoted since the render
		return false
	}
	if d.frr == nil || d.frr.UnconditionalWriteGeneration() != in.writeGen { // C1 belt: a Clear or commit write
		return false
	}
	now := d.localOwnershipVector19050()
	if len(now) != len(in.owners) {
		return false
	}
	for rg, own := range in.owners {
		if now[rg] != own {
			return false
		}
	}
	return true
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
	in.owners = d.localOwnershipVector19050()
	if !in.owners[rgID] {
		return frr.FastSkipped
	}
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
	outcome, lines := d.frr.FastInstallStatics(want, func() bool { return d.fastInstallPrecheck19050(in) })
	slog.Debug("frr fast install (#19050)", "rg", rgID, "epoch", epoch, "outcome", outcome.String(), "lines", len(lines))
	return outcome
}
