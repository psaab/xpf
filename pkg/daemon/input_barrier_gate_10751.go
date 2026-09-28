package daemon

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// ensureEarlyInputProtectionForNaming verifies the #10751 pre-networkd input
// guard is present before xpfd performs link activation. Interface renames
// bring links up (renameInterface ends with LinkSetUp), which makes kernel
// IPv6 link-locals reachable — the xpf-input-closed unit Requires xpfd so a
// failed barrier install blocks the daemon under systemd, and this gate covers
// direct starts (manual runs, raw-binary harnesses) that bypass unit
// dependencies. Returns true to proceed with activation. All installs use the
// lifeline-admitting variant so any later retention admits recovery.
//
//   - present → converge to the lifeline variant (best-effort) and return
//     true; the standing table still protects if the converge fails.
//   - absent + variant install succeeds → true (self-healed).
//   - absent + install fails + nftables unusable → true with a loud warning
//     (unenforceable platform — never brick boot where no enforcement is
//     possible, matching the pre-barrier posture).
//   - absent + install fails + nftables usable → false (fail closed).
//
// A presence-readback error warns and proceeds: the gate blocks on KNOWN-
// absent protection, not on observability failure (the subsequent barrier
// operations fail loudly on their own).
func ensureEarlyInputProtectionForNaming(cfg *config.Config) bool {
	present, err := nftInstaller.EarlyInputBarrierPresent()
	if err != nil {
		slog.Warn("cannot attest early host-input barrier before link activation; proceeding",
			"err", tagNftInstallErr(err))
		return true
	}
	lifelines := resolveEarlyInputGuardLifelines(cfg)
	if !present {
		if err := nftInstaller.InstallEarlyInputBarrierWithLifelineAdmit(lifelines); err == nil {
			slog.Warn("early host-input barrier missing before link activation; installed lifeline guard",
				"lifelines", lifelines)
			return true
		} else if nftProbeAvailable() != nil {
			slog.Warn("early host-input barrier missing and nftables is unusable; proceeding without input protection",
				"err", tagNftInstallErr(err))
			return true
		}
		slog.Error("early host-input barrier missing and guard install failed; refusing link activation",
			"lifelines", lifelines, "err", tagNftInstallErr(err))
		return false
	}
	// Present (global unit form or an older guard): converge to the current
	// lifeline variant so any later retention admits recovery. Best-effort:
	// the standing table still protects on failure; the first apply retries.
	if err := nftInstaller.InstallEarlyInputBarrierWithLifelineAdmit(lifelines); err != nil {
		slog.Warn("cannot converge early barrier to lifeline guard before link activation; proceeding with standing table",
			"lifelines", lifelines, "err", tagNftInstallErr(err))
	}
	return true
}

// lifelineRecordNameFn resolves the persisted lifeline record to its current
// kernel name. A package var so resolver tests can pin record-present/absent
// without sysfs.
var lifelineRecordNameFn = resolveLifelineCurrentName

// resolveEarlyInputGuardLifelines computes the iifname admit set for the
// pre-handoff lifeline guard, from most- to least-verified identity:
//
//   - Canonical defaults: em0, fab0, fab1, the vrf-mgmt master, and fxp0
//     unless an explicit non-fxp0 management leaf narrows it out (OQ-D: a
//     repurposed fxp0 is revenue, not management). vrf-mgmt is admitted
//     because Linux VRF receive switches skb->dev to the master for
//     ordinary local delivery on enslaved interfaces — slave names alone
//     need not match (B4); both master and slaves stay listed so either
//     observed path matches.
//   - Verified protected set (B6): the persisted lifeline record plus the
//     explicit management-interface leaf, via the same pure core the fence
//     builders use — record/leaf over name guesses.
//   - Detected default-route NIC: recovery fallback ONLY when no verified
//     distinct identity exists (no leaf and no resolved record). Otherwise
//     an unlisted detected NIC is data until proven management and stays
//     closed. With zero identity the NIC is the only recovery hint; admit
//     it whole and document the caveat (a static-default-via-data boot
//     opens that NIC for the bootstrap window — inherent without config;
//     the first commit converges to configured policy).
//
// The returned set is sorted and deduplicated. Whole-NIC (not
// destination-scoped) admits are deliberate: daddr scoping from a live
// snapshot goes stale on DHCP renewal, while no config exists to tell
// revenue IPs from management IPs on one NIC — interface identity plus
// narrowing is the finest verifiable boundary available pre-config.
func resolveEarlyInputGuardLifelines(cfg *config.Config) []string {
	mgmtLeaf := ""
	if cfg != nil {
		mgmtLeaf = cfg.System.ManagementInterface
	}
	set := map[string]bool{}
	for _, d := range []string{"em0", "fab0", "fab1", config.ManagementVRFDeviceName} {
		set[d] = true
	}
	if mgmtLeaf == "" || mgmtLeaf == defaultMgmtInterface {
		set[defaultMgmtInterface] = true
	}
	recordName, recordOK := "", false
	if name, ok := lifelineRecordNameFn(); ok && name != "" {
		recordName, recordOK = name, true
	}
	for name := range protectedInterfacesWith(mgmtLeaf, recordName) {
		set[name] = true
	}
	if name, found, err := detectLifelineInterfaceFn(); err != nil {
		slog.Warn("lifeline detection failed; guard admits resolved identities and defaults only", "err", err)
	} else if found && name != "" && !set[name] {
		if mgmtLeaf == "" && !recordOK {
			set[name] = true
		} else {
			slog.Info("default-route NIC is not a verified management identity; excluding it from the input guard",
				"interface", name)
		}
	}
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// requireEarlyInputProtectionPreApply converges the pre-handoff lifeline
// guard before an apply performs link-affecting mutations. Called at apply
// entry (before any reconcile) and at the host-inbound tail top (covering
// direct tail callers); both are no-op atomic checks post-handoff. A failed
// install fails the apply closed with STALE recorded.
func (d *Daemon) requireEarlyInputProtectionPreApply(cfg *config.Config) error {
	if d.earlyInputHandoffDone.Load() {
		return nil
	}
	// Doing pre-handoff work proves this process has not handed off; drop a
	// stale marker from a previous process so the CLI guard stays accurate.
	clearEarlyInputHandoffMarker()

	if err := nftInstaller.InstallEarlyInputBarrierWithLifelineAdmit(resolveEarlyInputGuardLifelines(cfg)); err != nil {
		err = tagNftInstallErr(err)
		d.noteHostInboundApplyFailed(time.Now())
		return fmt.Errorf("install early host-input guard before first handoff: %w", err)
	}
	return nil
}

// ensureEarlyInputBootstrapGuard replaces the #10751 global pre-networkd
// barrier with the lifeline-admitting variant when the daemon runs in
// bootstrap mode (no committed configuration, or a fail-closed load).
// Bootstrap suppresses the ordinary apply that would hand the barrier off,
// while remote recovery itself needs management connections the global
// barrier blocks — but lifting the barrier entirely would reopen data and
// link-local ingress the fail-closed fences do not cover (fence discovery
// or install can fail, and fences exclude link-locals). The variant keeps
// all non-lifeline ingress DROP-closed while the management lifeline stays
// reachable for recovery. Same table name, so the first ordinary apply
// removes it through the unchanged handoff path (handoffDone stays false
// until then). A variant-install failure retains the global barrier (fail
// closed) and is LOUD — the console remains for recovery.
func (d *Daemon) ensureEarlyInputBootstrapGuard() {
	var cfg *config.Config
	if d.store != nil {
		cfg = d.store.ActiveConfig()
	}
	lifelines := resolveEarlyInputGuardLifelines(cfg)
	// Bootstrap runs once per process start, always pre-handoff: drop any
	// stale marker for the same invariant as above.
	clearEarlyInputHandoffMarker()

	if err := nftInstaller.InstallEarlyInputBarrierWithLifelineAdmit(lifelines); err != nil {
		d.earlyInputGuardSwapFailed.Store(true)
		slog.Error("bootstrap cannot install lifeline-admitting input guard; global barrier retained — use the console if management is unreachable",
			"lifelines", lifelines, "err", tagNftInstallErr(err))
		return
	}
	d.earlyInputGuardSwapFailed.Store(false)
	slog.Warn("bootstrap swapped the global input barrier for a lifeline-admitting guard; data-interface services stay closed until the first commit",
		"lifelines", lifelines)
}

// sampleHostInboundSnapshots samples the interface address rows for the
// host-inbound apply path. A package var so handoff-race tests can script an
// address transition between the install sample and the handoff re-sample;
// production always samples the kernel. See SnapshotNewcomerAddrs.
var sampleHostInboundSnapshots = dpuserspace.BuildInterfaceSnapshots

// hostInboundHasPendingEnforcingIntentFromSnapshots reports whether any
// configured enforcement scope is still unresolved in snaps: a zone with
// interfaces but no address yet (coarse, zone-level), or a specific
// interface-unit/family with a DHCP client but no lease (fine-grained:
// mixed zones, sequential v4/v6 acquisition). Consulted ONLY pre-handoff,
// over the handoff re-sample, to retain the early barrier until every
// intended scope installs its own protection — otherwise an unrelated or
// first-family handoff lifts the global guard while pending ingress stays
// unprotected until a later apply.
func hostInboundHasPendingEnforcingIntentFromSnapshots(cfg *config.Config, snaps []dpuserspace.InterfaceSnapshot) bool {
	return dpuserspace.HostInboundPendingIntentFromSnapshots(cfg, snaps)
}

// removeEarlyInputBarrierAtHandoff removes the barrier for a first handoff
// after re-attesting it. Entry-time attestation leaves a TOCTOU across the
// tail: a privileged flush between enforcement install and this removal
// wipes both the new tables and the barrier, and absent-removal success
// would then record a handoff over wiped enforcement. Closing it:
//
//   - barrier present → remove (normal path).
//   - barrier missing → reinstall the guard and FAIL WITHOUT removing (the
//     just-installed enforcement is suspect; the restored guard keeps the
//     box closed and the next apply retries the whole handoff).
//   - readback error → reinstall, then REFUSE as well: an unreadable
//     readback cannot prove the just-installed enforcement survived, so a
//     concurrent flush plus broken list would otherwise record a handoff
//     over wiped tables. Retry the entire apply before any removal.
//
// expectedTables names the enforcement tables this handoff installed and now
// relies on (main table, plus the gap table when one stands). After a
// successful removal the helper re-reads their presence (#10751 R4-5): a
// flush interleaved between the install and the removal wipes enforcement
// while absent-removal still succeeds, so presence must be re-proven AFTER
// the removal, not just before. A missing table (or an unreadable readback)
// reinstalls the guard and refuses WITHOUT recording handoff-done. The
// teardown path passes nil — intended-empty needs no readback. A flush AFTER
// this readback is an accepted residual (no kernel-side transaction couples
// the two syscalls; the window is one list round-trip).
//
// Post-handoff calls remove idempotently (barrier expected absent — e.g.
// ExecReload residue cleanup); no attestation there. Install success implies
// exact shape: the installer flushes one atomic nf_tables batch, so success
// leaves no partial table to verify.
func (d *Daemon) removeEarlyInputBarrierAtHandoff(cfg *config.Config, expectedTables []string) error {
	if d.earlyInputHandoffDone.Load() {
		return nftInstaller.RemoveEarlyInputBarrier()
	}
	present, err := nftInstaller.EarlyInputBarrierPresent()
	if err == nil && present {
		if removeErr := nftInstaller.RemoveEarlyInputBarrier(); removeErr != nil {
			return removeErr
		}
		for _, table := range expectedTables {
			ok, readErr := nftInstaller.TablePresent(table)
			if readErr == nil && ok {
				continue
			}
			if readErr != nil {
				slog.Warn("cannot re-verify enforcement after barrier removal; reinstalling guard and refusing handoff",
					"table", table, "err", tagNftInstallErr(readErr))
			} else {
				slog.Warn("enforcement table missing after barrier removal (concurrent flush?); guard reinstalled, handoff refused",
					"table", table)
			}
			if installErr := nftInstaller.InstallEarlyInputBarrierWithLifelineAdmit(resolveEarlyInputGuardLifelines(cfg)); installErr != nil {
				return fmt.Errorf("reinstall early guard at handoff: %w", tagNftInstallErr(installErr))
			}
			if readErr != nil {
				return fmt.Errorf("enforcement table %s unreadable after barrier removal; guard reinstalled, handoff refused", table)
			}
			return fmt.Errorf("enforcement table %s missing after barrier removal; guard reinstalled, handoff refused", table)
		}
		return nil
	}
	if err != nil {
		slog.Warn("cannot re-attest early barrier at handoff; reinstalling guard and refusing handoff",
			"err", tagNftInstallErr(err))
	} else {
		slog.Warn("early barrier missing at handoff (concurrent flush wiped enforcement?); guard reinstalled, handoff refused")
	}
	if installErr := nftInstaller.InstallEarlyInputBarrierWithLifelineAdmit(resolveEarlyInputGuardLifelines(cfg)); installErr != nil {
		return fmt.Errorf("reinstall early guard at handoff: %w", tagNftInstallErr(installErr))
	}
	if err != nil {
		return errors.New("early barrier state unreadable at handoff; guard reinstalled, handoff refused")
	}
	return errors.New("early barrier missing at handoff; guard reinstalled, handoff refused")
}

// hostInboundHandoffExpectedTables names the enforcement tables a fallback
// handoff relies on: the main table, plus the gap table when one stands
// beside it.
func hostInboundHandoffExpectedTables(gapActive bool) []string {
	if gapActive {
		return []string{xnft.HostInboundTableName, xnft.HostInboundGapTableName}
	}
	return []string{xnft.HostInboundTableName}
}

// errEarlyInputProtectionRefused marks an activation refusal: the early
// barrier is known-absent and cannot be reinstalled while nftables is
// usable. Callers match it with errors.Is to abort link activation while
// letting unrelated naming failures keep their historical handling.
var errEarlyInputProtectionRefused = errors.New("early host-input barrier missing and reinstall failed")

// EarlyInputHandoffMarkerPath records a completed first handoff on disk so
// the `xpfd input-barrier` command (which cannot see the daemon's in-memory
// latch) refuses a post-handoff reinstall. /run is tmpfs: the marker starts
// absent on every boot. A package var so tests redirect it to a temp dir.
var EarlyInputHandoffMarkerPath = "/run/xpf/early-input-handoff.done"

// setEarlyInputHandoffDone records a completed first handoff in memory and
// on disk (best-effort marker write; a write failure only weakens the CLI
// guard, never the commit). All handoff-completion sites funnel through
// here so the two records cannot diverge.
func (d *Daemon) setEarlyInputHandoffDone() {
	d.earlyInputHandoffDone.Store(true)
	if err := os.MkdirAll(filepath.Dir(EarlyInputHandoffMarkerPath), 0755); err != nil {
		slog.Warn("cannot record early-input handoff marker; CLI reload guard degraded", "err", err)
		return
	}
	if err := os.WriteFile(EarlyInputHandoffMarkerPath, []byte("handed-off\n"), 0644); err != nil {
		slog.Warn("cannot record early-input handoff marker; CLI reload guard degraded", "err", err)
	}
}

// EarlyInputHandoffMarked reports whether the handoff marker file exists
// (a previous handoff completed in this boot).
func EarlyInputHandoffMarked() bool {
	_, err := os.Stat(EarlyInputHandoffMarkerPath)
	return err == nil
}

// clearEarlyInputHandoffMarker removes a stale marker when a new process
// starts pre-handoff work, restoring the "marker ⟺ current process handed
// off" invariant after a restart. Best-effort; failures are silent (a stale
// marker only makes the CLI conservative until the next handoff).
func clearEarlyInputHandoffMarker() {
	_ = os.Remove(EarlyInputHandoffMarkerPath)
}

// EarlyInputGuardSwapFailed reports whether the latest bootstrap
// lifeline-guard swap failed (global barrier retained instead). Feeds the
// xpf_early_input_guard_swap_failed gauge and /health.
func (d *Daemon) EarlyInputGuardSwapFailed() bool {
	if d == nil {
		return false
	}
	return d.earlyInputGuardSwapFailed.Load()
}
