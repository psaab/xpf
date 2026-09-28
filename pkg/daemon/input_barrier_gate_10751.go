package daemon

import (
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
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
	if err := nftInstaller.InstallEarlyInputBarrierWithLifelineAdmit(lifelines); err != nil {
		slog.Error("bootstrap cannot install lifeline-admitting input guard; global barrier retained — use the console if management is unreachable",
			"lifelines", lifelines, "err", tagNftInstallErr(err))
		return
	}
	slog.Warn("bootstrap swapped the global input barrier for a lifeline-admitting guard; data-interface services stay closed until the first commit",
		"lifelines", lifelines)
}

// hostInboundHasPendingEnforcingIntent reports whether any configured
// enforcement scope is still unresolved: a zone with interfaces but no
// address yet (coarse, zone-level), or a specific interface-unit/family
// with a DHCP client but no lease (fine-grained: mixed zones, sequential
// v4/v6 acquisition). Consulted ONLY pre-handoff to retain the early
// barrier until every intended scope installs its own protection —
// otherwise an unrelated or first-family handoff lifts the global guard
// while pending ingress stays unprotected until a later apply.
func hostInboundHasPendingEnforcingIntent(cfg *config.Config) bool {
	if len(dpuserspace.AddresslessEnforcingZones(cfg)) > 0 {
		return true
	}
	return len(dpuserspace.AddresslessEnforcingInterfaces(cfg)) > 0
}
