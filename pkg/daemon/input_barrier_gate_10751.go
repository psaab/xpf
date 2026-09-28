package daemon

import (
	"log/slog"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// ensureEarlyInputProtectionForNaming verifies the #10751 pre-networkd input
// barrier is present before xpfd performs link activation. Interface renames
// bring links up (renameInterface ends with LinkSetUp), which makes kernel
// IPv6 link-locals reachable — the xpf-input-closed unit Requires xpfd so a
// failed barrier install blocks the daemon under systemd, and this gate covers
// direct starts (manual runs, raw-binary harnesses) that bypass unit
// dependencies. Returns true to proceed with activation.
//
//   - present → true (attested; the common path, one netlink round-trip).
//   - absent + reinstall succeeds → true (self-healed).
//   - absent + reinstall fails + nftables unusable → true with a loud warning
//     (unenforceable platform — never brick boot where no enforcement is
//     possible, matching the pre-barrier posture).
//   - absent + reinstall fails + nftables usable → false (fail closed).
//
// A presence-readback error warns and proceeds: the gate blocks on KNOWN-
// absent protection, not on observability failure (the subsequent barrier
// operations fail loudly on their own).
func ensureEarlyInputProtectionForNaming() bool {
	present, err := nftInstaller.EarlyInputBarrierPresent()
	if err != nil {
		slog.Warn("cannot attest early host-input barrier before link activation; proceeding",
			"err", tagNftInstallErr(err))
		return true
	}
	if present {
		return true
	}
	if err := nftInstaller.InstallEarlyInputBarrier(); err == nil {
		slog.Warn("early host-input barrier missing before link activation; reinstalled")
		return true
	} else if nftProbeAvailable() != nil {
		slog.Warn("early host-input barrier missing and nftables is unusable; proceeding without input protection",
			"err", tagNftInstallErr(err))
		return true
	}
	slog.Error("early host-input barrier missing and reinstall failed; refusing link activation",
		"err", tagNftInstallErr(err))
	return false
}

// Default lifelines admitted by the bootstrap input guard when detection
// yields nothing better. fxp0/em0 are the canonical management NICs and
// fab0/fab1 the cluster control links; a name with no such interface simply
// never matches, so over-listing defaults is safe.
var earlyInputBootstrapDefaultLifelines = []string{"fxp0", "em0", "fab0", "fab1"}

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
	lifelines := append([]string(nil), earlyInputBootstrapDefaultLifelines...)
	if name, found, err := detectLifelineInterfaceFn(); err != nil {
		slog.Warn("bootstrap lifeline detection failed; admitting default management interfaces only",
			"err", err)
	} else if found && name != "" {
		duplicate := false
		for _, existing := range lifelines {
			if existing == name {
				duplicate = true
				break
			}
		}
		if !duplicate {
			lifelines = append(lifelines, name)
		}
	}
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
