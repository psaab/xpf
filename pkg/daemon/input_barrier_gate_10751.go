package daemon

import (
	"log/slog"
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

// removeEarlyInputBarrierForBootstrap lifts the #10751 pre-networkd barrier
// when the daemon runs in bootstrap mode (no committed configuration, or a
// fail-closed load). Bootstrap suppresses the ordinary apply that would hand
// the barrier off, while remote recovery itself needs management connections
// the barrier blocks — without this handoff a bootstrap boot retains a global
// DROP indefinitely (management lockout). Callers install any fail-closed
// fences FIRST (see the initManagers ordering) so data addresses keep scoped
// protection; the lifeline stays reachable throughout (established sessions
// never drop; new management connections work once the barrier lifts).
// Removal is idempotent (absent -> nil). A removal failure is LOUD (error
// log) but does not stop boot — the console remains for recovery.
func (d *Daemon) removeEarlyInputBarrierForBootstrap(reason string) {
	if err := nftInstaller.RemoveEarlyInputBarrier(); err != nil {
		slog.Error("bootstrap cannot lift early host-input barrier; management recovery may be blocked — use the console",
			"reason", reason, "err", tagNftInstallErr(err))
		return
	}
	d.earlyInputHandoffDone.Store(true)
	slog.Warn("bootstrap lifted early host-input barrier without an ordinary config apply; data-interface services are unenforced until the first commit",
		"reason", reason)
}
