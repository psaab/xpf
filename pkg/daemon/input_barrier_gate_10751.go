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
