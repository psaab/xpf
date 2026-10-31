package daemon

import (
	"github.com/psaab/xpf/pkg/config"
	"time"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/upgrade"
)

// daemonKernelSystem builds the kernel-channel KernelSystem with Gate 4's #6607
// dataplane-liveness probe wired.
//
// #7157: the three `pkg/daemon` construction sites used the BARE
// upgrade.NewKernelSystem(), which leaves HelperStatus nil — and ForwardBeacon's
// Precondition B is `if s.HelperStatus != nil`. So on the self-recover path the
// promotion gate silently collapsed to unit-liveness plus a host ping, while
// cmd/xpfd (newKernelConfig, via NewKernelSystemWithHelperStatus) had the full
// gate. Two callers of one gate disagreed about how strong it is, and the WEAKER
// one was the recovery path — the one that runs when something has already gone
// wrong.
//
// `systemctl is-active xpfd` is not a forwarding proof: a Type=simple unit
// reports active while its helper is down, stale or crash-looping and NOT
// forwarding — the exact state a kernel change is most likely to cause, and the
// one Gate 4 exists to catch.
//
// unitActive is passed nil deliberately: ForwardBeacon substitutes its own
// package-internal unitActiveProbeCtx(DefaultUnit), which is the SINGLE is-active
// primitive (#5808) — ctx-bounded so a wedged DBus is killed rather than blocking
// past the rollback deadline, and exit-code aware so "unit not found" is not read
// as "inactive". Re-implementing it here would be a second copy of a primitive
// that exists precisely to have one.
//
// The socket is resolved the same way the bootstrap path resolves it
// (dpuserspace.DefaultControlSocketPath(nil), bootstrap.go) rather than from the
// active config: this runs on a promotion/self-recover path where the config may
// not have compiled.
// #7157: config.IsManagementIfName is passed as the beacon's management-interface
// classifier. It is the #7515 SSOT for exactly this question — the same function
// the vrf-mgmt binder (managementVRFIfaceSet), the networkd `KeepMaster=yes` emitter and
// the ip-monitoring next-hop validator use — so this becomes a fourth consumer of
// one rule rather than a fourth copy of three prefixes. #7515 records that a
// divergence between those consumers is always a bug.
//
// Its known looseness (`emergency0`, `fabric0` and `fxpanything` all match — the
// defect is acknowledged in ifname_class_6731.go) is safe in THIS direction: the
// beacon uses the predicate only to REFUSE a target, so a false positive costs a
// fail-safe revert, never a promotion on an unproven kernel.
func daemonKernelSystem() upgrade.KernelSystem {
	return upgrade.NewKernelSystemWithHelperStatus(
		nil,
		daemonUpgradeHelperStatus,
		dpuserspace.DefaultControlSocketPath(nil),
		config.IsManagementIfName,
	)
}

// daemonUpgradeHelperStatus mirrors cmd/xpfd's defaultUpgradeHelperStatus.
//
// It is a second adapter rather than a shared one because cmd/xpfd's lives in
// package main and cannot be imported. Both are three lines over
// dpuserspace.ProbeStatus, and both must agree that a nil status means NOT
// ready — a helper that answers "no live status" has not proved it is
// forwarding, and reading that as ready is the false-PASS Gate 4 exists to
// prevent.
func daemonUpgradeHelperStatus(controlSocket string, timeout time.Duration) (enabled, armed bool, pid int, err error) {
	st, perr := dpuserspace.ProbeStatus(controlSocket, timeout)
	if perr != nil {
		return false, false, 0, perr
	}
	if st == nil {
		return false, false, 0, nil
	}
	return st.Enabled, st.ForwardingArmed, st.PID, nil
}
