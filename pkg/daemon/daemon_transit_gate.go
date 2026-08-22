package daemon

import (
	"log/slog"
	"os"
	"strings"
)

// #5275 — the transit-forwarding fail-closed gate.
//
// THE DEFECT. A successful config COMPILE followed by a dataplane ARM
// failure used to leave the box an open router. #1960/#1993 fail closed on
// a compile failure only; an arm failure (`rt.Start` → LoadUserspaceShim,
// or a retired-backend construction error) took a different branch that
// logged "running in config-only mode", cleared the dataplane cell, and
// FELL THROUGH to the boot applyConfig. Two sites then forced kernel
// transit forwarding ON regardless: enableForwarding() at bring-up and
// applyKernelTuning() at EVERY apply tail. With the AF_XDP shim never
// attached, nothing adjudicates transit — and this repo installs no
// nftables `hook forward` chain at all (the host-inbound tables are `hook
// input`), so the kernel routed transit under no policy whatsoever. A
// firewall whose dataplane failed to arm became a plain Linux router.
//
// THE GATE. Kernel transit forwarding is now CONDITIONAL on the dataplane
// being armed: `ip_forward` / `ipv6.conf.all.forwarding` are 1 only while
// Daemon.dataplaneArmed is true, and are driven to 0 on every path that
// lands in setDataplane(nil) — the boot Start() failure, the bootstrap-exit
// Start() failure, and both retired-backend arms — plus the two states
// where the daemon deliberately never arms (bootstrap mode, --no-dataplane).
// The apply-tail half is the load-bearing one: the tail runs on every
// commit, so without an armed-gated applyKernelTuning a later commit would
// silently re-open the hole.
//
// WHAT IS *NOT* CLOSED. Management stays up on purpose (#1960 no-brick):
// `ip_forward` governs FORWARDED packets only, so locally-terminated
// traffic — SSH, the gRPC/REST/CLI surfaces, the cluster heartbeat, DHCP —
// is untouched, as is the `hook input` host-inbound enforcement. The
// FRR/VRRP/RG-ownership half of #5275 (an unarmed node should also
// relinquish routing adjacencies and RG mastership) is HA-coupled, owes a
// `test-failover` smoke, and is deliberately NOT in this gate; likewise the
// full transit barrier in docs/research/5275-arm-failclosed/plan.md §6
// (inet FORWARD drop + bridge-family barrier + flowtable disable), of which
// this is the `ip_forward=0` half.
//
// WHY THE ARMED CASE IS UNAFFECTED. The armed AF_XDP fast path does not
// need `ip_forward` at all — measured in docs/image-validation.md
// ("Discriminator — this is the xpf dataplane, not the guest kernel"):
// with `net.ipv4.ip_forward=0` AND `net.ipv6.conf.all.forwarding=0` on the
// appliance, ping stayed at 0% loss and iperf3 moved 4.29 Gbit/s (v4) /
// 3.02 Gbit/s (v6). But some ARMED paths DO XDP_PASS to the kernel and rely
// on it — the route-based-VPN plaintext leaving an xfrm interface
// (pkg/config/README.md: "no `hook forward` rule covers it and `ip_forward`
// is 1") and SNAT'd frames passed up for kernel routing (the `accept_local`
// sysctl in enableForwarding exists for exactly that). So the gate NEVER
// lowers the knob while armed: the armed desired value is "1", byte-identical
// to the pre-#5275 unconditional write.

// ipv4ForwardSysctlPath / ipv6ForwardSysctlPath are the two kernel knobs
// that decide whether the kernel routes TRANSIT packets. They are the ONLY
// two sysctls the arm gate owns — the rest of enableForwarding's bundle
// (accept_ra, l3mdev_accept, accept_local) is host posture that does not
// admit transit on its own and stays unconditional.
//
// Package vars, not consts, for the same reason sshKnownHostsPath is one
// (daemon_system.go): tests drive the gate against a temp dir instead of
// /proc. Never reassigned in production.
var (
	ipv4ForwardSysctlPath = "/proc/sys/net/ipv4/ip_forward"
	ipv6ForwardSysctlPath = "/proc/sys/net/ipv6/conf/all/forwarding"
)

// transitForwardSysctlPaths is the single source of truth for the gated
// knob set. Both writers (enableForwarding at bring-up, applyKernelTuning
// at the apply tail) and the gate itself go through it, so the two can
// never drift into disagreeing about which knobs "transit forwarding" is.
func transitForwardSysctlPaths() []string {
	return []string{ipv4ForwardSysctlPath, ipv6ForwardSysctlPath}
}

// writeTransitForwardSysctls drives both transit knobs to on/off.
//
// BestEffortKernelKnob per docs/engineering-style.md "Persistence classes":
// procfs has no rename, so the atomic writers are impossible by construction
// and a direct os.WriteFile is correct here (allowlisted in
// pkg/fsatomic/canary_test.go).
//
// The read-compare before the write is load-bearing, not an optimisation:
// writing /proc/sys/net/ipv4/ip_forward resets the per-device configuration
// parameters to their forwarding-dependent defaults, so a no-op rewrite on
// every apply tail would clobber knobs a previous step set. Today's
// applyKernelTuning already had this guard; keeping it means an already-
// correct value is never rewritten in EITHER direction.
//
// A write failure is logged and skipped rather than propagated: this runs on
// boot and apply-tail paths that must not brick management, and the caller
// has already made the arm decision. The failure direction that matters is
// "could not close transit", which is why it is a Warn on a line that names
// the value it failed to set.
func writeTransitForwardSysctls(on bool) {
	want := "0"
	if on {
		want = "1"
	}
	for _, path := range transitForwardSysctlPaths() {
		current, _ := os.ReadFile(path)
		if strings.TrimSpace(string(current)) == want {
			continue
		}
		if err := os.WriteFile(path, []byte(want), 0644); err != nil {
			slog.Warn("failed to set kernel transit-forwarding sysctl",
				"path", path, "value", want, "err", err)
		}
	}
}

// DataplaneArmed reports whether the runtime dataplane has been proven to
// have STARTED in this daemon's lifetime. It is the predicate the transit
// gate keys off, and it is exported so a later status surface (`show
// chassis forwarding`, /health) can project it instead of re-deriving the
// state from a nil dataplane cell — a nil cell answers "is a backend
// published", which is NOT the same question (#5719: an unexported
// atomic.Bool with no accessor makes a truth projection impossible).
//
// Scope: this tracks the Start()/LoadUserspaceShim boundary, which is the
// boundary #5275 names. It is NOT the per-interface AF_XDP attach that
// happens later inside the first ApplyConfig — see the arm-coverage proof
// (pkg/dataplane/armproof.go, observe-only) and
// docs/research/5275-arm-failclosed/plan.md for that residual.
func (d *Daemon) DataplaneArmed() bool { return d.dataplaneArmed.Load() }

// markDataplaneArmed records a successful arm and re-opens kernel transit
// forwarding, so recovery from a prior fail-closed state (the bootstrap-exit
// arm after a bootstrap boot) does not need a daemon restart.
//
// Ordering: the atomic is stored BEFORE the knobs are written, so an
// applyKernelTuning that observes the flag can never re-close a knob this
// call just opened.
func (d *Daemon) markDataplaneArmed(stage string) {
	d.dataplaneArmed.Store(true)
	writeTransitForwardSysctls(true)
	slog.Info("dataplane armed; kernel transit forwarding enabled", "stage", stage)
}

// markDataplaneArmFailed records an arm FAILURE and closes kernel transit
// forwarding. This is the degraded fail-closed posture, so it logs at Error
// (not Warn) and names the remediation: the node is up and manageable but
// forwards no transit until the dataplane arms.
//
// The daemon deliberately does NOT exit — management/CLI/gRPC must stay
// reachable so the operator can correct the config in-band (#1960 no-brick).
func (d *Daemon) markDataplaneArmFailed(stage, remediation string, err error) {
	d.dataplaneArmed.Store(false)
	writeTransitForwardSysctls(false)
	slog.Error("dataplane arm FAILED; kernel transit forwarding DISABLED (fail-closed, degraded): "+
		"nothing adjudicates transit on this node, so it forwards none — management (SSH/CLI/gRPC/REST) "+
		"stays up so the config can be corrected in-band",
		"stage", stage, "err", err, "remediation", remediation)
}

// markDataplaneNotArmed records a DELIBERATE not-armed state and closes
// kernel transit forwarding. Distinct from markDataplaneArmFailed: nothing
// went wrong, the daemon is in a mode where it never arms, so this is Info.
//
// BOOTSTRAP IS FORWARDING-OFF, ON PURPOSE. Bootstrap mode exists so a box
// with no known-good config still answers management; it has no policy to
// enforce, so it must not carry transit. #1922 already SUPPRESSED
// enableForwarding there — but suppression is not closure: a daemon RESTART
// into bootstrap (or into the #1960 compile-failed boot, which forces
// bootstrap) inherits `ip_forward=1` from the previous armed run's sysctl
// writes, which survive the process. pkg/daemon/README.md already asserts
// "Transit is still fail-closed ... the daemon itself forwards no transit in
// this state"; the explicit close is what makes that assertion true.
//
// The same reasoning covers --no-dataplane: bring-up already declines to
// enable forwarding in that mode, so closing the knob makes the apply tail
// agree with bring-up instead of contradicting it.
func (d *Daemon) markDataplaneNotArmed(stage, reason string) {
	d.dataplaneArmed.Store(false)
	writeTransitForwardSysctls(false)
	slog.Info("dataplane not armed; kernel transit forwarding disabled (fail-closed)",
		"stage", stage, "reason", reason)
}
