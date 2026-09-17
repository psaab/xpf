package daemon

import (
	"github.com/psaab/xpf/pkg/cluster"
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
// fell through to transit forwarding ON regardless: the original unconditional
// writer and apply-tail writer opened the kernel before XDP attachment was
// proven. With the AF_XDP shim absent or detached, nothing adjudicates
// transit — and this repo installs no nftables `hook forward` chain at all
// (the host-inbound tables are `hook input`), so the kernel routed transit
// under no policy whatsoever. A firewall whose dataplane failed to arm became
// a plain Linux router, and a booting dataplane briefly did the same.
//
// THE GATE. Kernel transit forwarding is conditional on BOTH the dataplane
// having successfully started and the kernel reporting at least one live XDP
// link. `ip_forward` / `ipv6.conf.all.forwarding` are 1 only while that
// predicate is true. The periodic kernel-truth tick is authoritative; writer
// notifications only wake an earlier recount.
//
// The gate closes on every arm failure, deliberate non-arm, detach, and
// uncertain count. A successful Start therefore leaves forwarding closed
// until a fresh kernel count proves an XDP link; this prevents the boot window
// addressed by #9725 while preserving a live dataplane's kernel paths.
//
// WHAT IS *NOT* CLOSED. Management stays up on purpose (#1960 no-brick):
// `ip_forward` governs FORWARDED packets only, so locally-terminated
// traffic — SSH, the gRPC/REST/CLI surfaces, the cluster heartbeat, DHCP —
// is untouched, as is the `hook input` host-inbound enforcement. The
// FRR/VRRP/RG-ownership half of #5275 (an unarmed node should also
// relinquish routing adjacencies and RG mastership) is HA-coupled, owes a
// `test-failover` smoke, and is deliberately NOT in this gate; likewise the
// full transit barrier in docs/research/5275-arm-failclosed/plan.md §6
// (inet FORWARD drop + bridge-family barrier + flowtable disable).
//
// #7191 added the nftables legs. The barrier is now BOTH the `ip_forward=0`
// sysctl and an unconditional forward-hook DROP in the inet AND bridge
// families (pkg/nftables/transit_barrier.go), installed and removed from the
// same mark* helpers below so there is one arm state driving both. The bridge
// leg matters because `ip_forward` does not govern bridged frames at all, and
// this repo creates bridge domains.
//
// The plan's third leg, a flowtable disable, is a NO-OP today and is
// deliberately unwritten: xpf creates no flowtable, so there is nothing to
// flush. TestNoFlowtableIsEverCreated7191 pins that assumption so this
// sentence cannot rot into a false claim.
//
// CRITICALLY, the nftables legs are scoped to the CLOSED gate window only —
// the same window in which the transit sysctls are already 0 — so they close
// nothing that was open. Once both arm state and a live XDP link are proven,
// the barrier is removed so kernel-forwarded paths remain usable.
//
// #7191 added the post-attach arm-coverage proof. Coverage still gates the
// arm bit, while #9725 additionally requires a fresh kernel XDP-link census
// before opening the transit knobs.
//
// WHY THE OPEN CASE IS PRESERVED. The AF_XDP fast path does not need
// `ip_forward` at all — measured in docs/image-validation.md ("Discriminator —
// this is the xpf dataplane, not the guest kernel"): with the transit sysctls
// at 0 on the appliance, ping stayed at 0% loss and iperf3 moved 4.29 Gbit/s
// (v4) / 3.02 Gbit/s (v6). But some attached paths DO XDP_PASS to the kernel
// and rely on it — route-based-VPN plaintext leaving an xfrm interface and
// SNAT'd frames passed up for kernel routing. Once a live XDP link is proven,
// the gate keeps the desired value "1", byte-identical to the pre-#9725
// behavior.
// ipv4ForwardSysctlPath / ipv6ForwardSysctlPath are the two kernel knobs
// that decide whether the kernel routes TRANSIT packets. They are the ONLY
// two sysctls the arm gate owns — host posture (accept_ra, l3mdev_accept,
// accept_local) does not admit transit on its own and stays unconditional.
//
// Package vars, not consts, for the same reason sshKnownHostsPath is one
// (daemon_system.go): tests drive the gate against a temp dir instead of
// /proc. Never reassigned in production.
var (
	ipv4ForwardSysctlPath = "/proc/sys/net/ipv4/ip_forward"
	ipv6ForwardSysctlPath = "/proc/sys/net/ipv6/conf/all/forwarding"
)

// transitForwardSysctlPaths is the single source of truth for the gated
// knob set. The gate is the sole writer of these transit knobs; host posture
// remains separate and is applied by applyHostForwardingPosture.
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

// DataplaneArmed reports whether the runtime dataplane has been successfully
// started in this daemon's lifetime. Kernel transit is NOT opened by this bit
// alone: #9725 requires a separate kernel-truth XDP-link count, continuously
// re-evaluated by transit_gate_tick_9725.go.
func (d *Daemon) DataplaneArmed() bool { return d.dataplaneArmed.Load() }

// markDataplaneArmed records a successful Start. It deliberately leaves the
// transit gate closed until the same gate predicate proves a live XDP link;
// first ApplyConfig or the periodic tick opens it once the kernel reports one.
func (d *Daemon) markDataplaneArmed(stage string) {
	d.transitGateMu.Lock()
	d.dataplaneArmed.Store(true)
	d.writeTransitGateLocked(stage)
	d.transitGateMu.Unlock()
	d.applyDataplaneArmTrack(true)
	slog.Info("dataplane armed; transit gate re-evaluated", "stage", stage,
		"kernel_transit_open", d.transitOpen())
}

// applyDataplaneArmTrack mirrors the arm state into redundancy-group weight so
// a node that cannot forward stops outbidding a peer that can (#7178).
//
// Before this, a failed arm left the node fully eligible: it could win or retain
// RG mastership, take the RETH VIPs from a peer with a WORKING dataplane, and go
// on attracting traffic it then drops (#5275 closes kernel transit forwarding,
// so the node is a black hole rather than an unpoliced forwarder). "Let the peer
// have it" is the obvious answer on a cluster, and this is the mechanism that
// expresses it.
//
// It rides the EXISTING interface-monitor debt path rather than adding a rule to
// the election. The alternative — refusing MASTER outright — has to interact
// with priority-0 takeover and the ungated masterDownTimer, which is where the
// ~60ms failover budget lives; a synthetic monitor adds a debt CONTRIBUTOR and
// no new path into electRG.
//
// The cost is sub-total ON PURPOSE (see cluster.DataplaneArmMonitorCost): the
// node lands at weight 1, not 0, so an armed peer at 255 wins while a STANDALONE
// unarmed node stays primary. Demoting a lone node would not make it safe, only
// absent — nothing else takes the VIPs, and the operator may be reaching the box
// on one.
//
// Idempotent and safe with no cluster configured: SetMonitorWeight is a no-op
// for an unknown RG, and a nil manager short-circuits here.
func (d *Daemon) applyDataplaneArmTrack(armed bool) {
	if d.cluster == nil {
		return
	}
	for _, rg := range d.cluster.GroupStates() {
		d.cluster.SetMonitorWeight(rg.GroupID, cluster.DataplaneArmMonitorIface,
			!armed, cluster.DataplaneArmMonitorCost)
	}
}

// markDataplaneArmFailed records an arm FAILURE and closes kernel transit
// forwarding. This is the degraded fail-closed posture, so it logs at Error
// (not Warn) and names the remediation: the node is up and manageable but
// forwards no transit until the dataplane arms.
//
// The daemon deliberately does NOT exit — management/CLI/gRPC must stay
// reachable so the operator can correct the config in-band (#1960 no-brick).
func (d *Daemon) markDataplaneArmFailed(stage, remediation string, err error) {
	d.transitGateMu.Lock()
	d.dataplaneArmed.Store(false)
	// #7191: install the nft barrier FIRST on the closing path. Both legs
	// close, so the order only affects how early closure is complete.
	d.writeTransitGateLocked(stage)
	d.transitGateMu.Unlock()
	d.applyDataplaneArmTrack(false)
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
	d.transitGateMu.Lock()
	d.dataplaneArmed.Store(false)
	d.writeTransitGateLocked(stage)
	d.transitGateMu.Unlock()
	// #7178: DELIBERATE and FAILED are the same fact to a peer — this node
	// forwards no transit either way, so it must not outbid one that does. The
	// distinction is why this logs at Info while the failure path logs at Error;
	// it is not a reason to keep mastership. On a bootstrap boot there is no
	// cluster yet and applyDataplaneArmTrack is a no-op; the case this covers is
	// config-only mode on a node that already has a cluster configured.
	d.applyDataplaneArmTrack(false)
	slog.Info("dataplane not armed; kernel transit forwarding disabled (fail-closed)",
		"stage", stage, "reason", reason)
}

// applyTransitBarrier drives the #7191 nftables half of the barrier from the
// SAME arm state that drives the sysctls. armed==true REMOVES it; armed==false
// INSTALLS it.
//
// One source, deliberately: the barrier is never derived independently of
// dataplaneArmed. A second notion of "should the barrier be up" is precisely
// how a stale barrier survives arming and black-holes a healthy box.
//
// FAILURE DIRECTION IS ASYMMETRIC, and that asymmetry is the safety argument:
//
//   - failing to INSTALL (closing) is logged and swallowed, exactly as
//     writeTransitForwardSysctls does. The sysctl leg has already closed
//     transit; the barrier is belt to those braces, so a barrier that did not
//     install leaves the box no worse than pre-#7191, and propagating it would
//     brick management on a boot path.
//   - failing to REMOVE (opening) is logged at ERROR, because that is the
//     black-hole direction: a barrier that outlives arming drops the armed
//     paths that deliberately rely on kernel forwarding — route-based IPsec
//     plaintext off an xfrm interface, SNAT'd frames passed up for kernel
//     routing, and the #7409 slow-path reinject. The apply tail re-asserts on
//     every commit, so a transient failure self-heals; a persistent one is loud.
func (d *Daemon) applyTransitBarrier(armed bool) {
	if nftInstaller == nil {
		return
	}
	if armed {
		if err := nftInstaller.RemoveTransitBarrier(); err != nil {
			slog.Error("failed to REMOVE the unarmed transit barrier while armed; "+
				"kernel-forwarded paths that rely on an open FORWARD hook (route-based "+
				"IPsec plaintext, SNAT'd frames, slow-path reinject) may be dropped until "+
				"the next apply re-asserts", "err", err)
		}
		return
	}
	if err := nftInstaller.InstallTransitBarrier(); err != nil {
		slog.Warn("failed to install the unarmed transit barrier; ip_forward=0 still "+
			"closes transit, so this is a loss of defence-in-depth rather than an "+
			"open forwarding path", "err", err)
	}
}
