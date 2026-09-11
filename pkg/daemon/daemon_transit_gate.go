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
// FELL THROUGH to the boot applyConfig. Two sites then forced kernel
// transit forwarding ON regardless: enableForwarding() at bring-up and
// applyKernelTuning() at EVERY apply tail. With the AF_XDP shim never
// attached, nothing adjudicates transit — and this repo installs no
// nftables `hook forward` chain at all (the host-inbound tables are `hook
// input`), so the kernel routed transit under no policy whatsoever. A
// firewall whose dataplane failed to arm became a plain Linux router.
//
// THE GATE. Kernel transit forwarding is now CONDITIONAL: `ip_forward` /
// `ipv6.conf.all.forwarding` are 1 only while transitOpen holds, which needs
// the arm and, since #9725, a live attached shim XDP link
// (transit_closed_until_attach_9725.go states the rule). They are driven to 0
// on every path that lands in setDataplane(nil) — the boot Start() failure,
// the bootstrap-exit Start() failure, and both retired-backend arms — plus
// the two states where the daemon deliberately never arms (bootstrap mode,
// --no-dataplane), the bootstrap rollback, the #9686 stop, and any
// re-evaluation that finds an armed node with no live attached link.
// The apply-tail half is the load-bearing one: the tail runs on every
// commit, so without an applyKernelTuning tail gated on transitOpen a later
// commit would silently re-open the hole.
//
// WHAT IS *NOT* CLOSED. Management stays up on purpose (#1960 no-brick):
// `ip_forward` governs FORWARDED packets only, so locally-terminated
// traffic — SSH, the gRPC/REST/CLI surfaces, the cluster heartbeat, DHCP —
// is untouched, as is the `hook input` host-inbound enforcement. The
// FRR/VRRP/RG-ownership half of #5275 (an unarmed node should also
// relinquish routing adjacencies and RG mastership) is HA-coupled, owes a
// `test-failover` smoke, and is deliberately NOT in this gate. The full
// transit barrier in docs/research/5275-arm-failclosed/plan.md §6 (inet
// FORWARD drop + bridge-family barrier + flowtable disable) was not in the
// original #5275 gate either: its nftables legs landed in #7191, and only the
// flowtable disable is a deliberate no-op.
//
// #7191 added the nftables legs. The barrier is now BOTH the `ip_forward=0`
// sysctl and an unconditional forward-hook DROP in the inet AND bridge
// families (pkg/nftables/transit_barrier.go). Both legs are installed and
// removed by the gate's writes (writeTransitGateLocked,
// closeTransitUntilAttached) and the mark* helpers below, so one gate state
// (transitOpen) drives both. The bridge leg matters because `ip_forward` does
// not govern bridged frames at all, and this repo creates bridge domains.
//
// The plan's third leg, a flowtable disable, is a NO-OP today and is
// deliberately unwritten: xpf creates no flowtable, so there is nothing to
// flush. TestNoFlowtableIsEverCreated7191 pins that assumption so this
// sentence cannot rot into a false claim.
//
// CRITICALLY, the nftables legs are live exactly while transitOpen is false.
// Closing installs the barrier first and then writes `ip_forward=0`. Once both
// have landed, the inet leg is a second lock on routed transit, and the bridge
// leg is the only lock on bridged frames, which ignore `ip_forward`. See "WHY THE ARMED CASE IS UNAFFECTED" below, meaning armed
// WITH a live attached link: several armed paths depend on the kernel forward
// hook being open and unfiltered while transit is open, and a barrier live
// then would drop them.
//
// #7191 also made the per-interface attach part of the arm state: the
// post-attach arm-coverage proof GATES (daemon_arm_coverage_7191.go) instead
// of only logging, so that a box where Start() succeeded but an interface
// never got a shim does not report itself armed while forwarding that
// interface unadjudicated. That gate is inactive on the published runtime
// (#9804), which does not expose the proof. It is also distinct from
// AttachedXDPLinkCount, the #9725 conjunct: the proof is per interface, while
// one attached link opens transit globally, for every interface.
//
// WHY THE ARMED CASE IS UNAFFECTED (armed WITH a live attached link). The
// armed AF_XDP fast path does not need `ip_forward` at all — measured in
// docs/image-validation.md ("Discriminator — this is the xpf dataplane, not
// the guest kernel"):
// with `net.ipv4.ip_forward=0` AND `net.ipv6.conf.all.forwarding=0` on the
// appliance, ping stayed at 0% loss and iperf3 moved 4.29 Gbit/s (v4) /
// 3.02 Gbit/s (v6). But some ARMED paths DO XDP_PASS to the kernel and rely
// on it — the route-based-VPN plaintext leaving an xfrm interface
// (pkg/config/README.md: "no `hook forward` rule covers it and `ip_forward`
// is 1") and SNAT'd frames passed up for kernel routing (the `accept_local`
// sysctl in the host forwarding posture exists for exactly that). So while
// transitOpen holds, the desired value is "1", byte-identical to the pre-#5275
// unconditional write. When it does not hold, on an armed node too, those paths
// wait for an attach (transit_closed_until_attach_9725.go).

// ipv4ForwardSysctlPath / ipv6ForwardSysctlPath are the two kernel knobs
// that decide whether the kernel routes TRANSIT packets. They are the ONLY
// two sysctls the transit gate owns — the rest of the forwarding bundle
// (hostForwardingPostureSysctls: accept_ra, l3mdev_accept, accept_local) is
// host posture that does not admit transit on its own and stays unconditional.
//
// Package vars, not consts, for the same reason sshKnownHostsPath is one
// (daemon_system.go): tests drive the gate against a temp dir instead of
// /proc. Never reassigned in production.
var (
	ipv4ForwardSysctlPath = "/proc/sys/net/ipv4/ip_forward"
	ipv6ForwardSysctlPath = "/proc/sys/net/ipv6/conf/all/forwarding"
)

// transitForwardSysctlPaths is the single source of truth for the gated
// knob set. Every write goes through writeTransitForwardSysctls, which reads
// it: the mark* helpers here, closeTransitUntilAttached (the bring-up close,
// #9725), and writeTransitGateLocked (#9725), which re-evaluates the gate at
// the arm, after every ApplyConfig and at the apply tail. So no two writers
// can drift into disagreeing about which knobs "transit forwarding" is.
func transitForwardSysctlPaths() []string {
	return []string{ipv4ForwardSysctlPath, ipv6ForwardSysctlPath}
}

// transitForwardWriteHook, when set, observes every transit knob write before it
// happens (#9725). It is a test seam: a gate that opened and closed again within
// one step leaves the knobs where they started, and only the write history shows
// it. Never set in production.
var transitForwardWriteHook func(path, value string)

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
// has already made the gate decision. The failure direction that matters is
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
		if transitForwardWriteHook != nil {
			transitForwardWriteHook(path, want)
		}
		if err := os.WriteFile(path, []byte(want), 0644); err != nil {
			slog.Warn("failed to set kernel transit-forwarding sysctl",
				"path", path, "value", want, "err", err)
		}
	}
}

// DataplaneArmed reports whether the runtime dataplane has been proven to
// have STARTED in this daemon's lifetime. It is one conjunct of the transit
// gate's predicate (transitOpen), and it is exported so a later status
// surface (`show chassis forwarding`, /health) can project it instead of
// re-deriving the state from a nil dataplane cell — a nil cell answers "is a
// backend published", which is NOT the same question (#5719: an unexported
// atomic.Bool with no accessor makes a truth projection impossible).
//
// Scope: this tracks the Start()/LoadUserspaceShim boundary, which is the
// boundary #5275 names. It is NOT the per-interface AF_XDP attach that
// happens later inside the first ApplyConfig. Kernel transit also needs a live
// attached shim XDP link, re-read at every re-evaluation and not latched
// (#9725, transitOpen), so DataplaneArmed() alone does not mean transit is
// open.
func (d *Daemon) DataplaneArmed() bool { return d.dataplaneArmed.Load() }

// markDataplaneArmed records a successful arm (rt.Start) and re-evaluates the
// transit gate (#9725, transit_closed_until_attach_9725.go). The gate opens if
// a live shim XDP link is already attached; otherwise it stays closed until a
// later re-evaluation finds one. Recovery from a prior fail-closed state (the
// bootstrap-exit arm after a bootstrap boot) still needs no daemon restart: the
// re-evaluation after the apply that follows the arm opens transit if that
// apply left a link attached.
//
// It clears the #7178 demotion, as before. That happens before anything is
// attached, which #9842 records.
func (d *Daemon) markDataplaneArmed(stage string) {
	d.lockTransitGate("markDataplaneArmed")
	defer d.transitGateMu.Unlock()
	d.dataplaneArmed.Store(true)
	open := d.writeTransitGateLocked(stage)
	d.applyDataplaneArmTrack(true)
	slog.Info("dataplane armed", "stage", stage, "kernel_transit_open", open)
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
// forwards no transit until the transit gate opens (armed, with a live
// attached link).
//
// The daemon deliberately does NOT exit — management/CLI/gRPC must stay
// reachable so the operator can correct the config in-band (#1960 no-brick).
func (d *Daemon) markDataplaneArmFailed(stage, remediation string, err error) {
	d.lockTransitGate("markDataplaneArmFailed") // #9725
	defer d.transitGateMu.Unlock()
	d.dataplaneArmed.Store(false)
	d.transitWasOpen = false // #9725
	// #7191: install the nft barrier FIRST on the closing path. Both legs
	// close, so the order only affects how early closure is complete.
	d.applyTransitBarrier(false)
	writeTransitForwardSysctls(false)
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
// enforce, so it must not carry transit. #1922 SUPPRESSED the bring-up
// forwarding enable there, and #9725 later removed that enable altogether — but
// suppression is not closure: a daemon RESTART into bootstrap (or into the #1960
// compile-failed boot, which forces bootstrap) inherits `ip_forward=1` from a
// previous run's sysctl writes, which survive the process. pkg/daemon/README.md already asserts
// "Transit is still fail-closed ... the daemon itself forwards no transit in
// this state"; the explicit close is what makes that assertion true.
//
// The same reasoning covers --no-dataplane. Since #9725 no bring-up branch
// opens transit: bring-up closes it in every mode, so closing the knob here
// makes the apply tail agree with bring-up instead of contradicting it.
func (d *Daemon) markDataplaneNotArmed(stage, reason string) {
	d.lockTransitGate("markDataplaneNotArmed") // #9725
	defer d.transitGateMu.Unlock()
	d.dataplaneArmed.Store(false)
	d.transitWasOpen = false     // #9725
	d.applyTransitBarrier(false) // #7191
	writeTransitForwardSysctls(false)
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
// SAME gate state that drives the sysctls: transitOpen
// (transit_closed_until_attach_9725.go). open==true REMOVES it; open==false
// INSTALLS it.
//
// One source, deliberately: the barrier is never derived independently of the
// gate. A second notion of "should the barrier be up" is precisely how a stale
// barrier survives the gate opening and black-holes a healthy box.
//
// NEITHER FAILURE IS PROPAGATED. Every apply tail re-asserts, so both are
// retried on the next apply. Each direction is logged once per failure episode
// (logTransitBarrierEpisode): ERROR when it starts, Debug while it persists, and
// Info when it ends. The gate changing direction also ends the other direction's
// episode, so a failure after it switches back is logged at ERROR again. The
// error names the family that failed.
//
//   - failing to INSTALL (closing) is swallowed, because propagating it would
//     brick management on a boot path. What a missing leg leaves open depends on
//     its family. A missing inet leg leaves routed transit to ip_forward alone. A
//     missing bridge leg leaves bridged frames with no drop at all, because they
//     ignore ip_forward. The box is no worse than before #7191.
//   - failing to REMOVE (opening) is the black-hole direction. A barrier that
//     outlives the gate opening drops the armed paths that deliberately rely on
//     kernel forwarding: route-based IPsec plaintext off an xfrm interface,
//     SNAT'd frames passed up for kernel routing, and the #7409 slow-path
//     reinject.
func (d *Daemon) applyTransitBarrier(open bool) {
	if nftInstaller == nil {
		return
	}
	if open {
		d.transitBarrierInstallFailing = false
		d.transitBarrierRemoveFailing = logTransitBarrierEpisode("remove",
			d.transitBarrierRemoveFailing, nftInstaller.RemoveTransitBarrier())
		return
	}
	d.transitBarrierRemoveFailing = false
	d.transitBarrierInstallFailing = logTransitBarrierEpisode("install",
		d.transitBarrierInstallFailing, nftInstaller.InstallTransitBarrier())
}

// logTransitBarrierEpisode logs one barrier install or remove result against the
// failure episode it belongs to, and reports whether that operation is failing
// now. The caller holds transitGateMu, which guards both episode flags.
func logTransitBarrierEpisode(op string, wasFailing bool, err error) bool {
	switch {
	case err != nil && !wasFailing:
		slog.Error("failed to "+op+" the transit barrier; the next apply retries it", "err", err)
	case err != nil:
		slog.Debug("transit barrier "+op+" still failing", "err", err)
	case wasFailing:
		slog.Info("transit barrier " + op + " succeeded after earlier failures")
	}
	return err != nil
}
