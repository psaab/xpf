package daemon

import (
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/cluster"
	xnft "github.com/psaab/xpf/pkg/nftables"
	"github.com/vishvananda/netlink"
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
// #7191 added the nftables legs. The closed gate has BOTH the `ip_forward=0`
// sysctl and an unconditional forward-hook DROP in the inet AND bridge
// families (pkg/nftables/transit_barrier.go). #10302 extends the same owning
// boundary to the armed/open state: the forward hook remains policy-DROP and
// admits only the runtime-owned XDP links plus the daemon-owned adjudicated
// reinjection TUN. The bridge leg matters because `ip_forward` does not govern
// bridged frames at all, and this repo creates bridge domains.
//
// The plan's third leg, a flowtable disable, is a NO-OP today and is
// deliberately unwritten: xpf creates no flowtable, so there is nothing to
// flush. TestNoFlowtableIsEverCreated7191 pins that assumption so this
// sentence cannot rot into a false claim.
//
// The armed fence is installed before the transit sysctls are raised. If the
// fence cannot be installed, the sysctls remain zero. A closed-gate transition
// always restores the unconditional barrier before writing zero, so a stale
// pinhole set cannot survive a detach race.
//
// #7191 added the post-attach arm-coverage proof. Coverage still gates the
// arm bit, while #9725 additionally requires a fresh kernel XDP-link census
// before opening the transit knobs.
//
// The AF_XDP fast path does not need `ip_forward` at all — measured in
// docs/image-validation.md ("Discriminator — this is the xpf dataplane, not the
// guest kernel"): with the transit sysctls at 0 on the appliance, ping stayed
// at 0% loss and iperf3 moved 4.29 Gbit/s (v4) / 3.02 Gbit/s (v6). The only
// kernel-forwarded pinholes are the explicit ownership paths above; route-based
// XFRM plaintext and arbitrary leave-alone transit remain dropped.
// ipv4ForwardSysctlPath / ipv6ForwardSysctlPath are the two kernel knobs
// that decide whether the kernel routes TRANSIT packets. They are the ONLY
// two sysctls the arm gate owns — host posture (accept_ra, l3mdev_accept,
// accept_local) does not admit transit on its own and stays unconditional.
//
// Package vars, not consts, for the same reason sshKnownHostsPath is one
// (daemon_system.go): tests drive the gate against a temp dir instead of
// /proc. Never reassigned in production.

// attachedXDPIfindexSource is the provenance-bearing runtime capability used
// by the armed forward fence. It intentionally exposes the tracked xpf link
// set, not a global netlink "any XDP" scan: an unrelated XDP program on a
// leave-alone NIC is not an xpf policy proof.
type attachedXDPIfindexSource interface {
	AttachedXDPIfindexes() []int
}

type attachedXDPFenceLease interface {
	WithAttachedXDPFence(func([]int) error) error
}

// transitFenceLinkList is a test seam around the kernel name lookup. Production
// uses netlink's live list; tests supply links whose ifindexes and types model
// owned, unmanaged, and lookalike devices without changing kernel state.
var transitFenceLinkList = netlink.LinkList

const armedTransitReinjectIfname = "xpf-usp1"

// armedTransitFenceSpec resolves the only ingress pinholes permitted while
// armed:
//   - tracked runtime XDP links whose kernel names still resolve;
//   - the daemon-owned xpf-usp1 delegated slow-path TUN, but only when the
//     queue classifier has set the adjudicated skb mark.
//
// xpf-usp1 is a deliberate residual: both adjudicated xfrm reinjects and
// delegated traffic arrive with the same iifname. The queue-index classifier
// marks only the adjudicated queue; the fence always requires the interface
// and exact mark conjunction. xpf-usp0 is LocalDelivery/gated-only and is not
// a FORWARD pinhole.
//
// Missing capability, an unknown ifindex alongside another resolved ifindex, or
// a mismatched link type all produce fewer pinholes, never a broader one. If
// every supplied tracked ifindex is unknown, or kernel link enumeration fails,
// arming is fatal and leaves the gate closed. Direct route-based IPsec plaintext
// arrives on its daemon-owned xfrmi and remains absent from the allowlist;
// kernel-XFRM reinjection instead arrives through the marked xpf-usp1 queue.
func (d *Daemon) armedTransitFenceSpec() (xnft.ForwardFenceSpec, error) {
	var ifindexes []int
	if src, ok := d.dataplane().(attachedXDPIfindexSource); ok && src != nil {
		ifindexes = src.AttachedXDPIfindexes()
	}
	return d.armedTransitFenceSpecForIfindexes(ifindexes)
}

func (d *Daemon) armedTransitFenceSpecForIfindexes(ifindexes []int) (xnft.ForwardFenceSpec, error) {
	tracked := make(map[int]struct{}, len(ifindexes))
	for _, ifindex := range ifindexes {
		if ifindex > 0 {
			tracked[ifindex] = struct{}{}
		}
	}
	links, err := transitFenceLinkList()
	if err != nil {
		return xnft.ForwardFenceSpec{}, fmt.Errorf("resolve armed transit fence interfaces: %w", err)
	}
	names := make([]string, 0, len(tracked))
	marked := make([]xnft.ForwardFenceMark, 0, 1)
	resolvedTracked := false
	for _, link := range links {
		if link == nil || link.Attrs() == nil {
			continue
		}
		attrs := link.Attrs()
		if _, ok := tracked[attrs.Index]; ok {
			if attrs.Name != armedTransitReinjectIfname {
				names = append(names, attrs.Name)
			}
			delete(tracked, attrs.Index)
			resolvedTracked = true
		}
		if attrs.Name != armedTransitReinjectIfname {
			continue
		}
		tun, ok := link.(*netlink.Tuntap)
		if ok && tun.Mode == netlink.TUNTAP_MODE_TUN {
			marked = append(marked, xnft.ForwardFenceMark{
				Ifname: attrs.Name,
				Mark:   xnft.AdjudicatedTransitMark,
				Mask:   xnft.AdjudicatedTransitMarkMask,
			})
		}
	}
	if len(ifindexes) > 0 && !resolvedTracked {
		return xnft.ForwardFenceSpec{}, fmt.Errorf(
			"resolve armed transit interfaces: none of %d tracked XDP ifindexes found",
			len(ifindexes))
	}
	sort.Strings(names)
	out := names[:0]
	for _, name := range names {
		if name == "" || (len(out) > 0 && out[len(out)-1] == name) {
			continue
		}
		out = append(out, name)
	}
	return xnft.ForwardFenceSpec{AllowedIfnames: out, AllowedMarks: marked}, nil
}

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
// shouldManageTransitGate limits the persistent kernel forwarding fence to
// appliance images and hosts with a committed xpf configuration. A package
// install on a foreign, never-committed host must leave its existing kernel
// forwarding posture alone. Once ownership is established it remains latched
// for this daemon lifetime so a first-commit rollback cannot re-open transit.
func (d *Daemon) shouldManageTransitGate() bool {
	if d == nil {
		return false
	}
	if d.transitGateOwned.Load() {
		return true
	}
	if _, err := os.Stat(applianceMarkerFile); err == nil {
		d.transitGateOwned.Store(true)
		return true
	}
	if d.store != nil && d.store.EverCommitted() {
		d.transitGateOwned.Store(true)
		return true
	}
	if d.dataplaneArmed.Load() {
		d.transitGateOwned.Store(true)
		return true
	}
	return false
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
// transit gate and RG bid closed until the same predicate proves a live XDP
// link; first ApplyConfig or the periodic tick opens both once the kernel
// reports one.
func (d *Daemon) markDataplaneArmed(stage string) {
	if d == nil || !d.shouldManageTransitGate() {
		return
	}
	d.transitGateMu.Lock()
	d.dataplaneArmed.Store(true)
	ready := d.attachedXDPLinks() > 0
	opened := d.writeTransitGateLocked(stage, ready)
	d.applyDataplaneReadyTrack(opened)
	d.transitGateMu.Unlock()
	slog.Info("dataplane armed; transit gate re-evaluated", "stage", stage,
		"kernel_transit_open", opened)
}

// applyDataplaneReadyTrack mirrors the ready-to-serve predicate into
// redundancy-group weight so a node that cannot forward stops outbidding a
// peer that can (#7178).
//
// The predicate is deliberately stricter than Start success: a node is ready
// only when the dataplane is armed AND the kernel has proven at least one live
// XDP link (#9842). This is the same verdict used by the transit gate, so a
// node can never bid full weight while the gate is closed, or shed a servable
// dataplane.
//
// It rides the EXISTING interface-monitor debt path rather than adding a rule
// to the election. The cost is sub-total ON PURPOSE (see
// cluster.DataplaneArmMonitorCost): the node lands at weight 1, not 0, so an
// attached peer at 255 wins while a standalone node stays primary.
//
// The snapshot check makes repeated 1s kernel-truth ticks a read-only fast
// path: only a sentinel transition takes the Manager write lock and re-runs
// elections.
//
// Idempotent and safe with no cluster configured: SetMonitorWeight is a no-op
// for an unknown RG, and a nil manager short-circuits here.
func (d *Daemon) applyDataplaneReadyTrack(ready bool) {
	if d.cluster == nil {
		return
	}
	for _, rg := range d.cluster.GroupStates() {
		hasDebt := false
		for _, iface := range rg.MonitorFails {
			if iface == cluster.DataplaneArmMonitorIface {
				hasDebt = true
				break
			}
		}
		wantDebt := !ready
		if hasDebt == wantDebt {
			continue
		}
		d.cluster.SetMonitorWeight(rg.GroupID, cluster.DataplaneArmMonitorIface,
			wantDebt, cluster.DataplaneArmMonitorCost)
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
	if d == nil || !d.shouldManageTransitGate() {
		return
	}
	d.transitGateMu.Lock()
	d.dataplaneArmed.Store(false)
	// #7191: install the nft barrier FIRST on the closing path. Both legs
	// close, so the order only affects how early closure is complete.
	_ = d.writeTransitGateLocked(stage, false)
	d.applyDataplaneReadyTrack(false)
	d.transitGateMu.Unlock()
	slog.Error("dataplane arm FAILED; kernel transit forwarding DISABLED (fail-closed, degraded): "+
		"nothing adjudicates transit on this node, so it forwards none — management (SSH/CLI/gRPC/REST) "+
		"stays up so the config can be corrected in-band",
		"stage", stage, "err", err, "remediation", remediation)
}

// markDataplaneNotArmed records a DELIBERATE not-armed state and closes
// kernel transit forwarding only when xpf owns the host's transit posture.
// A foreign host with no committed configuration is not an appliance and
// the package install must preserve the host's existing forwarding state.
//
// Appliance factory bootstrap and any previously committed host still close:
// neither has a policy it can currently enforce, and sysctls outlive the
// daemon process. Once marked by the appliance marker or a committed config,
// ownership remains latched for this daemon lifetime so a first-commit
// rollback can close before detaching the dataplane.
func (d *Daemon) markDataplaneNotArmed(stage, reason string) {
	if d == nil || !d.shouldManageTransitGate() {
		return
	}
	d.transitGateMu.Lock()
	d.dataplaneArmed.Store(false)
	d.writeTransitGateLocked(stage, false)
	// #7178: DELIBERATE and FAILED are the same fact to a peer — this node
	// forwards no transit either way, so it must not outbid one that does. The
	// distinction is why this logs at Info while the failure path logs at Error.
	d.applyDataplaneReadyTrack(false)
	d.transitGateMu.Unlock()
	slog.Info("dataplane not armed; kernel transit forwarding disabled (fail-closed)",
		"stage", stage, "reason", reason)
}

func (d *Daemon) openTransitGateLocked() error {
	if nftInstaller == nil {
		writeTransitForwardSysctls(true)
		return nil
	}
	if lease, ok := d.dataplane().(attachedXDPFenceLease); ok && lease != nil {
		return lease.WithAttachedXDPFence(func(ifindexes []int) error {
			if len(ifindexes) == 0 {
				return fmt.Errorf("armed transit fence has no kernel-proven XDP links")
			}
			spec, err := d.armedTransitFenceSpecForIfindexes(ifindexes)
			if err != nil {
				return err
			}
			if err := nftInstaller.InstallArmedTransitFence(spec); err != nil {
				if xnft.IsTransitBarrierBridgeUnsupportedOnly(err) {
					slog.Warn("armed transit inet fence installed; bridge forward fence unsupported by kernel",
						"err", err)
				} else {
					return err
				}
			}
			writeTransitForwardSysctls(true)
			return nil
		})
	}
	if err := d.applyTransitBarrier(true); err != nil {
		return err
	}
	writeTransitForwardSysctls(true)
	return nil
}

// applyTransitBarrier drives the nftables forward fence from the same arm
// state that drives the sysctls. An armed state installs a policy DROP with
// provenance-scoped XDP_PASS pinholes; an unarmed state installs the existing
// unconditional DROP. It never removes the forward fence while the gate is
// being opened.
func (d *Daemon) applyTransitBarrier(armed bool) error {
	if nftInstaller == nil {
		return nil
	}
	if armed {
		spec, err := d.armedTransitFenceSpec()
		if err != nil {
			slog.Error("failed to resolve the armed transit forward fence; "+
				"kernel transit will remain closed", "err", err)
			return err
		}
		if err := nftInstaller.InstallArmedTransitFence(spec); err != nil {
			if xnft.IsTransitBarrierBridgeUnsupportedOnly(err) {
				slog.Warn("armed transit inet fence installed; bridge forward fence unsupported by kernel",
					"err", err)
				return nil
			}
			slog.Error("failed to install the armed transit forward fence; "+
				"kernel transit will remain closed", "err", err)
			return err
		}
		return nil
	}
	if err := nftInstaller.InstallTransitBarrier(); err != nil {
		slog.Warn("failed to install the unarmed transit barrier; ip_forward=0 still "+
			"closes transit, so this is a loss of defence-in-depth rather than an "+
			"open forwarding path", "err", err)
		return err
	}
	return nil
}
