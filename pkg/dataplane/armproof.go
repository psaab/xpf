package dataplane

import (
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

// #5275 PR1 — OBSERVE-ONLY dataplane arm-coverage proof.
//
// A config that COMPILES but whose dataplane fails to ARM degrades a cold-booted
// firewall to a policy-free router: ownership, forwarding and route/VIP
// advertisement are all published in initManagers BEFORE the arm
// (daemon_run_bringup.go:47 vs :414), and an attach failure surfaces through
// d.dp.ApplyConfig as an ORDINARY #5679 deferred error — compileErrorMustAbortApply
// only matches the required-protocol gate — so the apply tail still publishes.
//
// The eventual fix gates release on a positive arm proof. THIS FILE DOES NOT
// GATE ANYTHING. It computes the proof and reports what a gating build would
// have decided, so the divergence rate can be measured across the real fleet
// before the gate is ever load-bearing. `WouldGate` is a diagnostic, never a
// control input; nothing here returns an error that any caller acts on.
//
// SIDE EFFECTS, stated exactly (an "observe-only" claim that is not literally
// true is worse than no claim): the proof writes NO Go state — not the Manager,
// not the CompileResult it is proving — and it READS live kernel and bpf state.
// The read cost is per surface KIND, not uniform: a DIRECT surface with a
// tracked link costs one RTM_GETLINK for the attach mode plus one
// BPF_OBJ_GET_INFO for the program identity, and nothing at all when no link is
// tracked; a DELEGATED surface costs at most one RTM_GETLINK to resolve its
// parent and never a bpf_link call, because it reuses the parent's
// already-computed classification; a declined surface is rendered from its
// recorded struct and costs nothing. It runs once per compile, never per packet
// or per poll tick.
//
// STAGE. The plan's §5 takes the FINAL proof after the last mutation that can
// invalidate it (networkd, the RETH MAC link-cycle, the AF_XDP rebind /
// deferred-worker reapply). This proof runs inside CompileUserspaceShim, i.e.
// at the PRELIMINARY attachment stage — it proves the attach-point INVENTORY
// and REPORTS the program instance each tracked bpf_link carries; it does NOT
// verify that instance is the shim's (see xdpLinkProgramID), and it cannot see
// XSK binding readiness. The divergence rate it measures is therefore the
// PRELIMINARY-stage rate, which is a lower bound on the gate's.
//
// The measurement matters because "armed" today is weaker than the proof:
// attachUserspaceShimXDP treats a NATIVE attach failure as a warning, detaches,
// and re-attaches in generic (skb) mode — only a GENERIC failure returns an
// error. So a box reports itself armed while running the whole shim on the
// fallback path, and iavf SR-IOV VFs (no native XDP support at all) make that a
// supported steady state, not a misconfiguration.

// SurfaceCoverageKind classifies how one required attach point is covered.
//
// CoverageUncovered is deliberately the ZERO value: an entry that was never
// populated must read as NOT covered. For a gate whose job is to fail closed,
// the uninitialised state has to be the conservative one.
type SurfaceCoverageKind int

const (
	// CoverageUncovered — no shim instance here and no proven delegate.
	// This is the only kind a gating build would refuse on.
	CoverageUncovered SurfaceCoverageKind = iota
	// CoverageDirect — a shim program instance is attached at this attach
	// point. Native and generic (skb-mode) both qualify; see below.
	CoverageDirect
	// CoverageDelegated — no attach is expected here BY DESIGN; the parent
	// interface's program covers this surface.
	CoverageDelegated
	// CoverageSkipped — the COMPILER declined to arm this surface and still
	// returned success. Neither proven covered nor proven forwarding-without-
	// policy; a third, distinct unknown. See UnarmedSurface. A surface whose
	// link framing is a provably unshimmable raw-L3 kind uses this same reported
	// branch, but is explicitly excluded from the gate verdict.
	//
	// CoverageUncovered remains the only kind a gating build refuses on.
	CoverageSkipped
)

func (k SurfaceCoverageKind) String() string {
	switch k {
	case CoverageDirect:
		return "direct"
	case CoverageDelegated:
		return "delegated"
	case CoverageSkipped:
		return "skipped"
	default:
		return "uncovered"
	}
}

// SurfaceCoverage is the proof outcome for one required attach point.
type SurfaceCoverage struct {
	Ifindex int
	// Name is the CONFIGURED interface name. Populated only for a surface the
	// compiler declined to arm, where the ifindex may not exist at all (the
	// netdev was missing, or the VLAN child was never created).
	Name string
	Kind SurfaceCoverageKind
	// Unshimmable marks a compiler refusal for a known raw-L3 link kind. Such
	// a surface remains operator-visible and counted as skipped, but it does
	// not contribute to Uncovered/WouldGate because the Ethernet-only shim
	// cannot safely attach there. The flag is set only by the closed
	// isProvablyUnshimmableEncap match in netdev_framing_8279.go.
	Unshimmable bool
	// Via is the covering parent ifindex when Kind is CoverageDelegated. It is
	// also set on an UNCOVERED VLAN child whose delegate was rejected, so the
	// record names the parent that failed to cover it.
	Via int
	// ProgramID is the attached program INSTANCE (bpf_link readback) for a
	// direct surface, or the delegate's instance for a delegated one. Zero
	// means the readback did not yield one — reported, never inferred. See
	// xdpLinkProgramID.
	ProgramID uint32
	// Generic records that this surface is covered in skb-mode rather than
	// driver-mode XDP. Informational: it does NOT reduce coverage. Read from
	// the KERNEL, not from compile bookkeeping — see xdpLinkModeGeneric.
	Generic bool
	Detail  string
}

// label renders the surface identity for the compact per-surface token: the
// configured name when the proof has one (an unarmed surface may have no
// ifindex at all), otherwise the ifindex.
func (s SurfaceCoverage) label() string {
	if s.Name != "" {
		return s.Name
	}
	return strconv.Itoa(s.Ifindex)
}

// ArmCoverageReport is the whole-surface outcome of one proof run.
type ArmCoverageReport struct {
	Surfaces  []SurfaceCoverage
	Direct    int
	Delegated int
	Skipped   int
	Uncovered int
	// Ran reports that the proof executed against real inputs. False means it
	// did not run at all (no compile result, or no instance lookup) — which is
	// a DIFFERENT unknown from "ran and enumerated nothing", and by this file's
	// own DidGate rationale the two must never be indistinguishable.
	Ran bool
	// WouldGate reports whether a GATING build would have refused to release
	// ownership on this proof. Observe-only: no caller may branch on it.
	WouldGate bool
	// DidGate reports whether anything was ACTUALLY withheld. It is
	// unconditionally false in this phase, and is a distinct field rather than
	// an omission on purpose: the divergence rate has to be readable directly
	// from a record that says "would have gated, did not", not inferred from
	// the ABSENCE of an enforcement line. An absence is indistinguishable from
	// a proof that never ran. The gating PR is what makes this field vary.
	DidGate bool
}

// SurfaceSummary renders one compact, greppable token per surface —
// "<ifindex|name>:<branch>[/<detail>]" — so the per-surface branch is
// recoverable from a single log line instead of requiring one line per
// interface on every apply.
func (rep ArmCoverageReport) SurfaceSummary() string {
	if len(rep.Surfaces) == 0 {
		return ""
	}
	parts := make([]string, 0, len(rep.Surfaces))
	for _, s := range rep.Surfaces {
		switch s.Kind {
		case CoverageDirect:
			parts = append(parts, fmt.Sprintf("%s:direct/%s", s.label(), attachModeName(s.Generic)))
		case CoverageDelegated:
			// The delegate's attach mode is rendered too: a VLAN child behind
			// an skb-mode parent IS on the slow path, and without the mode it
			// is indistinguishable from one behind a native parent — which is
			// exactly the population this phase exists to count.
			parts = append(parts, fmt.Sprintf("%s:delegated/via-%d/%s",
				s.label(), s.Via, attachModeName(s.Generic)))
		case CoverageSkipped:
			if s.Unshimmable {
				parts = append(parts, fmt.Sprintf("%s:skipped/unshimmable", s.label()))
			} else {
				parts = append(parts, fmt.Sprintf("%s:skipped", s.label()))
			}
		default:
			parts = append(parts, fmt.Sprintf("%s:uncovered", s.label()))
		}
	}
	return strings.Join(parts, " ")
}

func attachModeName(generic bool) string {
	if generic {
		return "generic"
	}
	return "native"
}

// GENERIC XDP COUNTS AS ARMED — a stated decision, not an emergent property.
//
// A generic (skb-mode) shim is enforcing policy. It is slower — this project
// measures roughly 16% CPU overhead from the per-packet sk_buff — but packets
// still reach userspace-dp and are still evaluated. #5275 exists to prevent a
// POLICY-FREE kernel, and a box on the fallback path is not policy-free.
// Failing it closed would brick a supported deployment (iavf SR-IOV VFs have no
// native XDP at all) to prevent a condition that is not occurring.
//
// This is written down here, and pinned by a test, precisely because it would
// otherwise be an implicit consequence of how the readback happens to be
// written — and a later "tighten the proof" change would flip a supported
// deployment to fail-closed with nobody intending it.

// DELEGATED COVERAGE — the case a native/generic binary misses entirely.
//
// A VLAN sub-interface under the userspace shim is NEVER attached: both attach
// loops skip it (loader.go, and compiler.go's isUserspaceShim branch) and it is
// recorded in Manager.VlanSubInterfaces instead. The reason is in the source at
// both sites — the PARENT's XDP sees VLAN-tagged frames before kernel VLAN
// demuxing, and swapping the shim onto the child breaks IPv6 NDP because
// generic-mode XDP_PASS does not deliver correctly to the kernel NDP stack on
// VLAN devices.
//
// So policy IS enforced for these, at a DIFFERENT attach point. A per-surface
// proof that demands an instance on "every mapped attach point" fails on every
// VLAN sub-interface — the loss cluster runs reth0.50 and reth0.80, the
// standalone VM runs VLAN 50 — i.e. it would fail-close essentially every real
// deployment. The opposite shortcut, skipping VLAN children unconditionally, is
// just as wrong: it would pass a surface whose coverage was never checked.
//
// Delegation is therefore RESOLVED, not assumed, and resolved against the
// proof's OWN classification of the parent: the parent must be a REQUIRED
// surface and must itself classify as CoverageDirect, or the child is
// uncovered. A link that merely happens to be tracked is not enough — an
// enabled->disabled commit leaves the previous parent link in place while the
// parent is admin-DOWN and about to be torn down, and delegating to that would
// report a covered child with nothing enforcing its traffic.

// UnappliedFilterBinding records a firewall-filter binding the CONFIG declared
// but the compiler could not assign, because the interface it names was not
// resolvable at assignment time (#6893).
//
// WHY THIS IS SEPARATE FROM UnarmedSurface. The two soft skips in
// compiler_iface.go already record the CAUSE — the physical interface was not
// found, or the VLAN child could not be created — as an UnarmedSurface. Nothing
// recorded the CONSEQUENCE: compileFirewallFilters resolves the same name,
// misses, logs a warning and continues, so the binding vanishes with no
// structured trace even internally. The cause was visible to the arm-coverage
// proof and its consequence was not, which is why "the filter silently went
// missing" is undetectable by anything except reading logs.
//
// It is not folded into UnarmedSurface for two reasons. A filter binding is not
// an attach point, which is what that type documents itself as. And
// recordUnarmedSurface dedups on (Name, Ifindex), so in the exact case this
// exists for — a VLAN child that could not be created, whose filter then cannot
// be assigned — the consequence record would dedup onto the cause record and be
// lost.
//
// This is a record, not a gate: the compile still succeeds. Failing the apply on
// a VLAN creation failure is the separate, narrower change (#6893 fix direction
// 1), and this record is what its demonstration cell inverts.
type UnappliedFilterBinding struct {
	// Interface is the configured surface the binding names — "ge-0-0-2" for a
	// physical miss, "ge-0-0-2.50" for a VLAN child.
	Interface string
	// Filters lists the declared bindings that were not applied, each rendered
	// as "<direction> <family>:<name>".
	Filters []string
	// Reason is the resolution failure that prevented assignment.
	Reason string
}

// UnarmedSurface records an attach point the CONFIG required but the compiler
// DECLINED to arm, while the compile itself still SUCCEEDED (#5275).
//
// Three soft skips in compiler_iface.go remove a surface from the required set
// behind nothing but a slog.Warn: the interface was not found, the VLAN
// sub-interface could not be created, and the interface is administratively
// disabled. Without a record the proof cannot tell "the compiler declined to
// arm this" from "this was armed successfully" — both read as clean, because
// the surface is simply absent from pendingXDP.
type UnarmedSurface struct {
	// Name is the configured interface ("ge-0-0-1", or "ge-0-0-2.50" for a
	// VLAN child). Always set: the ifindex may not exist.
	Name string
	// Ifindex is the resolved ifindex, or 0 when the surface has none.
	Ifindex int
	// Reason is the compiler's own reason for declining.
	Reason string
	// StillForwarding marks the sharp variant: the surface was skipped but the
	// netdev is (or may still be) UP, in a security zone, and forwarded through
	// by the kernel with NO XDP attached. `set interfaces <if> disable` whose
	// netlink.LinkSetDown then fails is exactly that — the disable branch logs
	// the failure at WARN and continues, and address reconciliation runs
	// regardless. That is the policy-free-router condition #5275 exists to
	// prevent, so it reads as UNCOVERED rather than merely skipped.
	StillForwarding bool
	// Unshimmable marks a surface refused because its resolved link framing is
	// one of the closed, provably raw-L3 kinds in
	// isProvablyUnshimmableEncap. It remains visible and counted in the report
	// as a skipped surface even when StillForwarding is true; it does not
	// contribute to Uncovered/WouldGate because the Ethernet-only shim cannot
	// safely attach there. Unknown framing kinds never receive this exemption.
	Unshimmable bool
}

// disabledSurfaceRecord classifies an administratively disabled interface.
//
// Split out of mapZoneInterface deliberately. The only judgement in it is
// StillForwarding, which is the whole difference between a benign operator
// action and a policy-free router — and producing the condition in a test
// (a real netdev whose LinkSetDown fails) needs CAP_NET_ADMIN, while deciding
// what such a failure MEANS does not. In the caller it was unbindable; here it
// is four table rows.
//
// linkErr is the netlink link-resolution error: non-nil means no handle was
// ever obtained, so LinkSetDown was never even attempted. downErr is
// LinkSetDown's own error. The netdev is proven down only when BOTH are nil.
// Anything else leaves it possibly UP, still address-reconciled (that call sits
// outside the disable guard), still in a zone, still forwarded through by the
// kernel, and carrying no XDP.
func disabledSurfaceRecord(name string, ifindex int, linkErr, downErr error) UnarmedSurface {
	s := UnarmedSurface{Name: name, Ifindex: ifindex}
	switch {
	case linkErr != nil:
		s.Reason = fmt.Sprintf("administratively disabled but the link never resolved (%v) — "+
			"never brought down, may still be UP and forwarding with no XDP", linkErr)
		s.StillForwarding = true
	case downErr != nil:
		s.Reason = fmt.Sprintf("administratively disabled but link-down FAILED (%v) — "+
			"netdev may still be UP and forwarding with no XDP", downErr)
		s.StillForwarding = true
	default:
		s.Reason = "administratively disabled (netdev brought down)"
	}
	return s
}

// missingInterfaceRecord classifies a zone interface the compiler could not
// resolve.
//
// The record names the SURFACE THE CONFIG ASKED FOR, not the netdev whose
// lookup failed. They differ for a VLAN child: mapZoneInterface resolves
// "reth0.50" to its PARENT before the lookup, so the failure arrives here
// carrying only the parent's name. Filing the child under the parent's name
// makes recordUnarmedSurface's (Name, Ifindex) dedup fold every child of one
// absent parent — and the parent's own record — into a SINGLE entry, while a
// parent that resolves yields one record per surface. The count is this
// phase's deliverable, so the same configured topology would report a
// different number of surfaces depending on a condition unrelated to how many
// surfaces exist, and always in the UNDER direction. The parent stays in the
// Reason, which is where an operator needs it: the child is missing BECAUSE
// its real device is.
//
// vlanID is the child's 802.1Q id, 0 for a physical/unit-0 reference — the
// same value mapZoneInterface uses to build the child's name, so the two sites
// cannot spell one surface two ways.
//
// "Not found" is NOT the only thing net.InterfaceByName reports through this
// error. It wraps a genuine absence (its own errNoSuchInterface) and a netlink
// DUMP failure (ENOBUFS / ENOMEM / EINTR, surfaced as a syscall.Errno) in the
// same *net.OpError. Only the first proves nothing forwards through the netdev;
// a dump failure says nothing at all about whether it exists, and it may be
// live, UP and in a zone. errNoSuchInterface is unexported, so the distinction
// is drawn from the WRAPPED type — a syscall.Errno means the enumeration
// failed, not that the interface is absent — and an unrecognised error falls to
// the absence branch only because that is what every non-errno error from this
// call means today.
func missingInterfaceRecord(physName string, vlanID int, zone string, err error) UnarmedSurface {
	name, subject := physName, "interface"
	if vlanID > 0 {
		name = fmt.Sprintf("%s.%d", physName, vlanID)
		subject = fmt.Sprintf("parent interface %s", physName)
	}
	s := UnarmedSurface{
		Name:   name,
		Reason: fmt.Sprintf("%s not found in zone %s: %v", subject, zone, err),
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		s.Reason = fmt.Sprintf("%s lookup FAILED in zone %s (%v) — "+
			"the netdev enumeration errored, so absence is unproven and it may be UP and forwarding", subject, zone, err)
		s.StillForwarding = true
	}
	return s
}

// ProveArmCoverage computes the arm-coverage proof for the surfaces result
// requires, WITHOUT gating anything (#5275 PR1, observe-only).
//
// It writes no Go state: not the Manager, and not the CompileResult it is
// proving (the link resolution deliberately uses peekLinkByIndex, which does
// not memoise, so the result's caches are untouched). It does READ live kernel
// and bpf state — see the SIDE EFFECTS note at the top of this file for the
// per-kind cost — and never returns an error a caller acts on. A
// readback failure degrades that surface to uncovered and is reported, the
// conservative direction, matching what a gating build would do.
func (m *Manager) ProveArmCoverage(result *CompileResult) ArmCoverageReport {
	if m == nil {
		return ArmCoverageReport{}
	}
	rep := classifyArmCoverage(result, m.attachedInstance)
	// #7191: publish the verdict so the daemon can GATE on it. Publishing from
	// INSIDE the proof (rather than from the call site) is deliberate: it makes
	// it impossible to publish a stashed or hand-built report, which is the same
	// property TestArmProofIsInvokedFromCompileUserspaceShim enforces for the
	// LOGGED report. The classification itself is unchanged and still writes no
	// state of its own.
	m.publishArmCoverage(rep)
	return rep
}

// instanceLookup reports the program instance bound at an ifindex.
//
// ok=false means "not covered here" — no tracked link, or a readback that
// failed. Injected so the classification is testable without a real bpf_link;
// production always passes Manager.attachedInstance.
type instanceLookup func(ifidx int) (progID uint32, generic bool, ok bool)

// classifyArmCoverage is the whole proof, separated from bpf so it can be
// exercised directly.
func classifyArmCoverage(result *CompileResult, lookup instanceLookup) ArmCoverageReport {
	var rep ArmCoverageReport
	if result == nil || lookup == nil {
		// Ran stays false: this proof did NOT run, which must not read the
		// same as a proof that ran and found nothing wrong.
		return rep
	}
	rep.Ran = true

	// Deterministic order so the log line is stable across boots and two
	// reports can be diffed.
	required := append([]int(nil), result.pendingXDP...)
	sort.Ints(required)
	isRequired := make(map[int]bool, len(required))
	for _, ifidx := range required {
		isRequired[ifidx] = true
	}

	// Pass 1 classifies every DIRECT surface, because a delegated surface
	// resolves against the parent's OWN classification and must not race the
	// order of the required slice.
	direct := make(map[int]SurfaceCoverage, len(required))
	for _, ifidx := range required {
		if isDelegatedSurface(result, ifidx) {
			continue
		}
		direct[ifidx] = coverDirect(lookup, ifidx)
	}

	// Pass 2 emits in ifindex order, resolving delegation against pass 1.
	unarmed := unarmedByIfindex(result)
	for _, ifidx := range required {
		if s, ok := direct[ifidx]; ok {
			rep.Surfaces = append(rep.Surfaces, s)
			continue
		}
		rep.Surfaces = append(rep.Surfaces, coverDelegated(result, direct, isRequired, unarmed, ifidx))
	}

	// Surfaces the compiler declined to arm are NOT in pendingXDP at all. They
	// are appended last so the required-surface ordering above is unchanged.
	rep.Surfaces = append(rep.Surfaces, unarmedCoverage(result)...)

	for _, s := range rep.Surfaces {
		switch s.Kind {
		case CoverageDirect:
			rep.Direct++
		case CoverageDelegated:
			rep.Delegated++
		case CoverageSkipped:
			rep.Skipped++
		default:
			rep.Uncovered++
		}
	}
	rep.WouldGate = rep.Uncovered > 0
	// Observe-only phase: nothing is ever withheld. Set explicitly so the
	// record carries the fact rather than leaving it to be inferred.
	rep.DidGate = false
	return rep
}

// isDelegatedSurface reports whether ifidx is a VLAN sub-interface, which the
// userspace shim covers from the parent rather than attaching to directly.
// This is exactly how compiler_iface.go marks them.
//
// It reports what the COMPILER INTENDED, not what the netdev is: the sole
// production writer of genericXDPIfindexes (compiler_iface.go, the VLAN-child
// site) records whatever ifindex ensureVLANSubInterface returned, and that
// function adopts an existing "<phys>.<vid>" without checking its kind. So a
// true answer here means "the compiler filed this as a VLAN child", and
// coverDelegated must still verify the kind against the kernel.
func isDelegatedSurface(result *CompileResult, ifidx int) bool {
	return result.genericXDPIfindexes[ifidx] && !result.tunnelIfindexes[ifidx]
}

// vlanLinkKind is netlink's kind string for an 802.1Q device — what
// (*netlink.Vlan).Type() returns, and what the kernel reports in
// IFLA_INFO_KIND. Compared as a string rather than type-asserting
// *netlink.Vlan so the decision and the operator-facing detail come from one
// call and cannot drift apart.
//
// WHAT THIS PROVES, exactly. Once the kind is "vlan", ParentIndex is the
// kernel's own real_dev for the 8021q device, so every downstream branch is
// reading a genuine VLAN-over-parent relationship, and the SKIPPED promotion's
// premise ("a VLAN cannot pass traffic while its real device is DOWN") holds
// against the device that actually carries it.
//
// WHAT IT DOES NOT PROVE, stated so a later reader does not assume more. The
// kind alone does NOT prove the parent is LOCAL. A genuine vlan whose real_dev
// lives in another network namespace keeps kind "vlan" and keeps a ParentIndex
// that now names an ifindex in the FOREIGN namespace — so it passes this belt
// and its parent key is meaningless here. That is why netnsIDLocal exists; see
// below.
//
// An earlier revision of this comment disposed of that case by asserting such
// an orphan is forced admin-DOWN, that LinkSetUp fails ENETDOWN, and that it
// cannot transmit. That is FALSE, and the experiment it came from only
// reproduced because it left the foreign real_dev DOWN. Re-measured on this
// kernel with three namespaces, moving the child out and leaving the real_dev
// behind: with the real_dev DOWN, LinkSetUp does fail (rc=2, ENETDOWN,
// flags=broadcast, oper=down) — but bring that real_dev UP in ITS OWN
// namespace and the orphan comes up (rc=0, flags=up|broadcast|running,
// oper=up) and forwards. `vlan_dev_open` refuses only while the real_dev is
// down; nothing pins it down permanently. So the orphan IS a live forwarding
// surface, and letting a same-numbered local record answer for it is exactly
// the under-count this belt exists to stop.
//
// Nor does it prove the resolved parent is the CONFIGURED one. An adopted vlan
// stacked on a different device delegates to that device instead. The verdict
// stays honest either way — the parent's XDP really does see that child's
// tagged frames, and a down parent really does stop it — so this belt is
// scoped to the kind. Binding the configured parent needs the compiler to
// record it per child, which is a CompileResult data-model change and not part
// of an observe-only phase.
const vlanLinkKind = "vlan"

// netnsIDLocal is the LinkAttrs.NetNsID value meaning "this link's real_dev
// lives in MY namespace", i.e. its ParentIndex is a local ifindex.
//
// The kernel emits IFLA_LINK_NETNSID only when the link's link_net differs
// from its dev_net (rtnl_fill_link_netnsid); for an 8021q device link_net is
// dev_net(real_dev). So the attribute is present EXACTLY when the parent is
// foreign. vishvananda/netlink pre-seeds -1 in LinkDeserialize
// (link_linux.go:2064) and overwrites it only from that attribute
// (link_linux.go:2304), so -1 means "not emitted" means "local parent".
//
// The comparison MUST be `!= -1`, never `> 0`: a foreign nsid of 0 is a real
// value and `> 0` misses it. (`>= 0` happens to be indistinguishable from
// `!= -1` for every producible value — the seed is the only negative one and
// the wire parse is unsigned — but `!= -1` is the spelling that says what it
// means, so keep it.) Two reasons, both
// measured rather than reasoned:
//
//  1. A foreign parent's nsid is commonly ZERO — the reproduction below read
//     netnsid=0 on the orphan — so `> 0` would let exactly the case this belt
//     exists for straight through.
//  2. netlink parses the wire s32 UNSIGNED: `int(native.Uint32(...))`. A wire
//     NETNSA_NSID_NOT_ASSIGNED (-1), which peernet2id_alloc can return when
//     the peer net is not alive, therefore arrives as 4294967295 on a 64-bit
//     build, not as -1. `!= -1` still catches it, in the conservative
//     direction; a signed-minded check would not.
//
// Measured on this kernel with this netlink version (dummy real_dev p0 + vlan
// child p0.100, child moved to a peer netns, probed through
// netlink.LinkByIndex):
//
//	p0.100  type="vlan" parentIndex=5 netnsid=0   real_dev DOWN -> LinkSetUp rc=2 (ENETDOWN)
//	p0.100  type="vlan" parentIndex=5 netnsid=0   real_dev UP   -> LinkSetUp rc=0, up|running
//	loc0.100 type="vlan" parentIndex=7 netnsid=-1 (local control, up|running)
//
// The middle row is the whole point: the orphan is a LIVE forwarding surface
// whose ParentIndex(5) is an ifindex in another namespace, free to collide
// with any local interface. Note the zero value of a hand-built
// netlink.LinkAttrs is 0, NOT -1. The -1 seed comes from netlink's own
// constructors — LinkDeserialize (which every production path here goes
// through) and NewLinkAttrs — never from a bare composite literal, which is
// what fixtures use. So a fixture must set this explicitly or it models a link
// production cannot produce, and 0 is not a harmless default: it is a real
// FOREIGN nsid that this belt rejects.
const netnsIDLocal = -1

// coverDirect classifies one attach point that must carry its own instance.
func coverDirect(lookup instanceLookup, ifidx int) SurfaceCoverage {
	s := SurfaceCoverage{Ifindex: ifidx}
	progID, generic, ok := lookup(ifidx)
	if !ok {
		s.Generic = generic
		s.Detail = "no shim instance attached"
		return s
	}
	s.Kind = CoverageDirect
	s.ProgramID = progID
	s.Generic = generic
	if generic {
		s.Detail = "attached (generic/skb-mode — enforcing, counts as armed)"
	} else {
		s.Detail = "attached (native)"
	}
	return s
}

// unarmedByIfindex indexes the surfaces the compiler declined to arm by their
// RESOLVED ifindex, for the delegation check in coverDelegated.
//
// Only entries with a real ifindex are indexed. A missing netdev, a VLAN child
// that was never created, and a nil zone slot all record Ifindex 0 by
// construction — they have no ifindex to record — and folding them onto one key
// would let any of them answer for some other surface's parent.
func unarmedByIfindex(result *CompileResult) map[int]UnarmedSurface {
	if len(result.unarmedSurfaces) == 0 {
		return nil
	}
	out := make(map[int]UnarmedSurface, len(result.unarmedSurfaces))
	for _, u := range result.unarmedSurfaces {
		if u.Ifindex > 0 {
			out[u.Ifindex] = u
		}
	}
	return out
}

// coverDelegated classifies one VLAN sub-interface against its parent.
//
// The parent must be a REQUIRED surface and must itself have classified as
// CoverageDirect. Accepting any tracked link would let a child report covered
// against a parent nothing proves is armed — see the DELEGATED COVERAGE note.
//
// The `direct` map already encodes both conditions (it holds exactly the
// required, non-delegated surfaces), so the explicit isRequired check does not
// change the verdict — it sharpens the recorded REASON, which is the whole
// output of an observe-only phase.
//
// `unarmed` is the one case where a parent OUTSIDE the required set is not a
// hole in the proof: see the PROVEN-DOWN PARENT note below.
//
// EVERY branch here reads ParentIndex as a LOCAL VLAN delegation, so the link
// must be PROVEN to be an 802.1Q device (vlanLinkKind) AND proven to have a
// same-namespace real_dev (netnsIDLocal) before that field means anything. The
// kind alone is not enough: an orphan vlan whose real_dev was left in another
// namespace keeps kind "vlan" and a foreign ParentIndex, and it is a live
// forwarding surface, not an inert one.
func coverDelegated(
	result *CompileResult,
	direct map[int]SurfaceCoverage,
	isRequired map[int]bool,
	unarmed map[int]UnarmedSurface,
	ifidx int,
) SurfaceCoverage {
	s := SurfaceCoverage{Ifindex: ifidx}

	lnk, err := result.peekLinkByIndex(ifidx)
	if err != nil {
		s.Detail = fmt.Sprintf("vlan child: parent unresolvable: %v", err)
		return s
	}
	if lnk == nil {
		s.Detail = "vlan child: parent unresolvable: no link"
		return s
	}
	// #6916 single-sourced the kind and namespace rejections into
	// vlanDelegationDefect, which is also what ensureVLANSubInterface now
	// consults before ADOPTING a device at "<phys>.<vid>". The two must agree:
	// this proof decides whether a surface is covered, that adoption decides
	// whether a device becomes the surface, and a device one trusts while the
	// other refuses it is exactly the state #5275 exists to make impossible.
	// The long-form reasoning for each rejection moved with the code.
	//
	// UNCOVERED is the honest reading of either rejection: nothing here proves
	// a shim covers this surface. Via is deliberately left ZERO — naming a
	// bogus parent in the record would repeat the same confusion in the
	// operator's log, and an under-count that hides a live forwarding surface
	// is worse for #5275 than the over-count this file already removed.
	if why := vlanDelegationDefect(lnk); why != "" {
		s.Detail = "vlan child: " + why + " and proves nothing about this surface"
		return s
	}
	parent := lnk.Attrs().ParentIndex
	if parent <= 0 {
		s.Detail = "vlan child: no parent ifindex"
		return s
	}
	s.Via = parent

	if !isRequired[parent] {
		// PROVEN-DOWN PARENT. A clean `set interfaces ge-0-0-2 disable` leaves
		// the child in pendingXDP and the parent out of it: compiler_iface.go
		// appends the VLAN child ~130 lines ABOVE the isDisabled check and
		// never appends a disabled parent. Read as "delegate not required" the
		// child lands UNCOVERED and drives WouldGate — on a legitimate
		// operator action, on precisely the interface shape both reference
		// deployments run (the loss cluster's reth0.50/reth0.80, the
		// standalone VM's VLAN 50). That is the inflated baseline this phase
		// exists to avoid, and it contradicts the stated rule that a clean
		// disable stays out of would-gate.
		//
		// It is not a hole in the proof either: a VLAN device cannot pass
		// traffic while its real device is DOWN, so a proven-down parent
		// proves the child is not forwarding. The child inherits SKIPPED — the
		// same third unknown the parent's own record carries, counted once per
		// surface.
		//
		// StillForwarding is the whole condition. A disable whose LinkSetDown
		// FAILED (or whose link never resolved, so it was never attempted)
		// leaves the parent possibly UP, zoned and carrying no XDP, and the
		// child rides that same netdev — so it stays UNCOVERED, which is the
		// policy-free-router reading both records should have.
		if u, ok := unarmed[parent]; ok && !u.StillForwarding {
			s.Kind = CoverageSkipped
			s.Detail = fmt.Sprintf(
				"vlan child: delegate %s (ifindex %d) was declined by the compiler and proven "+
					"down — %s", u.Name, parent, u.Reason)
			return s
		}
		s.Detail = fmt.Sprintf(
			"vlan child: delegate ifindex %d is not a required surface — nothing proves it armed", parent)
		return s
	}
	pc, ok := direct[parent]
	if !ok {
		s.Detail = fmt.Sprintf(
			"vlan child: delegate ifindex %d is not itself a direct surface", parent)
		return s
	}
	if pc.Kind != CoverageDirect {
		s.Detail = fmt.Sprintf(
			"vlan child: delegate ifindex %d carries no shim instance", parent)
		return s
	}

	s.Kind = CoverageDelegated
	s.ProgramID = pc.ProgramID
	s.Generic = pc.Generic
	s.Detail = fmt.Sprintf("covered by parent ifindex %d", parent)
	return s
}

// unarmedCoverage renders the surfaces the compiler declined to arm.
//
// Ordered by name so two reports of the same box are diffable; the ifindex is
// not a usable sort key here because a missing interface has none.
func unarmedCoverage(result *CompileResult) []SurfaceCoverage {
	if len(result.unarmedSurfaces) == 0 {
		return nil
	}
	out := make([]SurfaceCoverage, 0, len(result.unarmedSurfaces))
	for _, u := range result.unarmedSurfaces {
		s := SurfaceCoverage{
			Ifindex:     u.Ifindex,
			Name:        u.Name,
			Kind:        CoverageSkipped,
			Unshimmable: u.Unshimmable,
			Detail:      u.Reason,
		}
		if u.StillForwarding && !u.Unshimmable {
			s.Kind = CoverageUncovered
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Ifindex < out[j].Ifindex
	})
	return out
}

// Kernel XDP attach modes (uapi/linux/if_link.h, mirrored in nl/link_linux.go).
const (
	xdpAttachedNone  = 0 // no program attached
	xdpAttachedDrv   = 1 // XDP_ATTACHED_DRV — driver (native) mode
	xdpAttachedSKB   = 2 // XDP_ATTACHED_SKB — generic (skb) mode
	xdpAttachedHW    = 3 // XDP_ATTACHED_HW  — hardware offload
	xdpAttachedMulti = 4 // XDP_ATTACHED_MULTI — programs in more than one mode
)

// xdpModeIsGeneric decides whether a kernel attach mode counts as skb-mode for
// the coverage measurement. Pure, so every mode including the ones a test
// cannot produce is covered by a table.
//
// XDP_ATTACHED_MULTI counts as GENERIC. It means programs are attached in more
// than one mode, so the kernel cannot report a single one — and it is reachable
// here: attachUserspaceShimXDP DISCARDS m.DetachXDP's error on the native
// fallback path, so a failed detach followed by the generic re-attach leaves
// two links on the interface. Reading MULTI as native would undercount the
// slow-path population, which is the same direction as the defect that made
// this flag come from the kernel in the first place.
func xdpModeIsGeneric(attached bool, mode uint32) bool {
	if !attached {
		return false
	}
	return mode == xdpAttachedSKB || mode == xdpAttachedMulti
}

// xdpLinkModeGeneric reports whether ifindex currently carries an XDP program
// in GENERIC (skb) mode, read from the KERNEL.
//
// Ground truth, deliberately, and not control-plane bookkeeping. The
// native->generic fallback in attachUserspaceShimXDP happens ONCE, and the
// resulting m.xdpLinks entry SURVIVES across compiles — syncInterfaceAttachments
// detaches only ifindexes outside the allowed ingress set, and the pin sweep in
// userspace/manager_compile.go deletes link PINS, not the map. So every later
// compile short-circuits on "already attached" and any per-compile record of
// the fallback is empty while the box is still on skb-mode. A proof that read
// that record would report "went native" on every commit after the first, on
// precisely the population (iavf SR-IOV VFs) whose measurement is the point of
// this phase.
//
// A package-level var because a unit test cannot attach XDP.
var xdpLinkModeGeneric = func(ifindex int) bool {
	l, err := netlink.LinkByIndex(ifindex)
	if err != nil || l == nil {
		return false
	}
	xdp := l.Attrs().Xdp
	if xdp == nil {
		return false
	}
	return xdpModeIsGeneric(xdp.Attached, xdp.AttachMode)
}

// xdpLinkProgramID reads back the program instance bound to a tracked bpf_link.
//
// A package-level var because link.Link carries an unexported method and cannot
// be implemented outside cilium/ebpf, so Manager.attachedInstance is otherwise
// unreachable from a unit test.
//
// WHAT IS NOT PROVEN — the residual this observe-only phase leaves for the
// gate, named so nobody reads more into the ProgramID than it carries.
//
// This accepts ANY readable program id. It does not compare it against
// m.programs[m.XDPEntryProgram()] (the program AttachXDP installs), and it does
// not check Info.XDP().Ifindex against the ifindex the surface is being proved
// for. So the proof shows an instance EXISTS and reports which one; it does not
// show it is the shim's, nor that the link is attached where the Manager
// believes.
//
// It is sound TODAY, by an invariant that lives entirely in other functions —
// which is exactly why the gate cannot inherit it. Every writer of m.xdpLinks
// installs m.programs[m.XDPEntryProgram()]: AttachXDP's fresh attach
// (link.XDPOptions{Program: prog}) and its pinned-link reuse (existing.Update
// (prog), the pin dropped and re-attached when that fails), and swapXDPEntryProg,
// which updates the tracked links and only then makes XDPEntryProgram() name
// the program it installed — though note it SKIPS VLAN sub-interfaces
// (loader.go, m.VlanSubInterfaces), and it returns on the FIRST per-link
// Update error without advancing m.xdpEntryProg, so a partial swap leaves some
// links on the new program while XDPEntryProgram() still names the old one.
// Neither state is reachable through today's daemon lifecycle: only the shim is
// loaded, it is selected before attachment, and the swap calls are guarded.
// Post-#1476 m.programs has one writer for the shim (loader_userspace_shim.go)
// and the legacy entry program is never loaded, so there is a single candidate
// to compare against.
//
// Be precise about WHY that holds, because an earlier revision of this comment
// was wrong and the gate must not inherit the error. It is NOT encapsulation:
// Manager.XDPLinks() (loader.go) returns the LIVE m.xdpLinks map by reference,
// and Manager.Program(name) returns a live *ebpf.Program handle, so an
// out-of-package holder of a *Manager can reach a tracked link and Update it.
// The two current out-of-package callers — userspace/manager_compile.go and
// userspace/maps_sync.go — read only len and keys, never the link values. So
// the invariant is upheld by the CALL SITES, not by the API, and a future
// caller in pkg/dataplane/userspace could falsify it without touching any
// signature. (A shallow map copy would not fix that either; the link.Link
// values stay mutable. A key-only snapshot API would.)
//
// On that basis the comparison is deliberately DEFERRED to the gating PR
// rather than claimed impossible: at this head it would measure nothing, while
// introducing a new way to report a false uncovered (an unreadable expected
// program), and the fixture binding it would have to be fabricated.
//
// The GATE must still add it. A build that withholds ownership, forwarding and
// route/VIP advertisement must not rest its refusal on an invariant upheld by
// callers elsewhere in the package — and the gate has to decide the direction
// this phase has no evidence for: whether an UNREADABLE expected program fails
// closed. That decision belongs where it withholds traffic, not in a
// diagnostic. Plan §13/D1 carries the same split.
var xdpLinkProgramID = func(l link.Link) (progID uint32, ok bool) {
	if l == nil {
		return 0, false
	}
	info, err := l.Info()
	if err != nil || info == nil {
		return 0, false
	}
	return uint32(info.Program), true
}

// attachedInstance reads back the program instance bound at ifidx.
//
// ok=false means no link is tracked for this ifindex, or the readback failed —
// both degrade the surface to uncovered rather than being papered over.
//
// The generic flag is the LIVE kernel attach mode (xdpLinkModeGeneric), not
// anything this compile recorded, because the mode persists across compiles and
// the per-compile record does not.
func (m *Manager) attachedInstance(ifidx int) (progID uint32, generic bool, ok bool) {
	// #6740: guarded read. xdpLinkModeGeneric / xdpLinkProgramID below issue
	// netlink+BPF queries, so the lock is released before them.
	l, exists := m.xdpLinkFor(ifidx)
	if !exists {
		return 0, false, false
	}
	generic = xdpLinkModeGeneric(ifidx)
	progID, ok = xdpLinkProgramID(l)
	if !ok {
		// A tracked link whose identity cannot be read is NOT proof of
		// coverage; report it with a zero instance so the divergence is
		// visible rather than assumed benign.
		return 0, generic, false
	}
	return progID, generic, true
}

// LogArmCoverage emits the observe-only proof result (#5275 PR1).
//
// One SUMMARY line per COMPILE — never per packet or per poll tick — plus one
// line for each surface a gating build would refuse on and each the compiler
// declined to arm (the loop at the tail). A fully-covered box stays at the one
// line. Not one line per apply: a single daemon apply compiles TWICE on the
// RETH deferred-MAC path (daemon_apply_dataplane.go calls
// reapplyAfterDeferredMAC), so seq is folded into the stage label to keep the
// two records distinguishable.
//
// The line is emitted UNCONDITIONALLY, including when the proof enumerated no
// surfaces at all. Suppressing it would make "nothing to arm", "the proof did
// not run" and "the build has no proof" identical in a log archive — the very
// failure mode this file's DidGate rationale exists to reject. `ran` separates
// the first two; the absence of the line separates the third.
//
// It states plainly that nothing was gated, so an operator reading a WOULD-GATE
// line does not believe traffic was affected.
func (rep ArmCoverageReport) LogArmCoverage(stage string, seq uint64) {
	// One label for the whole proof run, so the summary line and every
	// per-surface line below correlate to the SAME compile.
	label := fmt.Sprintf("%s#%d", stage, seq)
	slog.Info("dataplane arm-coverage proof",
		"issue", "#5275",
		"stage", label,
		"ran", rep.Ran,
		"direct", rep.Direct,
		"delegated", rep.Delegated,
		"skipped", rep.Skipped,
		"uncovered", rep.Uncovered,
		// Both are emitted every time. would_gate is the measurement;
		// did_gate is the fact that nothing was withheld. Reporting only the
		// first would make "the proof said refuse" and "the proof refused"
		// indistinguishable in a log archive.
		"would_gate", rep.WouldGate,
		"did_gate", rep.DidGate,
		// Per-surface branch, so the direct/delegated/skipped/uncovered mix is
		// recoverable per box without one line per interface.
		"surfaces", rep.SurfaceSummary())
	// Only the surfaces a gating build would have refused on are worth a
	// per-surface line; a fully-covered box stays at one line. A SKIPPED
	// surface gets one too — the compiler declined to arm it and said so only
	// in its own terms, so the proof restates it in the proof's.
	//
	// The two levels are not cosmetic. WARN is the would-gate set: a surface a
	// gating build would refuse on. A skip is the benign branch — the dominant
	// member is a clean `disable`, which is a legitimate operator action and is
	// excluded from would_gate for exactly that reason — so it is INFO. Logging
	// it at WARN would put a routine commit's expected output at the same level
	// as the policy-free-router condition and train operators to ignore both.
	for _, s := range rep.Surfaces {
		switch s.Kind {
		case CoverageUncovered:
			slog.Warn("dataplane arm-coverage: surface WOULD fail a gating proof (NOT gated in this build)",
				"issue", "#5275",
				"stage", label,
				"surface", s.label(),
				"detail", s.Detail)
		case CoverageSkipped:
			slog.Info("dataplane arm-coverage: compiler DECLINED to arm this surface (compile still succeeded)",
				"issue", "#5275",
				"stage", label,
				"surface", s.label(),
				"detail", s.Detail,
				"unshimmable", s.Unshimmable)
		}
	}
}
