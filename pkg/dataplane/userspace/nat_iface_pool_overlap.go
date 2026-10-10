package userspace

import (
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync/atomic"
)

// #7717 — DETECTION ONLY.
//
// The config-time gate (#7645, pkg/config/compiler_nat_iface_egress.go) forecloses
// a NAT pool overlapping an interface-mode SNAT egress address when that address is
// CONFIGURED. It says so itself, and says why the other half was not shipped:
//
//	"Runtime-resolved addresses (DHCP, netlink) are deliberately out of scope here
//	 — foreclosing those is the snapshot-builder half of §5.7 and needs the DRAIN
//	 discipline behind it, because marking a pool unusable with nothing draining
//	 would strand live sessions."
//
// This is that snapshot-builder half, DETECTING and reporting only. It does NOT
// mark the pool unusable and does not touch `pool_failure`: quarantining with
// nothing draining is the stranding the merged gate names. The quarantine ships
// with the drain, in one change, where a test can make it fire.
//
// Why detection is worth shipping alone: the overlap is silent today. Two
// allocators mint the same (E, port) — demonstrated by
// `defect_pin_pool_and_interface_snat_mint_one_identity_7717` — and an operator
// has no signal that they are in that state. This gives them one, and gives the
// drain PR a measurement to validate against.
//
// NOTE ON TIMING, and it is the reason this half exists at all: this runs at
// SNAPSHOT BUILD, not at commit. A runtime-learned address is unknown at commit
// time by definition, so a commit-time check cannot see it — that is precisely
// the gap #7645 left. DHCP address changes trigger a full recompile, so a lease
// that creates an overlap is detected on the rebuild it causes.

// interfaceSNATPoolOverlap is one (address, pool rule, interface rule) finding.
type interfaceSNATPoolOverlap struct {
	// Address is the host form of the overlapping egress address.
	Address string
	// Interface is the snapshot interface whose live address it is.
	Interface string
	// InterfaceRule and PoolRule name the two rules whose domains collide.
	InterfaceRule string
	PoolRule      string
}

func (o interfaceSNATPoolOverlap) String() string {
	return fmt.Sprintf("address %s on %s: interface-mode rule %q and pool rule %q",
		o.Address, o.Interface, o.InterfaceRule, o.PoolRule)
}

// snatOverlapScans counts DETECTOR RUNS; snatOverlapAddresses is the count from
// the most recent run.
//
// Two values, deliberately. A single "overlaps" gauge reads 0 both when there is
// no overlap and when the detector never ran — the same ambiguity that let an
// unguarded headroom read report "enormous room" at the moment headroom was
// unknown. `scans_total == 0` means UNKNOWN, not healthy.
var (
	snatOverlapScans     atomic.Uint64
	snatOverlapAddresses atomic.Uint64
)

// InterfaceSNATPoolOverlapStats reports (scans, overlapping addresses at the last
// scan). A caller MUST read scans first: zero scans means the detector has not
// run and the address count carries no information.
func InterfaceSNATPoolOverlapStats() (scans uint64, addresses uint64) {
	return snatOverlapScans.Load(), snatOverlapAddresses.Load()
}

// interfaceSNATEgressCandidatesFromSnapshot derives, from the SNAPSHOT's live
// interface addresses, the set of addresses an interface-mode SNAT rule can
// translate onto — the same matrix `interfaceSNATEgressAddresses` applies to
// config, on runtime-resolved data.
//
// The scope semantics are AND-of-non-empty-constraints, mirroring the dataplane's
// `scope_matches` and the config-time gate: each configured to-side scope must
// agree, an unconfigured scope does not constrain, and a rule with NO to-side
// scope is a wildcard over every interface. The wildcard row is the one the old
// `maps_sync.go` precedent got wrong by returning nothing, which understates the
// candidate set exactly where it is widest.
//
// Returns address -> label naming why it is a candidate.
func interfaceSNATEgressCandidatesFromSnapshot(snap *ConfigSnapshot) map[string]string {
	if snap == nil || len(snap.Interfaces) == 0 {
		return nil
	}
	out := make(map[string]string)
	rules := append([]SourceNATRuleSnapshot(nil), snap.SourceNAT...)
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Name < rules[j].Name })
	ifaces := append([]InterfaceSnapshot(nil), snap.Interfaces...)
	sort.SliceStable(ifaces, func(i, j int) bool { return ifaces[i].Name < ifaces[j].Name })

	for _, rule := range rules {
		if !rule.InterfaceMode {
			continue
		}
		for _, ifc := range ifaces {
			if !interfaceInSnapshotEgressScope(rule, ifc) {
				continue
			}
			for _, a := range ifc.Addresses {
				host := hostOfSnapshotAddress(a.Address)
				if host == "" {
					continue
				}
				if _, seen := out[host]; !seen {
					out[host] = fmt.Sprintf("interface-mode source-NAT rule %q egress %s",
						rule.Name, ifc.Name)
				}
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// interfaceInSnapshotEgressScope applies the derivation matrix for ONE snapshot
// interface against ONE interface-mode rule's to-side scope. It is an
// over-approximating detector for #7717 only; forwarding registration uses
// interfaceSnapshotCanBeSNATEgress and exact logical-name matching.
func interfaceInSnapshotEgressScope(rule SourceNATRuleSnapshot, ifc InterfaceSnapshot) bool {
	if rule.ToInterface != "" && !snapshotInterfaceNameMatches(rule.ToInterface, ifc.Name) {
		return false
	}
	if rule.ToRoutingInstance != "" && rule.ToRoutingInstance != ifc.RoutingInstance {
		return false
	}
	if rule.ToZone != "" && rule.ToZone != ifc.Zone {
		return false
	}
	return true
}

// natEgressLifelineBaseName is the interface name with any unit suffix
// removed — the string the lifeline arms test.
func natEgressLifelineBaseName(name string) string {
	if idx := strings.IndexByte(name, '.'); idx >= 0 {
		return name[:idx]
	}
	return name
}

// interfaceSnapshotCanBeSNATEgress reports whether a snapshot row can be a
// runtime interface-mode SNAT egress. The helper builds its forwarding maps
// only for rows with ifindex>0. Management/HA/fabric/loopback lifelines are
// excluded, but tunnel rows are retained because they can carry egress.
// Unzoned rows stay local so the #5659 empty-zone sentinel remains armed.
func interfaceSnapshotCanBeSNATEgress(ifc *InterfaceSnapshot) bool {
	if ifc.Ifindex <= 0 || ifc.AdminDisabled || ifc.Zone == "" {
		return false
	}
	base := natEgressLifelineBaseName(ifc.Name)
	return !strings.HasPrefix(base, "fxp") &&
		!strings.HasPrefix(base, "em") &&
		!strings.HasPrefix(base, "fab") &&
		base != "lo0"
}

// snapshotInterfaceNameMatches intentionally accepts a bare unit base only
// for the over-approximating #7717 detection matcher, never registration.
func snapshotInterfaceNameMatches(want, have string) bool {
	if want == have {
		return true
	}
	if base, _, ok := strings.Cut(have, "."); ok && want == base {
		return true
	}
	return false
}

// hostOfSnapshotAddress strips any prefix length. Snapshot addresses are stored
// as "A.B.C.D/len" or bare hosts depending on source, so both are accepted; a
// value that does not parse as an IP contributes nothing rather than being
// compared as a string.
func hostOfSnapshotAddress(addr string) string {
	s := strings.TrimSpace(addr)
	if s == "" {
		return ""
	}
	if host, _, ok := strings.Cut(s, "/"); ok {
		s = host
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return ""
	}
	return ip.String()
}

// detectInterfaceSNATPoolOverlaps reports every (pool address, interface-mode
// egress address) coincidence in the snapshot.
//
// Pool addresses are compared as HOSTS. A pool member expressed as a range or
// prefix is out of scope for this detector and is skipped rather than
// approximated — reporting a maybe-overlap as an overlap would make the warning
// unactionable, and this half exists to give operators a signal they can act on.
// That limitation is stated in the warning's own text.
func detectInterfaceSNATPoolOverlaps(snap *ConfigSnapshot) []interfaceSNATPoolOverlap {
	if snap == nil {
		return nil
	}
	candidates := interfaceSNATEgressCandidatesFromSnapshot(snap)
	if len(candidates) == 0 {
		return nil
	}
	ifaceRuleFor := make(map[string]string, len(candidates))
	ifaceNameFor := make(map[string]string, len(candidates))
	for addr, label := range candidates {
		ifaceRuleFor[addr] = label
		ifaceNameFor[addr] = label
	}

	rules := append([]SourceNATRuleSnapshot(nil), snap.SourceNAT...)
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Name < rules[j].Name })

	var out []interfaceSNATPoolOverlap
	seen := make(map[string]struct{})
	for _, rule := range rules {
		if rule.InterfaceMode || len(rule.PoolAddresses) == 0 {
			continue
		}
		for _, member := range rule.PoolAddresses {
			host := hostOfSnapshotAddress(member)
			if host == "" {
				continue
			}
			if _, isCandidate := candidates[host]; !isCandidate {
				continue
			}
			key := host + "\x00" + rule.Name
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, interfaceSNATPoolOverlap{
				Address:       host,
				Interface:     ifaceNameFor[host],
				InterfaceRule: ifaceRuleFor[host],
				PoolRule:      rule.Name,
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Address != out[j].Address {
			return out[i].Address < out[j].Address
		}
		return out[i].PoolRule < out[j].PoolRule
	})
	return out
}

// reportInterfaceSNATPoolOverlaps runs the detector over a freshly built
// snapshot, QUARANTINES each overlapping pool, logs one warning per finding,
// and records the counters.
//
// It ALWAYS bumps the scan counter, including when nothing overlaps — that is
// what lets a reader tell "no overlap" from "detector never ran".
//
// #7717 part 2: the quarantine is enabled HERE, in the same change as the
// dataplane drain that makes it safe. Shipping it earlier would have marked
// pools unusable with nothing draining, which the merged config gate names as
// stranding live sessions — and a quarantine wired but disabled could not have
// been mutation-tested, because nothing would make it fire.
//
// `PoolUnusable` is the SHIPPED transport for this: the Rust side already maps
// it onto `pool_failure`, which already refuses new mints. What the drain adds
// is that the quarantined pool's allocator is now RETAINED so its live flows
// can still release, and that interface-mode mints on the address fail closed
// until that drain completes.
func reportInterfaceSNATPoolOverlaps(snap *ConfigSnapshot) {
	overlaps := detectInterfaceSNATPoolOverlaps(snap)
	snatOverlapScans.Add(1)
	snatOverlapAddresses.Store(uint64(len(overlaps)))
	if len(overlaps) == 0 {
		return
	}

	quarantined := make(map[string]struct{}, len(overlaps))
	for _, o := range overlaps {
		quarantined[o.PoolRule] = struct{}{}
	}
	for i := range snap.SourceNAT {
		if _, hit := quarantined[snap.SourceNAT[i].Name]; !hit {
			continue
		}
		snap.SourceNAT[i].PoolUnusable = true
		// Preserve an existing reason: a pool already unusable for its own
		// sake (empty, invalid range) stays reported as that. Overwriting it
		// would replace a specific diagnosis with a less specific one.
		if snap.SourceNAT[i].PoolUnusableReason == "" {
			snap.SourceNAT[i].PoolUnusableReason = poolUnusableReasonIfaceOverlap
		}
	}

	for _, o := range overlaps {
		slog.Warn("source-NAT pool overlaps an interface-SNAT egress address and has been "+
			"QUARANTINED; its live flows drain and interface-mode mints on the address "+
			"fail closed until they do",
			"address", o.Address,
			"pool_rule", o.PoolRule,
			"interface_rule", o.InterfaceRule,
			"issue", "#7717",
			"note", "pool members expressed as ranges or prefixes are not compared")
	}
}

// poolUnusableReasonIfaceOverlap is the snapshot reason string for a pool
// quarantined because its address is also an interface-SNAT egress address.
const poolUnusableReasonIfaceOverlap = "iface_snat_egress_overlap"
