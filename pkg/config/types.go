package config

import (
	"fmt"
	"strconv"
	"strings"
)

// LinuxIfName translates a Junos-style interface name (e.g. "ge-0/0/0")
// to a valid Linux interface name (e.g. "ge-0-0-0"). Linux IFNAMSIZ
// forbids "/" so we replace with "-".
func LinuxIfName(name string) string {
	return strings.ReplaceAll(name, "/", "-")
}

// DHCPLeaseIfName returns the Linux interface name under which the
// DHCP manager keys the lease for the given configured interface unit:
// LinuxIfName(ifName), plus a ".<vlan-id>" suffix when the unit is
// 802.1Q tagged. Note the suffix is the unit's VLAN ID, NOT its unit
// number — the two coincide by convention but are distinct concepts,
// bridged only here. Shared by the daemon's buildDHCPClientSpecs and
// the ip-monitoring interface-typed next-hop compiler (#1844) so the
// two derivations can never drift.
func DHCPLeaseIfName(ifName string, unit *InterfaceUnit) string {
	base := LinuxIfName(ifName)
	if unit != nil && unit.VlanID > 0 {
		return fmt.Sprintf("%s.%d", base, unit.VlanID)
	}
	return base
}

// InterfaceHasVlanSubinterface reports whether ifCfg carries at least one
// configured 802.1Q VLAN subinterface (a logical unit with VlanID > 0).
//
// It is the SCOPE of every RX-VLAN-hardware-offload fail-closed decision. Only
// a parent that classifies traffic by in-frame VLAN tag is at risk when the tag
// is HW-stripped: the XDP dataplane derives 802.1Q identity solely from the
// in-frame tag, so a stripped tag makes a frame parse as vlan_id=0 and fall
// back to the PHYSICAL parent ifindex — untrusted VLAN traffic classified into
// the parent's zone. A plain parent has no such mapping to get wrong, so a
// disable failure there is tolerated rather than failing the operator's commit.
//
// Shared, like DHCPLeaseIfName above, so the two enforcement points cannot
// drift: the compile-time activation gate (#5268,
// pkg/dataplane.rxVlanOffloadActivationError) and the post-link-cycle
// re-disable (#9946, pkg/daemon.reDisableRxVlanAfterLinkCycle). They must agree
// on scope in BOTH directions — a post-cycle fault wider than the compile gate
// would fail commits on plain parents that never strip a tag, and a narrower
// one would leave the bypass the compile gate exists to prevent.
func InterfaceHasVlanSubinterface(ifCfg *InterfaceConfig) bool {
	if ifCfg == nil {
		return false
	}
	for _, unit := range ifCfg.Units {
		if unit != nil && unit.VlanID > 0 {
			return true
		}
	}
	return false
}

// InterfaceSlot extracts the FPC slot number from an interface name, in BOTH
// spellings this codebase uses:
//
//	"ge-0/0/7" → 0   "ge-7/0/7" → 7   "xe-3/1/2" → 3   (Junos config spelling)
//	"ge-0-0-7" → 0   "ge-7-0-7" → 7                    (operational spelling)
//
// Returns -1 for a name carrying no FPC slot at all ("fab0", "em0", "reth0",
// "st0.1"), which is what every caller's `>= 0` guard is testing for.
//
// #8829: THE DASH SPELLING IS NOT AN ALIAS, IT IS THE ONE OPERATORS SEE.
// linksetup.go emits `ge-%d-0-%d`, so `show interfaces`, the `.link` files and
// the topology tables all render dashes, while config and this function spoke
// only slashes. An operator copying a name out of an operational surface wrote
// the spelling that did not resolve. Two conventions both exist deliberately;
// what was wrong was that only one of them was parseable here.
//
// TWO DEFECTS FOLLOWED, and the second is the dangerous one:
//
//   - RethToPhysical scores members 2=local, 0=peer, 1=slot-unknown. A dash
//     name returned -1, so BOTH members scored 1 and the tie broke
//     ALPHABETICALLY: on node 1, `reth0` resolved to `ge-0-0-0` — node 0's
//     member. Measured before this change.
//   - Every alignment gate is `InterfaceSlot(...) >= 0` (compiler_chassis.go,
//     and the #8444 fabric-member validator), so THE SPELLING THAT NEEDED
//     VALIDATION WAS THE ONE THAT SKIPPED IT. A wrong-node dash name committed
//     clean while its slash twin was rejected. Normalising the parse without
//     that gate firing would have left the fail-open in place.
//
// Measured after: the dash form now behaves IDENTICALLY to the slash form on
// both paths — strict commit rejects a wrong-node name, the tolerant load path
// warns and continues — so a persisted config still boots (#1319) and nothing
// that committed before is newly unbootable.
func InterfaceSlot(name string) int {
	// Find the first "-" separator, then parse the FPC number up to the next
	// separator, which is "/" in the config spelling and "-" in the
	// operational one.
	dashIdx := strings.Index(name, "-")
	if dashIdx < 0 || dashIdx+1 >= len(name) {
		return -1
	}
	rest := name[dashIdx+1:]
	sepIdx := strings.Index(rest, "/")
	if sepIdx < 0 {
		sepIdx = strings.Index(rest, "-")
	}
	if sepIdx < 0 {
		return -1
	}
	slot, err := strconv.Atoi(rest[:sepIdx])
	if err != nil {
		return -1
	}
	return slot
}

// SlotToNodeID maps a vSRX FPC slot to a cluster node-id.
// Convention: slot 0 → node0, slot 7 → node1.
func SlotToNodeID(slot int) int {
	if slot == 7 {
		return 1
	}
	return 0
}

// RethToPhysical returns a map of reth name → local physical member name.
// Built from interfaces that have RedundantParent set.
func (c *Config) RethToPhysical() map[string]string {
	m := make(map[string]string)
	bestScore := make(map[string]int)
	localNodeID := -1
	if c.Chassis.Cluster != nil {
		localNodeID = c.Chassis.Cluster.NodeID
	}
	for _, ifc := range c.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		if ifc.RedundantParent != "" {
			score := 1
			if localNodeID >= 0 {
				slot := InterfaceSlot(ifc.Name)
				if slot >= 0 {
					if SlotToNodeID(slot) == localNodeID {
						score = 2
					} else {
						score = 0
					}
				}
			}
			prev, ok := m[ifc.RedundantParent]
			if !ok || score > bestScore[ifc.RedundantParent] ||
				(score == bestScore[ifc.RedundantParent] && ifc.Name < prev) {
				m[ifc.RedundantParent] = ifc.Name
				bestScore[ifc.RedundantParent] = score
			}
		}
	}
	return m
}

// ResolveReth resolves "reth0" or "reth0.50" to the physical member equivalent.
// Returns input unchanged if not a RETH name.
func (c *Config) ResolveReth(ref string) string {
	rethMap := c.RethToPhysical()
	parts := strings.SplitN(ref, ".", 2)
	if phys, ok := rethMap[parts[0]]; ok {
		if len(parts) == 2 {
			return phys + "." + parts[1]
		}
		return phys
	}
	return ref
}

// ResolveFab resolves "fab0" or "fab0.0" to the backing physical member
// interface using LocalFabricMember. Returns input unchanged if not a fab name
// or the interface has no LocalFabricMember set.
func (c *Config) ResolveFab(ref string) string {
	parts := strings.SplitN(ref, ".", 2)
	base := parts[0]
	if c.Interfaces.Interfaces == nil {
		return ref
	}
	ifc, ok := c.Interfaces.Interfaces[base]
	if !ok || ifc == nil || ifc.LocalFabricMember == "" {
		return ref
	}
	resolved := ifc.LocalFabricMember
	if len(parts) == 2 {
		return resolved + "." + parts[1]
	}
	return resolved
}

// ResolveKernelIfName converts a Junos-style interface reference
// (as found in zone declarations and the keys of
// cfg.Interfaces.Interfaces) to the Linux kernel ifname it should
// resolve to on the LOCAL node.
//
// This is a DISPLAY-name resolver for API readers — it is NOT the
// same as ResolveFab (which returns the fabric overlay's parent
// physical member for BPF attachment). fab0 itself is a real kernel
// IPVLAN device, so API queries on fab0 must look up "fab0", not
// its parent. st0.x resolves to the xfrmi device derived from the
// AUTHORED bind-interface, which is not always the ref itself.
//
// Resolution semantics, in order:
//  1. Bare refs (no "." suffix):
//     - reth* → ResolveReth → physical member, LinuxIfName.
//     - all others (fxp0, em0, fab0, lo, ge-0/0/0, gr-0/0/0, st0):
//     LinuxIfName(ref). Matches snapshotLinuxName for the no-unit
//     case.
//  2. Dotted refs (e.g. "ge-0/0/0.80", "reth0.50", "gr-0/0/0.0",
//     "irb.0", "st0.0"):
//     a. st<N>.<M>: resolve the xfrmi device from the AUTHORED
//     bind-interface via SecureTunnelUnitNetdev (#5619). A bare
//     `bind-interface st0` and an explicit `bind-interface st0.0`
//     derive the same if_id under DIFFERENT device names, while
//     the unit ref is `st0.0` either way — so it is read from the
//     config, NOT reconstructed from the ref. Falls back to the
//     verbatim ref only when no VPN binds the unit, since no xfrmi
//     device exists for it then. That whole rule lives in
//     SecureTunnelUnitNetdev, which snapshotLinuxName and
//     junosHostLinuxName also call — one resolver, not three
//     copies asserted to agree (#6691).
//     b. IRB: look up via IRBToBridge(cfg.BridgeDomains) and return
//     the bridge device name (no suffix).
//     c. Tunnel: if TunnelNameMap[ref] is set, return that name
//     verbatim (covers gr-0/0/0.0 → gr-0-0-0 and
//     gr-0/0/0.1 → gr-0-0-0u1).
//     d. Otherwise look up cfg.Interfaces.Interfaces[base].Units[unit]:
//     - If unit has tunnel.Name set, return that.
//     - If unit.VlanID > 0, return
//     LinuxIfName(ResolveReth(base)) + "." + VlanID.
//     - If unit.Number == 0, return
//     LinuxIfName(ResolveReth(base)) (unit-0 collapse).
//     - Else return LinuxIfName(ResolveReth(base)) + "." + unit.Number.
//     e. Fallback: LinuxIfName(ResolveReth(ref)) — preserves suffix.
//
// NOTE: Keep in sync with snapshotLinuxName in
// pkg/dataplane/userspace/interfaces.go and resolveJunosIfName in
// pkg/daemon/daemon_dhcp.go. Migration to centralize all callers was
// tracked as a follow-up to #1565, which is CLOSED, so keeping them in step
// is a live obligation on anyone editing any of the three rather than
// something a pending migration is about to remove.
//
// #8994 MEASURED that obligation instead of restating it, and it is now
// enforced rather than requested: TestResolverAgreement8994 asserts these
// resolvers name the SAME kernel device for every declared interface in a
// corpus that includes the case they used to disagree on. Two of the three
// turned out not to be independent derivations at all — resolveJunosIfName
// is literally LinuxIfName(ResolveReth(x)), and a tunnel unit's name comes
// from TunnelNameMap on both sides — so what the guard actually protects is
// the arms below against snapshotLinuxName's VLAN/reth/unit-0 rules.
// resolveBareKernelIfName is the BARE-ref arm of ResolveKernelIfName, split out
// so callers that already know structurally that they hold an interface name —
// not a unit ref — can reach it without round-tripping through the dotted
// parse (#6861 F1/F3).
//
// The distinction is load-bearing, not cosmetic. ResolveKernelIfName decides
// which arm to take by splitting the string on ".", so an interface whose
// AUTHORED name contains a dot (`ip-0/0/0.0` is a legal interface name in the
// config tree even though Junos would read it as a unit ref) takes the dotted
// arm and can consume an unrelated unit's TunnelNameMap entry. The dataplane's
// snapshotLinuxName has no such ambiguity because it branches on `unit != nil`
// — a structural fact. A caller holding the structure must be able to say so.
func (c *Config) resolveBareKernelIfName(name string) string {
	if strings.HasPrefix(name, "reth") {
		return LinuxIfName(c.ResolveReth(name))
	}
	return LinuxIfName(name)
}

// ResolveKernelIfName resolves a Junos interface reference to the Linux device
// name. It builds the tunnel-name map itself; a caller resolving MANY refs
// should hoist that map once and use resolveKernelIfNameWith instead (#8862).
func (c *Config) ResolveKernelIfName(ref string) string {
	return c.resolveKernelIfNameWith(ref, tunnelNameMapFn(c))
}

// resolveKernelIfNameWith is ResolveKernelIfName with the tunnel-name map
// supplied by the caller.
//
// TunnelNameMap walks every interface and every unit, so building it per
// reference makes a per-interface loop quadratic: #8854 fixed one such loop and
// this is the same shape at the two sites that dominated the profile
// afterwards. The map is a pure function of c.Interfaces and does not change
// during validation — verified by instrumenting TunnelNameMap to compare its
// rendering against the first call for the same *Config across pkg/config and
// pkg/configstore, with a positive control that mutated a unit tunnel mid-walk
// and did fire.
//
// The map is a REQUIRED parameter rather than an optional nil: TunnelNameMap
// returns a non-nil EMPTY map for a config with no tunnels, so nil would be a
// sentinel that collides with a legitimate value.
func (c *Config) resolveKernelIfNameWith(ref string, tunMap map[string]string) string {
	// #8994: A REF THAT NAMES A DECLARED INTERFACE IS THAT INTERFACE, even when
	// it contains a dot. This arm is placed FIRST because everything below
	// decides what the ref MEANS by parsing it, and an explicit declaration
	// outranks a parse -- the same precedence the secure-tunnel arm already
	// applies when an authored `bind-interface` outranks the tunnel-name map.
	//
	// Without it, `ResolveKernelIfName` split on "." and read a declared
	// interface named `gr-0/0/0.0` as unit 0 of `gr-0/0/0`, so when that unit
	// carried a tunnel the dotted arm returned the TUNNEL's device
	// (`gr-0-0-0`) while the dataplane's snapshotLinuxName returned the
	// interface's own (`gr-0-0-0.0`). Two subsystems named one configured
	// interface differently, and the config COMPILES, so it is operator-
	// reachable. Measured in TestResolverAgreement8994, which now expects an
	// EMPTY divergence set.
	//
	// The blast radius is narrower than this function's 15 callers suggest: a
	// ref with no dot already took the bare arm, and a genuine unit ref
	// (`ge-0/0/0.0` where only `ge-0/0/0` is declared) is not a key in
	// Interfaces, so neither changes. Only a config that DECLARES a dotted
	// interface name behaves differently, which is the defect case itself.
	if ifc, ok := c.Interfaces.Interfaces[ref]; ok && ifc != nil {
		return c.resolveBareKernelIfName(ref)
	}
	parts := strings.SplitN(ref, ".", 2)
	base := parts[0]

	// Bare refs.
	if len(parts) == 1 {
		return c.resolveBareKernelIfName(base)
	}

	// XFRM (st<N>): the kernel device is the AUTHORED bind-interface, which
	// is not always the ref. A bare `bind-interface st0` and an explicit
	// `bind-interface st0.0` derive the same if_id under DIFFERENT device
	// names ("st0" vs "st0.0", pkg/routing/xfrm.go), and the unit ref is
	// `st0.0` either way — so resolve it from the config rather than
	// reconstructing it from the ref (#5619). Falls back to the verbatim ref
	// when no VPN binds this unit: no xfrmi device exists for it then, and
	// the verbatim ref is what this returned before.
	//
	// The whole rule lives in SecureTunnelUnitNetdev (xfrmi.go) so
	// snapshotLinuxName and junosHostLinuxName apply the IDENTICAL one
	// instead of hand-copied instances of it (#6691).
	//
	// The verbatim arm below is THIS function's own fallback, not part of the
	// shared rule: when no VPN binds the unit, SecureTunnelUnitNetdev declines
	// (ok=false) so the dataplane resolvers can name the ordinary interface —
	// the NIC, the VLAN device, the GRE device — while this one keeps
	// returning the ref, which is what it returned before #5619. The gate is
	// IsSecureTunnelIfName rather than the unbounded `Atoi(base[2:])` this
	// replaced, so an out-of-range `st65536.3` now falls through to the
	// ordinary unit resolution and agrees with the snapshot (#6691): a name
	// the xfrmi constructor rejects is an ordinary interface here too.
	if dev, ok := c.SecureTunnelUnitNetdev(ref); ok {
		return dev
	}
	if IsSecureTunnelIfName(base) {
		return LinuxIfName(ref)
	}

	// IRB.
	if base == "irb" {
		if bridges := IRBToBridge(c.BridgeDomains); bridges != nil {
			if bridge, ok := bridges[ref]; ok && bridge != "" {
				return bridge
			}
		}
		// Fall through if no bridge mapping; fallback handles it.
	}

	// Per-unit tunnel by ref.
	if tunMap != nil {
		if linuxName, ok := tunMap[ref]; ok && linuxName != "" {
			return linuxName
		}
	}

	// Bail to fallback if the suffix isn't numeric (malformed ref
	// like "ge-0/0/0.foo" must not silently map to unit 0).
	unitNum, err := strconv.Atoi(parts[1])
	if err != nil {
		return LinuxIfName(c.ResolveReth(ref))
	}
	if c.Interfaces.Interfaces == nil {
		return LinuxIfName(c.ResolveReth(ref))
	}
	if ifc, ok := c.Interfaces.Interfaces[base]; ok && ifc != nil {
		if unit, ok := ifc.Units[unitNum]; ok && unit != nil {
			if unit.Tunnel != nil && unit.Tunnel.Name != "" {
				return unit.Tunnel.Name
			}
			kernelBase := LinuxIfName(c.ResolveReth(base))
			if unit.VlanID > 0 {
				return fmt.Sprintf("%s.%d", kernelBase, unit.VlanID)
			}
			if unit.Number == 0 {
				return kernelBase
			}
			return fmt.Sprintf("%s.%d", kernelBase, unit.Number)
		}
	}

	// Fallback for refs not modeled in cfg.Interfaces.Interfaces:
	// preserve the suffix and translate slashes only.
	return LinuxIfName(c.ResolveReth(ref))
}

// DHCPLeaseKey returns the lease-lookup key that pkg/dhcp.Manager
// keys leases by for the given config-level interface ref and unit
// number. Mirrors the construction in
// pkg/daemon/daemon_dhcp.go:56-95:
//
//	key = LinuxIfName(configRef) + ("." + strconv(unit.VlanID)) when > 0
//
// configRef is the CONFIG-LEVEL name (e.g. "reth0"), not the resolved
// physical member — the daemon's DHCP Start() is invoked with the
// config-level name.
//
// Returns ("", false) when the unit doesn't exist in cfg.
func (c *Config) DHCPLeaseKey(configRef string, unitNum int) (string, bool) {
	configRef = strings.SplitN(configRef, ".", 2)[0]
	if c.Interfaces.Interfaces == nil {
		return "", false
	}
	ifc, ok := c.Interfaces.Interfaces[configRef]
	if !ok || ifc == nil {
		return "", false
	}
	unit, ok := ifc.Units[unitNum]
	if !ok || unit == nil {
		return "", false
	}
	key := LinuxIfName(configRef)
	if unit.VlanID > 0 {
		key = key + "." + strconv.Itoa(unit.VlanID)
	}
	return key, true
}

// Config is the top-level typed configuration, compiled from the AST.
type Config struct {
	Security          SecurityConfig
	Interfaces        InterfacesConfig
	Applications      ApplicationsConfig
	RoutingOptions    RoutingOptionsConfig
	Protocols         ProtocolsConfig
	RoutingInstances  []*RoutingInstanceConfig
	Firewall          FirewallConfig
	ClassOfService    *ClassOfServiceConfig
	Services          ServicesConfig
	ForwardingOptions ForwardingOptionsConfig
	System            SystemConfig
	PolicyOptions     PolicyOptionsConfig
	Schedulers        map[string]*SchedulerConfig
	Chassis           ChassisConfig
	EventOptions      []*EventPolicy
	BridgeDomains     []*BridgeDomainConfig
	Warnings          []string // non-fatal validation warnings

	// LenientNATTerminalActionRules records every NAT rule the TOLERANT path
	// admitted despite validateNATTerminalActionCardinalityStrict rejecting it
	// (#7640). It is populated ONLY on that path — the strict path returns the
	// error instead, so a non-empty slice means exactly "this config carries a
	// rule a commit would have refused".
	//
	// It exists because the warning alone has nowhere to go on the paths where
	// such a rule survives. cfg.Warnings reaches an operator through the commit
	// RESPONSE (pkg/api/config.go, pkg/grpcapi/server_config.go) and an
	// apply-time log line (pkg/daemon/daemon_apply.go) — and a tolerant LOAD
	// (boot, peer-sync, rollback) has no commit response. On exactly those
	// paths the only trace was one startup log line that nothing alerts on.
	//
	// Rebuilt per compile by construction: every CompileConfig produces a fresh
	// *Config, so fixing the config clears it without a separate clear path.
	// That matters — an alert that keeps firing after the fix gets muted, and a
	// muted alert is how the next real one is missed.
	//
	// Consumers: the xpf_nat_rules_lenient_terminal_action gauge (pkg/api) and
	// the per-rule annotation in `show security nat {source,destination} rule
	// detail` (pkg/natshow). Both read THIS field rather than re-deriving, so a
	// count, an annotation and the warning can never disagree about which rules
	// are affected.
	LenientNATTerminalActionRules []LenientNATTerminalActionRule
}

// LenientNATTerminalActionRule identifies one NAT rule admitted by the tolerant
// path despite carrying the wrong number of terminal actions (#7640).
type LenientNATTerminalActionRule struct {
	// Kind is "source" or "destination".
	Kind string
	// RuleSet and Rule are the authored names, so an operator can go straight
	// to the offending stanza.
	RuleSet string
	Rule    string
	// Actions is the terminal-action count the gate objected to: 0 (actionless
	// — the rule installs no translation and, for source NAT, does not stop
	// rule evaluation) or >= 2 (contradictory — all but one action is
	// discarded by a fixed precedence the operator did not write).
	Actions int
}

// String renders the rule identity for the gauge hook and the operator-facing
// annotation. Stable and greppable: `source rule-set RS rule R (0 actions)`.
func (r LenientNATTerminalActionRule) String() string {
	return fmt.Sprintf("%s rule-set %s rule %s (%d actions)",
		r.Kind, r.RuleSet, r.Rule, r.Actions)
}

// IRBToBridge returns a mapping of IRB interface reference (e.g. "irb.0") to
// bridge device name (e.g. "br-bd0") for all bridge domains with a routing-interface.
func IRBToBridge(bds []*BridgeDomainConfig) map[string]string {
	m := make(map[string]string)
	for _, bd := range bds {
		if bd.RoutingInterface != "" {
			m[bd.RoutingInterface] = "br-" + bd.Name
		}
	}
	return m
}

// TunnelNameMap returns a mapping from Junos interface reference (e.g. "gr-0/0/0.0")
// to the Linux tunnel interface name. A unit WITH its own per-unit
// tunnel stanza always maps to its compiler-assigned TunnelConfig.Name
// (unit 0 = base Linux name, unit N>0 = "uN" suffix,
// compiler_interfaces.go) — even when an interface-level tunnel
// coexists, because the compiler creates BOTH devices and mapping the
// unit ref to the base name would shadow the real uN device (#1910 r1
// Codex/AGY convergent High).
//
// The compiler no longer assigns a "uN" name in ONE case: a unit that stays
// on an interface-level `tunnel mode wireguard` (#6941,
// unitSharesInterfaceWireguardDevice). There is no real uN device to shadow
// there — that interface has exactly ONE emitted endpoint (#1910), so at most
// one device can carry it, and the uN device could only ever hold the unit's
// addresses with no endpoint behind them. Nothing changes here for that case
// because this function reads TunnelConfig.Name and the compiler now sets it
// to the base name; a unit that OVERRIDES the mode still gets its own uN
// device and is unaffected. Units WITHOUT their own tunnel stanza
// under an interface-level tunnel share the interface device; the
// interface-level gate admits WireGuard despite its empty GRE-style
// `source` (the #1736 collectAppliedTunnels twin — the persistent wgN
// TUN is one shared device, so wg0.1 must resolve to wg0, not fall
// through to a literal ".1" name).
func (c *Config) TunnelNameMap() map[string]string {
	m := make(map[string]string)
	for ifName, ifc := range c.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		ifaceTunnel := ifc.Tunnel != nil &&
			(ifc.Tunnel.Source != "" || ifc.Tunnel.Mode == "wireguard")
		baseName := LinuxIfName(ifName)
		for unitNum, unit := range ifc.Units {
			ref := ifName + "." + strconv.Itoa(unitNum)
			if unit != nil && unit.Tunnel != nil && unit.Tunnel.Name != "" {
				// Per-unit tunnel: its own Linux device, always.
				m[ref] = unit.Tunnel.Name
				continue
			}
			if ifaceTunnel {
				// Interface-level tunnel: unit shares the device.
				m[ref] = baseName
			}
		}
	}
	return m
}

// tunnelNameMapFn is the seam through which the hoisting call sites reach
// TunnelNameMap (#8862). Production always holds the method; the guard swaps it
// to COUNT builds, because the property being protected is "built a bounded
// number of times per validation, not once per interface or unit" and no
// correctness assertion can observe that. Same idiom as
// resolveInterfaceHostInboundFn (#8854) and pkg/daemon's deriveKernelNameFn.
var tunnelNameMapFn = (*Config).TunnelNameMap
