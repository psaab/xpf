package config

import (
	"errors"
	"fmt"
	"sort"
)

// ipipTunnelSite is one emitted tunnel endpoint whose mode is ipip, carrying
// the operator-facing label for it.
type ipipTunnelSite struct {
	label string
}

// effectiveIpipTunnelSites returns every tunnel ENDPOINT the dataplane would
// actually emit whose mode is ipip, in the emitter's own order.
//
// It delegates to EmitTunnelEndpointNames rather than walking the compiled
// records itself. That is the point (#4785 re-gate B2): the emitter is already
// the single source of truth for "which tunnel endpoints reach the dataplane
// snapshot", it is what buildTunnelEndpointSnapshots consumes, and it is what
// the sibling commit-time gate validateTunnelEndpointIDCollisionAST is built
// on — so this gate now sits behind the same drift guarantee instead of
// hand-rolling a second model of a question the codebase already answers.
//
// Three defects came from that hand-rolled model and are closed by deleting it:
//
//   - A unit with NO tunnel stanza still inherits the interface-level tunnel —
//     which the emitter does, and says so in a comment. The old walk skipped
//     exactly those units (`unit.Tunnel == nil { continue }`), so
//     `ip-0/0/0 tunnel src/dst` + `unit 0 tunnel mode gre` + a bare `unit 2`
//     let unit 0's GRE record shadow the interface record on the shared device
//     key while unit 2 — which emits ipip — was never visited. That config
//     COMMITTED with the alarm surface silent, having been correctly REJECTED
//     one commit earlier. An over-rejection fix that becomes an
//     under-rejection is worse than the bug it replaced.
//   - The old model named routing.tunnelManager as the authority. Under the
//     userspace dataplane — the only supported runtime — collectAppliedTunnels
//     sets AnchorOnly and creates a mode-INDEPENDENT Tuntap anchor. What
//     decides gre_decap_index membership versus the TunnelKind::Unknown drop
//     arm is the EMITTED endpoint's mode, which is this function's input.
//   - The emitter applies the same source/destination screen the snapshot
//     builder does, so an endpoint reported here really is emitted. A `tunnel
//     destination` with no source emits nothing and is no longer reported as a
//     dead tunnel.
//
// Ordering is the emitter's — interfaces sorted by name, units by number — so
// the first reported strict error is stable across runs and identical on both
// HA nodes.
func effectiveIpipTunnelSites(cfg *Config) []ipipTunnelSite {
	var sites []ipipTunnelSite
	for _, ep := range EmitTunnelEndpointNames(cfg) {
		if ep.Tunnel != nil && ep.Tunnel.Mode == TunnelModeIPIP {
			sites = append(sites, ipipTunnelSite{label: fmt.Sprintf("%q", ep.Name)})
		}
	}
	return sites
}

// emittedTunnelDeviceNames returns the set of Linux DEVICE names the emitted
// tunnel endpoints bind to at runtime.
//
// Runtime identity for a tunnel is the device name, not the *TunnelConfig
// pointer: routing keys its desired set by TunnelConfig.Name
// (pkg/routing/tunnel.go), so two records sharing a name are ONE kernel device,
// and the dataplane resolves an emitted endpoint ref to a device through
// snapshotLinuxName -> cfg.TunnelNameMap() (pkg/dataplane/userspace/interfaces.go),
// which for a unit with its own tunnel stanza is that UNIT's device even when
// the emitted endpoint carries the interface-level object.
//
// Resolution is STRUCTURAL — keyed on the (interface, unit) pair the emitter
// emitted from — not on parsing the emitted ref string (#6861 F1/F3). Two
// defects came from parsing the string, both reproduced before this fix:
//
//   - `LinuxIfName(ep.Name)` was NOT what snapshotLinuxName does for a bare
//     interface ref. Its no-unit arm resolves a `reth*` name through ResolveReth
//     first, so an emitted `reth0` endpoint was recorded live under "reth0"
//     when the snapshot actually binds it to the physical member "ge-0-0-0".
//     The harm is a FALSE POSITIVE on a different record: `ge-0/0/0` (reth0's
//     member) carrying its own unemitted ipip stanza has anchor device
//     "ge-0-0-0" — the very device reth0's endpoint runs on — so with the wrong
//     derivation that device is absent from the live set and the advisory calls
//     a live, traffic-carrying device dead. That is this gate's own defect class
//     surviving in its fallback arm.
//   - Looking the ref up in TunnelNameMap first let an interface whose AUTHORED
//     name contains a dot consume an unrelated unit's entry: `ip-0/0/0.0` is a
//     legal interface name, and both it and unit 0 of `ip-0/0/0` are emitted
//     under the identical ref "ip-0/0/0.0". Production collides on that too
//     (buildTunnelEndpointSnapshots keys ifaceByName by the same string), so
//     which device is live is genuinely undecidable here — and marking BOTH
//     live is the correct failure mode for an ADVISORY, whose harm is a false
//     "this device is dead" aimed at live config.
//
// The device derivation itself is still delegated: resolveBareKernelIfName and
// ResolveKernelIfName (pkg/config/types.go) are the sanctioned config-side twin
// of snapshotLinuxName, carrying a drift-guard test in the userspace package.
// What this function owns is only the structural walk — which (interface, unit)
// pair each emitted ref came from — mirroring how buildInterfaceSnapshots names
// its rows.
func emittedTunnelDeviceNames(cfg *Config) map[string]bool {
	if cfg == nil {
		return nil
	}
	// The ID-COLLISION DROP, mirrored from the builder. Being emitted is
	// necessary but NOT sufficient for an endpoint to reach the snapshot:
	// buildTunnelEndpointSnapshots (pkg/dataplane/userspace/tunnels.go) hashes
	// each ref to a StableTunnelEndpointID and RETURNS — appending nothing —
	// when that id is already taken, so the later-sorting collider is dropped.
	// Counting it as live suppressed the advisory for an anchor whose endpoint
	// the runtime will never create, which is the exact inverse of this
	// advisory's job: the operator gets silence about a dead device (#6861
	// re-gate B1).
	//
	// Measured on the frozen pair pinned by tunnelid_test.go (StableTunnelEndpointID
	// "wg0" == "wg34524.0" == 17799): complete GRE `wg0` plus interface-level
	// IPIP `wg34524` overridden by a complete unit-0 GRE emits both refs, the
	// runtime keeps `wg0` and drops `wg34524.0`, and before this loop
	// live["wg34524"] was true — so the `wg34524` device the IPIP anchor
	// creates had no endpoint and no alarm.
	//
	// The iteration order is the builder's: EmitTunnelEndpointNames is the SSOT
	// both walk (sorted interface names, sorted unit numbers), and the builder
	// feeds addEndpoint straight from it, so "first wins" means the same ref
	// here as there.
	//
	// WHAT THIS STILL DOES NOT MODEL, stated rather than implied: addEndpoint
	// also skips a ref whose interface is absent from the runtime
	// InterfaceSnapshot rows (its `ifaceByName` lookup), and this function has
	// no ifindex knowledge — it never did. So a collision whose WINNER has no
	// kernel device would, at runtime, leave the loser installed, and this loop
	// drops the loser anyway. That conjunction (a missing kernel device AND an
	// id collision) is the one shape where the drop can produce a false "this
	// device is dead"; within the model this function has always used — every
	// emitted ref is present — the drop is exactly the builder's rule.
	emittedRefs := make(map[string]bool)
	usedIDs := make(map[uint16]string)
	for _, ep := range EmitTunnelEndpointNames(cfg) {
		id := StableTunnelEndpointID(ep.Name)
		if _, taken := usedIDs[id]; taken {
			continue
		}
		usedIDs[id] = ep.Name
		emittedRefs[ep.Name] = true
	}
	refToDevice := cfg.TunnelNameMap()

	out := make(map[string]bool)
	for name, iface := range cfg.Interfaces.Interfaces {
		if iface == nil {
			continue
		}
		// The bare interface row. EmitTunnelEndpointNames publishes this ref
		// only for an interface-level tunnel on an interface with no units.
		if emittedRefs[name] {
			out[cfg.resolveBareKernelIfName(name)] = true
		}
		for unitNum, unit := range iface.Units {
			if unit == nil {
				continue
			}
			// Synthesized from the STRUCTURE, so this is unambiguously the
			// unit arm even when `name` itself contains a dot.
			ref := fmt.Sprintf("%s.%d", name, unitNum)
			if !emittedRefs[ref] {
				continue
			}
			// TunnelNameMap FIRST, matching snapshotLinuxName's unit arm
			// ordering. ResolveKernelIfName is the right derivation but not in
			// the right ORDER for this question: it answers XFRM (`st<N>`) and
			// IRB refs BEFORE consulting the tunnel map, while snapshotLinuxName
			// — which is what actually fills InterfaceSnapshot.LinuxName —
			// consults the map first and has no XFRM or IRB arm at all (its own
			// doc records the IRB delta as intentional). Deferring to
			// ResolveKernelIfName unconditionally therefore mis-derived exactly
			// the refs where the two disagree: `st0.1` resolved to "st0.1"
			// instead of the unit's "st0u1" device, and `irb.0` under a bridge
			// domain to "br-bd0" instead of "irb". Both put a device the
			// dataplane never binds into the live set, and left the real one
			// out.
			if device, ok := refToDevice[ref]; ok && device != "" {
				out[device] = true
				continue
			}
			out[cfg.ResolveKernelIfName(ref)] = true
		}
	}
	return out
}

// ipipUnimplementedText is the shared operator-facing explanation, used by BOTH
// the strict commit gate and the ValidateConfig alarm advisory so the two can
// never drift.
//
// The wording says nothing about kernel devices: because the caller reports
// only EMITTED endpoints, "this endpoint reaches the dataplane snapshot" is a
// measured fact, unlike the earlier indicative claim that a tunnel "is created"
// — which was false for a stanza the emitter screens out (#4785 re-gate N4).
func ipipUnimplementedText(where string) string {
	return fmt.Sprintf(
		"tunnel endpoint %s has mode ipip: IPIP (ip-in-ip) is NOT implemented in the "+
			"userspace dataplane (#4785) — this endpoint reaches the dataplane snapshot "+
			"but carries NO traffic in either direction (an inbound proto-4 frame has no "+
			"decap stage and is dropped; an egress inner packet classifies as an unknown "+
			"tunnel mode and is dropped). Use `mode gre` or `mode wireguard` for a working "+
			"tunnel. Note an `ip-*` interface defaults to `mode ipip` even when the mode is "+
			"not written explicitly, and a unit with no `tunnel` stanza of its own inherits "+
			"the interface-level tunnel; a `gr-*` interface defaults to `mode gre`.",
		where)
}

// validateIpipTunnelDeadWarning is the ValidateConfig advisory (#4788, retained
// through #4785 half 1).
//
// The strict gate below covers a NEW commit. This covers the config ALREADY ON
// DISK: a generation committed by an older build loads leniently (a warning, not
// a reject, per #1960), and the alarm surfaces — `show system alarms` in the CLI
// and gRPC, plus the two security-alarm views — RECOMPUTE ValidateConfig from
// the active config rather than reading cfg.Warnings. Without this the operator
// gets a one-time apply log and a standing "No alarms currently active" on a box
// whose tunnel carries nothing.
//
// It reports EVERY dead endpoint, not just the first: an operator who fixes one
// should not discover the next only on the following commit (#4785 re-gate N5).
func validateIpipTunnelDeadWarning(cfg *Config) []string {
	var warnings []string
	for _, s := range effectiveIpipTunnelSites(cfg) {
		warnings = append(warnings, ipipUnimplementedText(s.label))
	}
	return append(warnings, ipipAnchorOnlyWarnings(cfg)...)
}

// ipipAnchorOnlyWarnings reports an ipip tunnel record that creates a kernel
// ANCHOR but has no emitted endpoint (#4785 re-gate follow-up).
//
// The strict gate deliberately keys on emitted endpoints only, and that is the
// right property for it — but "no emitted endpoint" is not the same as "nothing
// exists on the box". collectAppliedTunnels (pkg/daemon/daemon_run_routehelpers.go)
// hands records to the routing manager, which creates a mode-INDEPENDENT Tuntap
// anchor, and its two screens are NOT the emitter's:
//
//   - INTERFACE level: appended whenever `Source != ""` (or the mode is
//     wireguard). So an interface record with a source but no destination —
//     which the emitter suppresses — still gets an anchor.
//   - UNIT level: appended for EVERY non-nil `unit.Tunnel`, with no
//     completeness screen at all. A unit carrying only a destination emits
//     nothing and still gets an anchor.
//
// Both shapes must be walked. The unit half is not optional and not new: the
// #4788 advisory this gate replaced walked units, and dropping it meant
//
//	set interfaces ip-0/0/0 unit 5 tunnel destination 10.0.0.2
//
// committed with NEITHER the strict rejection (nothing is emitted, so the gate
// is silent by design) NOR any standing alarm, while still creating a visible
// `ip-0-0-0u5` device that carries nothing. That directly contradicts the
// reason the advisory is registered at all.
//
// This is an ADVISORY, not a rejection, deliberately. The anchor carries no
// traffic but breaks nothing, the operator may well have meant the unit-level
// tunnel, and blocking the commit would re-import the over-rejection this gate
// has already swung through twice. An alarm names it; a commit does not stop
// for it.
//
// The predicate is ASYMMETRIC between the two sites, and both shapes are
// measured rather than assumed (#6861 r5):
//
//	interface: !emitted[t] && !live[t.Name]
//	unit:                    !live[unit.Tunnel.Name]
//
// The interface site's conjunction is deliberate — do not "simplify" it to one
// clause. Neither clause subsumes the other, and each was at one point the whole
// predicate and wrong on its own:
//
//   - `emitted[t]` is POINTER identity: "is this record the object the emitter
//     published". It is the advisory's stated contract — a record with no
//     emitted endpoint. Alone it is wrong, because several unemitted records
//     SHARE a device with an emitted one (below), and it declared those live
//     devices dead.
//   - `live[t.Name]` is DEVICE identity: "is this record's kernel device claimed
//     by something the emitter published". Alone it is also wrong: an emitted
//     record whose own device name differs from where its endpoint binds —
//     `reth0`, whose endpoint resolves to the physical member `ge-0-0-0` — gets
//     reported as a dead anchor. That record is already covered, correctly, by
//     the dead-endpoint advisory (ipipUnimplementedText), so this would be a
//     SECOND diagnosis of one record, with a structurally false cause ("every
//     unit overrides it" on an interface that has no units) pointing the
//     operator at the wrong stanza.
//
// The UNIT site carries only the device clause, because the pointer clause there
// is provably redundant rather than merely unmeasured: TunnelNameMap keys a
// unit's device BY unit.Tunnel.Name, and compiler_interfaces.go always assigns a
// non-empty Name at construction, so an emitted unit record's device is its own
// name and live[] necessarily holds it. Dropping it reds nothing; dropping the
// interface one reds TestIpipEmittedRecordIsNeverAlsoAnAnchor_6861.
//
// WHY POINTER KEYING AND NOT `emittedName[t.Name]` — a separate question from
// whether the clause exists at all, and one the reth case above does NOT answer.
// In that case the emitted record IS `t`, so a name-keyed set suppresses it just
// as well; TestIpipEmittedRecordIsNeverAlsoAnAnchor_6861 stays green under the
// re-keying and therefore proves only that SOME emitted-check is present.
//
// The keying is decided by the one shape where an emitted record is NOT `t` yet
// shares `t.Name`, with that name absent from live[]. The shapes that can put an
// interface-site candidate on a SHARED, NON-LIVE Name are two — and that
// qualified statement is the exhaustive one (#6861 re-gate C4). An earlier
// revision claimed Name sharing itself had only two sources, which is false: an
// interface authored `gr-0/0/0u1` shares a Name with `gr-0/0/0 unit 1`, a third
// and COMMITTABLE shape. It cannot be turned into a discriminator here (the unit
// ref puts that very name in live[], so the device clause decides first), so the
// conclusion is unchanged; the underlying authored-vs-derived name collision is
// filed separately as #6964. The two that do decide the keying:
//
// An interface-level record and its own unit 0 — where TunnelNameMap
// puts that very name in live[], so the device clause decides first and the
// keying never matters — or two DIFFERENT interface keys canonicalizing to
// one Linux name, since LinuxIfName only replaces '/' with '-' (`gr-0/0-0` and
// `gr-0/0/0` both give `gr-0-0-0`). Pair that with interface-level WireGuard
// whose lowest unit is > 0, where the emitter publishes the INTERFACE pointer at
// ref `X.u` (#1910) while TunnelNameMap resolves `X.u` to the UNIT device
// `X u<n>`, and the name is emitted while the device is not live. Name keying
// then drops a real dead ipip anchor on the strength of an unrelated
// interface's name. Bound by
// TestIpipAnchorEmittedClauseIsPointerKeyedNotNameKeyed_6861, which reds on
// exactly that re-keying.
//
// SCOPE of that difference, because it bounds the claim: the LITERAL fixture is
// rejected by a strict LOCAL commit — the duplicate Linux-device-name gate
// (compiler_validate_strict_ifname_collision.go) fires on the two interface
// keys.
//
// That bound is the LOCAL STRICT EFFECTIVE VIEW and no wider. An earlier
// revision said "on anything committable the two keyings are equivalent", which
// is categorical and false (#6861 re-gate, Codex 4): put the collision fixture
// only in node1's `${node}` group and keep node0 clean. compileTreeStrict
// strictly compiles node0 ONLY, the peer compile downgrades the duplicate-name
// gate, and the peer registry carries just the SNAT and emitted-IPIP subjects —
// and this candidate is source-only, so the emitter drops it before the IPIP
// subject ever sees it. Node0 commits; node1 then activates the exact shape
// through SyncApply.
//
// What pointer keying protects is therefore the TOLERANT surface (#1960):
// configstore Load/SyncApply lenient-compiles a config the local strict commit
// would refuse, and `show system alarms` — the actual rendering command, not
// plain `show system` — renders ValidateConfig's warnings for whatever is
// active. Kept because it is correct on its own terms rather than by borrowing
// another gate's guarantee.
//
// The orphan `reth0` device in that second case is real, but it is not this
// gate's subject: the same orphan appears with `mode gre`, where #4785 is
// deliberately silent, so #4785 is not its cause. It is the routing-vs-dataplane
// name divergence tracked in #6941 (routing keys its desired set by
// TunnelConfig.Name -- pkg/routing/tunnel.go `desired[tc.Name]`; the dataplane
// binds via snapshotLinuxName, pkg/dataplane/userspace/interfaces.go). #6941 is
// CLOSED and both halves still key differently, so #8995 tracks the residual
// (and #8994 the general case: three resolvers kept in step by a NOTE).
//
// Why the DEVICE clause has to exist at all: the advisory's claim is about a
// Linux device — "an interface an operator can see that carries no traffic" —
// and these records share one device with an emitted one:
//
//   - GRE/IPIP UNIT 0. compiler_interfaces.go gives unit 0's per-unit tunnel
//     the BASE Linux name, identical to the interface-level record's, and
//     routing keys its desired set by that name (pkg/routing/tunnel.go), so
//     the two records are one device. With `ip-0/0/0 tunnel source/destination`
//     plus `unit 0 tunnel mode gre`, the emitter publishes the unit's GRE
//     pointer (#5635) and the interface pointer is unemitted — but the device
//     it names is the one carrying the working GRE tunnel. The pointer test
//     declared that live device dead.
//   - A UNIT under an interface-level WireGuard stanza. The emitter publishes
//     ONE endpoint keyed by the lowest unit carrying the INTERFACE-level
//     pointer (#1910), while TunnelNameMap resolves that same unit ref to the
//     UNIT's own device — which is what snapshotLinuxName, and therefore the
//     tunnel-endpoint snapshot, binds the WireGuard TUN to. The unit's pointer
//     is unemitted; its device is live WireGuard infrastructure.
//
// The name comes from cfg.TunnelNameMap() — the same map
// pkg/dataplane/userspace/interfaces.go:snapshotLinuxName consults to fill
// InterfaceSnapshot.LinuxName — so there is ONE source of truth for the device
// name and the advisory cannot drift from what the dataplane opens.
func ipipAnchorOnlyWarnings(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	live := emittedTunnelDeviceNames(cfg)
	emitted := make(map[*TunnelConfig]bool)
	for _, ep := range EmitTunnelEndpointNames(cfg) {
		emitted[ep.Tunnel] = true
	}

	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)

	var out []string
	for _, name := range names {
		iface := cfg.Interfaces.Interfaces[name]
		if iface == nil {
			continue
		}
		if t := iface.Tunnel; t != nil && t.Mode == TunnelModeIPIP && !emitted[t] && !live[t.Name] &&
			// The interface-level anchor screen in collectAppliedTunnels. A
			// record that fails it creates nothing, so there is nothing to warn
			// about.
			t.Source != "" {
			out = append(out, ipipAnchorOnlyText(
				fmt.Sprintf("interfaces %q", name), t, false, false))
		}

		unitNums := make([]int, 0, len(iface.Units))
		for u := range iface.Units {
			unitNums = append(unitNums, u)
		}
		sort.Ints(unitNums)
		for _, u := range unitNums {
			unit := iface.Units[u]
			if unit == nil || unit.Tunnel == nil {
				continue
			}
			// No source screen here, on purpose: collectAppliedTunnels has none
			// for units, so ANY non-nil unit tunnel becomes an anchor.
			// No emitted-POINTER clause here, unlike the interface site above:
			// it is provably redundant (#6861 r5). TunnelNameMap keys a unit's
			// device BY unit.Tunnel.Name, and the compiler always assigns a
			// non-empty Name at construction, so an emitted unit record's
			// device IS its own name and live[] already holds it. The interface
			// site has no such identity — snapshotLinuxName resolves a bare
			// `reth*` through ResolveReth, so an emitted reth0 record's device
			// is the physical member and NOT t.Name.
			//
			// What was measured, stated exactly: DELETING the clause reds
			// nothing here and reds
			// TestIpipEmittedRecordIsNeverAlsoAnAnchor_6861 at the interface
			// site. That is a presence measurement and nothing more — it does
			// not speak to how the interface site's set is KEYED, because
			// deleting a check is caught by any test that the check exists.
			// The pointer-vs-name keying is a separate claim with its own
			// fixture and its own mutation; see the block above
			// `ipipAnchorOnlyWarnings` and
			// TestIpipAnchorEmittedClauseIsPointerKeyedNotNameKeyed_6861.
			if unit.Tunnel.Mode != TunnelModeIPIP || live[unit.Tunnel.Name] {
				continue
			}
			out = append(out, ipipAnchorOnlyText(
				fmt.Sprintf("interfaces %q unit %d", name, u), unit.Tunnel, true,
				iface.Tunnel != nil && iface.Tunnel.Mode == TunnelModeWireGuard))
		}
	}
	return out
}

// ipipInterfaceStanzaRemovalAdvice is the ONLY wording allowed to suggest
// removing an INTERFACE-level `tunnel` stanza (#6861 F1b).
//
// The unconditional "Remove the interface-level `tunnel` stanza if the per-unit
// tunnels are the intent" it replaces was unsafe advice. A unit tunnel is built
// by cloneForUnit FROM the interface-level record and only then takes its own
// overrides (compiler_interfaces.go), so a unit carrying just `tunnel mode gre`
// holds INHERITED source/destination — and the emitter suppresses any
// non-WireGuard endpoint missing either half (tunnelemit.go). An operator who
// complied would therefore stop a working per-unit GRE tunnel from emitting at
// all. These advisories reach the boot/apply log and the standing
// `show system alarms` surfaces, so they are acted on; a remediation that
// silently drops traffic is strictly worse than no remediation.
//
// The safe ordering is stated instead of the deletion, so the sentence is still
// actionable rather than merely a refusal.
const ipipInterfaceStanzaRemovalAdvice = "Removing the interface-level `tunnel` " +
	"stanza would drop this anchor, but any unit that does not set its OWN " +
	"`tunnel source` and `tunnel destination` INHERITS them from this stanza and " +
	"would stop emitting an endpoint altogether — give those units explicit " +
	"endpoints first, then remove it."

// ipipWireguardSlotRemovalAdvice is the ONLY remediation offered for a unit
// anchor sitting under an interface-level `tunnel mode wireguard` stanza,
// whether that unit's endpoint is complete or incomplete (#6861 F1b/F4).
//
// Removing the unit's own stanza is the single action that both drops the dead
// anchor and cannot cost traffic. The two alternatives an operator would
// otherwise reach for are each unsafe, and both were offered before:
//
//   - Removing the interface-level WireGuard stanza deletes the working
//     WireGuard tunnel AND exposes the unit's ipip endpoint, which the strict
//     gate then rejects.
//   - Completing the unit's endpoints is simply INEFFECTIVE. The emitter
//     publishes one endpoint keyed by the LOWEST unit and continues past every
//     other per-unit record (tunnelemit.go), so a completed — or GRE-converted
//     — unit still emits nothing. Verified by compiling exactly that config.
const ipipWireguardSlotRemovalAdvice = "Remove THIS UNIT's `tunnel` stanza to " +
	"drop the dead anchor — it is the only action that helps. Completing this " +
	"unit's endpoints, or switching it to `mode gre`, does NOT make it emit: " +
	"the interface-level WireGuard stanza holds the interface's single endpoint " +
	"slot. And do NOT remove that interface-level stanza to free the slot: it " +
	"deletes the working WireGuard tunnel AND exposes this ipip endpoint, which " +
	"the commit gate then rejects."

// ipipAnchorOnlyText renders one anchor-only advisory, naming the ACTUAL reason
// the endpoint was not emitted. isUnit selects the fallback wording, and is
// passed explicitly by the caller rather than sniffed out of `where` — the
// prefix string is a display detail and must not become a control input.
//
// The earlier single-cause wording always said "every unit overrides it"
// (#4785 fold F3). For a stanza the emitter suppressed because its endpoint is
// incomplete that diagnosis is false, and the per-unit remediation it implies
// is the wrong advice, so the incomplete cause is checked FIRST: it is shared
// by both kinds of record and takes precedence for either, because an endpoint
// missing a half stays unemitted even once any other suppressor is gone.
//
// The two COMPLETE-but-unemitted fallbacks are genuinely different causes, and
// collapsing them into the interface wording was wrong three ways for a unit —
// it named a unit and then explained the interface-level stanza, inverted the
// direction (the interface-level stanza suppressed the unit, not the units
// overriding the interface), and pointed remediation at the wrong stanza
// (#6861 F1). Enumerated against the emitter, a COMPLETE record reaches here
// only via:
//
//   - INTERFACE, with units: EmitTunnelEndpointNames walks the units and emits
//     each unit's own TunnelConfig (#5635), so the interface-level object is
//     never published. "every unit overrides it" is exactly right.
//   - UNIT, under an interface-level `tunnel mode wireguard` stanza: that mode
//     short-circuits to ONE endpoint keyed by the lowest unit (#1910,
//     tunnelemit.go) and the per-unit records are never visited. With
//     iface.Tunnel nil, or non-WireGuard, a complete unit record IS emitted and
//     never reaches here — so WireGuard is the whole of this branch. If another
//     mode ever gains a short-circuit, this wording needs revisiting with it.
//
// Every REMEDIATION here is constrained by one rule (#6861 F1b): it must never
// instruct the operator to delete config that is carrying traffic. Removing an
// interface-level stanza is only ever offered through
// ipipInterfaceStanzaRemovalAdvice, which states the inheritance hazard and the
// safe ordering; the unit branch offers removing the UNIT's stanza only, and
// says explicitly why removing the interface-level WireGuard stanza is not the
// alternative it was previously presented as (it deletes a working tunnel and
// exposes a complete ipip endpoint the commit gate then rejects).
func ipipAnchorOnlyText(where string, t *TunnelConfig, isUnit, underIfaceWireguard bool) string {
	var cause, fix string
	switch {
	case isUnit && underIfaceWireguard:
		cause = "the interface-level `tunnel mode wireguard` stanza takes the " +
			"interface's single tunnel endpoint, so this unit's own endpoint is " +
			"never emitted even though it is fully configured"
		fix = ipipWireguardSlotRemovalAdvice
	case isUnit:
		// Enumerated against the emitter, a COMPLETE unit record reaches here
		// ONLY under an interface-level WireGuard short-circuit, so this arm is
		// currently unreachable. It exists so that a future mode gaining its own
		// short-circuit produces an honest "cause unknown" rather than silently
		// inheriting WireGuard's — the failure this whole family of fixes is
		// about is confident advice that is wrong.
		cause = "no tunnel endpoint is emitted for this unit, and the reason is " +
			"not one this check recognises"
		fix = "Inspect the interface-level `tunnel` stanza and this unit's own; " +
			"one of them is suppressing the other. Do not delete either before " +
			"establishing which."
	default:
		cause = "no tunnel endpoint is emitted for the interface-level stanza " +
			"(every unit overrides it)"
		fix = ipipInterfaceStanzaRemovalAdvice
	}
	if missing := ipipMissingEndpointHalves(t); missing != "" {
		cause = fmt.Sprintf("%s, so no tunnel endpoint is emitted", missing)
		switch {
		case isUnit && underIfaceWireguard:
			// #6861 F4: the missing half is a TRUE cause, but "configure both
			// endpoints" is an INEFFECTIVE remedy here and was offered as the
			// first recommendation. Interface-level WireGuard emits only the
			// LOWEST unit and never visits the others (tunnelemit.go), so
			// completing this unit's endpoints — with or without switching it to
			// `mode gre` — still emits nothing. Verified by compiling exactly
			// that: the emitted set stays the single WireGuard endpoint.
			cause += " — and completing it would not help, because the " +
				"interface-level `tunnel mode wireguard` stanza already holds the " +
				"interface's only tunnel endpoint"
			fix = ipipWireguardSlotRemovalAdvice
		case isUnit:
			fix = "Configure both endpoints (and use `mode gre` or `mode " +
				"wireguard` for a tunnel that carries traffic), or remove THIS " +
				"UNIT's `tunnel` stanza."
		default:
			fix = "Configure both endpoints (and use `mode gre` or `mode " +
				"wireguard` for a tunnel that carries traffic). " +
				ipipInterfaceStanzaRemovalAdvice
		}
	}
	return fmt.Sprintf(
		"%s tunnel mode ipip: %s, but it still creates a kernel anchor device %q "+
			"with nothing routed through it — an interface an operator can see that "+
			"carries no traffic (#4785). %s",
		where, cause, t.Name, fix)
}

// ipipMissingEndpointHalves names which halves of a non-WireGuard tunnel
// endpoint are absent, or "" when both are present. It mirrors the emitter's
// own suppression screen (tunnelemit.go: a non-WireGuard tunnel without BOTH
// Source and Destination is never emitted), so the reason reported is the
// reason emission actually failed.
//
// "" is reachable for a record that is complete yet still unemitted — a unit
// tunnel under an interface-level WireGuard stanza, where the emitter publishes
// one endpoint keyed by the lowest unit and never visits the per-unit records.
// The caller's fallback there is NOT a neutral placeholder, and reading it as
// one is what let a unit record be reported with the interface-level cause
// (#6861 F1): "" means "complete, so some OTHER suppressor is responsible", and
// which suppressor that is differs between an interface record and a unit one.
// ipipAnchorOnlyText branches on isUnit to say which.
func ipipMissingEndpointHalves(t *TunnelConfig) string {
	switch {
	case t.Source == "" && t.Destination == "":
		return "neither `tunnel source` nor `tunnel destination` is configured"
	case t.Source == "":
		return "no `tunnel source` is configured"
	case t.Destination == "":
		return "no `tunnel destination` is configured"
	}
	return ""
}

// validateIpipTunnelUnimplementedStrict hard-rejects a config that would emit a
// tunnel endpoint whose mode is `ipip` (#4785 half 1).
//
// IPIP parses, compiles, and reaches the dataplane snapshot, but the userspace
// dataplane — the only supported runtime — has no IPIP primitive in either
// direction:
//
//   - INBOUND: forwarding_build/tunnels.rs indexes an endpoint into
//     `gre_decap_index` only when `tunnel_mode_kind(&endpoint.mode) ==
//     TunnelKind::Gre`. `ipip` classifies as `TunnelKind::Unknown`, so it is
//     never indexed and a received proto-4 frame has nothing to decap against.
//   - OUTBOUND: `TunnelKind::Unknown` is the fail-closed arm of the egress
//     encap dispatcher, which drops rather than defaulting to GRE encap (the
//     pre-#2327 fail-open behaviour).
//
// So the endpoint is dead in BOTH directions. Before this gate it committed
// green with only an advisory (#4788): the operator got a configured interface
// that passes no traffic and no error to act on. Converting the advisory into a
// rejection is the "reject, don't guess" resolution — an unimplemented feature
// must fail loudly at commit rather than succeed into a blackhole.
//
// This is DELIBERATELY not gated on "would it otherwise work": there is no
// partial IPIP support to preserve. Half 2 of #4785 implements the decap stage;
// when it lands this gate is removed, not relaxed.
//
// Strict on the operator commit / commit-check path (CompileConfig). The call
// site tolerates it on the load / peer-sync paths (opts.lenientIpipTunnelMode)
// so a config an older binary already accepted still BOOTS (#1960) — the
// runtime's own fail-closed arms keep the endpoint inert either way, so
// tolerating it there loses nothing. Mirrors validateTunnelOuterFamilyStrict,
// which it runs beside.
func validateIpipTunnelUnimplementedStrict(cfg *Config, lenient bool) ([]string, error) {
	sites := effectiveIpipTunnelSites(cfg)
	if len(sites) == 0 {
		return nil, nil
	}
	if lenient {
		// #4785 re-gate N1: return NO warnings here. runTailGates folds
		// ValidateConfig — which registers validateIpipTunnelDeadWarning — into
		// cfg.Warnings BEFORE this gate runs, so appending again emitted the
		// same ~500-character paragraph TWICE per dead endpoint on the tolerant
		// path. One registration, one warning.
		return nil, nil
	}
	// Strict: report the FIRST offender, in the emitter's deterministic order.
	// The advisory carries the full list.
	return nil, errors.New(ipipUnimplementedText(sites[0].label))
}
