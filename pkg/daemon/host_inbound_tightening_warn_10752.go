package daemon

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// host_inbound_tightening_warn_10752.go projects the any-service→named
// tightening risk into commit output (#10752 round 4, scope-keyed round 6).
//
// The dangerous order is a transition: host-inbound scope(s) whose effective
// set admitted flows that the new set no longer admits, while pre-existing
// box-oriented flows for UNGUARDED tuples (custom ports, exempt
// control-plane/client ports, bare IP protocols) keep riding the broad reply
// accept. Commit-time ValidateConfig sees only the NEW config, so it cannot
// observe the transition — and the any-service breadth advisory fires only
// while the stanza is still open. This file closes that gap at the commit
// funnel — the only applier returning a response object capable of carrying
// warnings: applyAndSyncCommittedWithPeerSnapshotAuthorization (oldActive +
// compiled). Other old+new holders (syncAndApply, executeConfirmedRollback)
// run the sweep and journal without projecting transition warnings.
//
// Firing has two shapes. When this attempt's own conntrack sweep (stashed by
// flushDeniedHostInboundConntrack, cleared per attempt) observed stranded
// box-oriented flows on addresses the OLD config covered in a narrowed
// effective scope, each warning line names only scopes that admitted the
// exact tuple before the transition and deny it afterward. The collector,
// per-attempt stash, and projection retain tuple identity, so counts and
// samples exclude unrelated flows on the same address or scope. A silent-class
// pointer accompanies observed evidence (the sweep cannot observe in-range
// customs, ranges, post-sweep reconnects, or sweep misses). When narrowed
// scopes exist but the sweep observed no stranded tuples in them, the commit
// carries a transition-only advisory with honest zero-observed wording and a
// manual-procedure pointer, so silent-class narrowings never pass
// commit-silent. The advisory is suppressed only when the narrowed scopes'
// zones own no address in either generation (zone-granular by design: an
// addressless member in an addressed zone still warns, and DHCP members may
// gain addresses at any time). The advisory lives in the commit channel
// because only the commit funnel returns a response object: the sweep (and
// journal WARN it feeds) sees only the new state, so per-apply journal context
// cannot express a transition.
//
// A scope narrows when it loses packet-wide full-admit or an unguarded-relevant
// token (a token contributing zero catalogued tuples, so its removal changes
// no guard or flush behavior — exempts, bare protocols, and ranges). Narrowings
// that drop only catalogued tokens need no warning: flush+guard enforce those.
// Effective override state comes from the CANONICAL resolver
// (config.ResolveInterfaceHostInbound: physical∪unit union, quarantine), and
// the zone-level scope counts ONLY where no replacing override applies
// (#6515): a zone-level token shadowed on every member interface is effective
// nowhere, so its removal is not a transition.
//
// Projection mirrors the #9841 MTU discipline exactly: response-only shallow
// copy owning fresh Warnings storage (the applied original is never
// mutated — snapshot readers race with nothing), committed digest untouched
// (warnings participate in neither identity nor diff), and failed applies
// project nothing.

// keptFlowTuple10752 is the conntrack tuple whose identity must survive
// collector, stash, and warning projection.
type keptFlowTuple10752 struct {
	src      netip.Addr
	dst      netip.Addr
	protocol uint8
	srcPort  uint16
	dstPort  uint16
}

// keptTupleEvidence10752 retains per-class counts for one tuple. Samples are
// rendered from the tuple itself during projection.
type keptTupleEvidence10752 struct {
	custom uint64
	other  uint64
}

// keptAddrEvidence is one box address's kept-flow evidence: per-class counts
// and samples plus exact tuple identities for transition projection.
type keptAddrEvidence struct {
	custom        uint64
	customSamples []string
	other         uint64
	otherSamples  []string
	byTuple       map[keptFlowTuple10752]keptTupleEvidence10752
}

// keptSuspiciousApplyReport is one flush sweep's kept-flow evidence.
type keptSuspiciousApplyReport struct {
	byAddr map[netip.Addr]keptAddrEvidence
}

// clearKeptSuspicious10752 resets the per-attempt evidence stash. Called by
// the commit funnel immediately before its apply; the flush sweep inside the
// apply repopulates it. Same-goroutine under applySem — no apply can
// interleave between clear and populate.
func (d *Daemon) clearKeptSuspicious10752() {
	d.keptSuspiciousMu.Lock()
	defer d.keptSuspiciousMu.Unlock()
	d.keptSuspiciousStash = nil
}

// recordKeptSuspicious10752 stores this sweep's evidence for a later
// projection read (deep copy — the sweep's map is not retained). Called
// unconditionally at the end of every flush sweep (including zero-count
// sweeps, which overwrite stale evidence).
func (d *Daemon) recordKeptSuspicious10752(byAddr map[netip.Addr]keptAddrEvidence) {
	d.keptSuspiciousMu.Lock()
	defer d.keptSuspiciousMu.Unlock()
	stash := &keptSuspiciousApplyReport{}
	if len(byAddr) > 0 {
		stash.byAddr = make(map[netip.Addr]keptAddrEvidence, len(byAddr))
		for addr, ev := range byAddr {
			stash.byAddr[addr] = cloneKeptAddrEvidence10752(ev)
		}
	}
	d.keptSuspiciousStash = stash
}

func cloneKeptAddrEvidence10752(ev keptAddrEvidence) keptAddrEvidence {
	out := keptAddrEvidence{
		custom:        ev.custom,
		customSamples: append([]string(nil), ev.customSamples...),
		other:         ev.other,
		otherSamples:  append([]string(nil), ev.otherSamples...),
	}
	if len(ev.byTuple) > 0 {
		out.byTuple = make(map[keptFlowTuple10752]keptTupleEvidence10752, len(ev.byTuple))
		for tuple, tupleEv := range ev.byTuple {
			out.byTuple[tuple] = tupleEv
		}
	}
	return out
}

// stashedKeptSuspicious10752 returns the current attempt's evidence, if any.
// The returned map is stash-owned: callers must not mutate it.
func (d *Daemon) stashedKeptSuspicious10752() map[netip.Addr]keptAddrEvidence {
	d.keptSuspiciousMu.Lock()
	defer d.keptSuspiciousMu.Unlock()
	if d.keptSuspiciousStash == nil {
		return nil
	}
	return d.keptSuspiciousStash.byAddr
}

// hostInboundScopeState is one scope's effective admission: full-admit flag
// plus expanded, namespaced ("s:<svc>"/"p:<proto>") tokens and their
// precomputed family-specific SSOT match tuples.
type hostInboundScopeState struct {
	full       bool
	tokens     map[string]bool
	ipMatches  []config.L4Match
	ip6Matches []config.L4Match
}

// hostInboundOverrideIndex10752 canonicalizes config.ResolveInterfaceHostInbound
// into per-unit effective overrides keyed by canonical unit literal. The
// resolver is the enforcement contract: a unit's effective override is the
// UNION of any covering physical-interface override and its own unit
// override (#3720), with cross-zone leaks quarantined to the owning zone
// (#3720 M01, #5489). Bare-physical keys carry no unit and are skipped —
// expansion already pushed their tokens onto the covered units. Alias
// spellings collapsing onto one canonical literal merge (union is
// order-insensitive downstream: scope tokens are sets).
func hostInboundOverrideIndex10752(cfg *config.Config) map[string]*config.HostInboundTraffic {
	out := map[string]*config.HostInboundTraffic{}
	if cfg == nil {
		return out
	}
	for key, hib := range config.ResolveInterfaceHostInbound(cfg) {
		if hib == nil {
			continue
		}
		if s := cfg.SplitInterfaceUnitRef(key); s.HasUnit {
			out[s.Literal] = config.MergeHostInboundTraffic(out[s.Literal], hib)
		}
	}
	return out
}

// hostInboundOwnedMembers10752 returns the sorted canonical units the zone
// owns for host-inbound enforcement: members expanded through the canonical
// bare→unit fan-down, first-sorted-owner wins, lifelines skipped. Shared by
// scope-state construction and disappearance replacement comparison so both
// agree on membership. name is the zone map key (ownership compares
// against it, not the struct field). Units-only by design: bare
// trunk-parent addresses form no scope, so all-units-overridden plus a
// zone-stanza narrowing stays silent for kept flows there (documented
// exception in the service matrix warning section).
func hostInboundOwnedMembers10752(cfg *config.Config, name string, ifaces []string, owners map[string]string, lifelines map[string]bool) []string {
	if cfg == nil {
		return nil
	}
	members := map[string]bool{}
	for _, ref := range ifaces {
		if ref == "" {
			continue
		}
		for _, key := range config.InterfaceUnitRefKeys(cfg, ref) {
			// Ownership is keyed exactly as the map was built
			// (first-writer-wins over sorted zones); identity is
			// canonical so aliases collapse.
			if owners[key] != name {
				continue
			}
			split := cfg.SplitInterfaceUnitRef(key)
			if !split.HasUnit {
				continue
			}
			if config.HostInboundLifelineInterface(split.Literal, lifelines) {
				continue
			}
			members[split.Literal] = true
		}
	}
	out := make([]string, 0, len(members))
	for unit := range members {
		out = append(out, unit)
	}
	sort.Strings(out)
	return out
}

// hostInboundScopeStates returns every scope's effective state: "zone:<name>"
// for the zone-level stanza plus "zone:<name>|iface:<canonical-unit>" for
// each owned member unit, where an effective override REPLACES the zone level
// (#6515). Members expand through the canonical bare→unit fan-down
// (config.InterfaceUnitRefKeys); units compare by canonical literal so alias
// spellings match stably across configs. Lifeline units are skipped
// (mirroring the view builders), as are members owned by another zone
// (config.InterfaceZoneMap first-sorted ownership: a quarantined override or
// shadowed stanza enforces nothing for the losing zone). The zone-level
// scope is emitted ONLY where the zone token is effective — i.e. some owned
// non-lifeline member has no applicable override. A zone whose owned members
// are all override-covered enforces nothing at zone level, so narrowing the
// zone stanza there is not a transition.
func hostInboundScopeStates(cfg *config.Config) map[string]hostInboundScopeState {
	out := map[string]hostInboundScopeState{}
	if cfg == nil {
		return out
	}
	lifelines := config.HostInboundLifelineSet(cfg)
	overrides := hostInboundOverrideIndex10752(cfg)
	owners := config.InterfaceZoneMap(cfg)
	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		zoneNames = append(zoneNames, name)
	}
	sort.Strings(zoneNames)
	for _, name := range zoneNames {
		zone := cfg.Security.Zones[name]
		if zone == nil {
			continue
		}
		members := hostInboundOwnedMembers10752(cfg, name, zone.Interfaces, owners, lifelines)
		if len(members) == 0 {
			continue
		}
		zoneCovers := false
		for _, unit := range members {
			if _, ok := overrides[unit]; !ok {
				zoneCovers = true
				break
			}
		}
		if zoneCovers {
			out["zone:"+name] = hostInboundScopeTokens(zone.HostInboundTraffic)
		}
		for _, unit := range members {
			effective := zone.HostInboundTraffic
			if override, ok := overrides[unit]; ok {
				effective = override
			}
			out["zone:"+name+"|iface:"+unit] = hostInboundScopeTokens(effective)
		}
	}
	return out
}

func hostInboundScopeTokens(hi *config.HostInboundTraffic) hostInboundScopeState {
	state := hostInboundScopeState{tokens: map[string]bool{}}
	if hi == nil {
		return state
	}
	addTokens := func(tokens []string, kind byte, expandAll func() []string) {
		for _, tok := range tokens {
			if config.HostInboundFullAdmitService(tok) {
				state.full = true
				continue
			}
			if tok == "all" {
				for _, expanded := range expandAll() {
					state.tokens[string([]byte{kind})+":"+expanded] = true
				}
				continue
			}
			state.tokens[string([]byte{kind})+":"+tok] = true
		}
	}
	addTokens(hi.SystemServices, 's', config.HostInboundAllExpansionServices)
	addTokens(hi.Protocols, 'p', config.HostInboundAllExpansionProtocols)
	if state.full {
		return state
	}
	for token := range state.tokens {
		switch {
		case strings.HasPrefix(token, "s:"):
			name := strings.TrimPrefix(token, "s:")
			state.ipMatches = append(state.ipMatches, config.HostInboundServiceMatch(name, "ip")...)
			state.ip6Matches = append(state.ip6Matches, config.HostInboundServiceMatch(name, "ip6")...)
		case strings.HasPrefix(token, "p:"):
			name := strings.TrimPrefix(token, "p:")
			state.ipMatches = append(state.ipMatches, config.HostInboundProtocolMatch(name, "ip")...)
			state.ip6Matches = append(state.ip6Matches, config.HostInboundProtocolMatch(name, "ip6")...)
		}
	}
	return state
}

// hostInboundUnguardedTokens10752 is the SSOT-derived set of tokens whose
// removal can strand unguarded box-oriented flows: tokens contributing at
// least one tuple the catalog can never guard — a TCP/UDP tuple with a port
// outside the catalog (exempts, ranges, customs-adjacent), or a bare IP
// protocol. ICMP-only and L2/nil tokens are excluded (short-lived/global and
// never in IP conntrack respectively). Computed once; pure SSOT.
var hostInboundUnguardedTokens10752 = sync.OnceValue(func() map[string]bool {
	out := map[string]bool{}
	consider := func(key string, matches func(family string) []config.L4Match) {
		for _, family := range []string{"ip", "ip6"} {
			catalog := xnft.HostInboundStaleReplyCatalog(family)
			tcpSet := map[uint16]bool{}
			for _, p := range catalog.TCP {
				tcpSet[p] = true
			}
			udpSet := map[uint16]bool{}
			for _, p := range catalog.UDP {
				udpSet[p] = true
			}
			for _, m := range matches(family) {
				switch m.Proto {
				case config.HostInboundProtoTCP:
					for _, r := range m.Ports {
						for p := uint32(r.Lo); p <= uint32(r.Hi); p++ {
							if !tcpSet[uint16(p)] {
								out[key] = true
							}
						}
					}
				case config.HostInboundProtoUDP:
					for _, r := range m.Ports {
						for p := uint32(r.Lo); p <= uint32(r.Hi); p++ {
							if !udpSet[uint16(p)] {
								out[key] = true
							}
						}
					}
				case config.HostInboundProtoICMP, config.HostInboundProtoICMPv6:
					continue
				default:
					out[key] = true
				}
			}
		}
	}
	for tok := range config.KnownHostInboundSystemServices {
		if tok == "all" || config.HostInboundFullAdmitService(tok) {
			continue
		}
		consider("s:"+tok, func(family string) []config.L4Match {
			return config.HostInboundServiceMatch(tok, family)
		})
	}
	for tok := range config.KnownHostInboundProtocols {
		if tok == "all" {
			continue
		}
		consider("p:"+tok, func(family string) []config.L4Match {
			return config.HostInboundProtocolMatch(tok, family)
		})
	}
	return out
})

// hostInboundScopeTransition10752 retains the old and new admission states for
// each narrowed scope so projection can test the exact observed tuple.
type hostInboundScopeTransition10752 struct {
	old hostInboundScopeState
	new []hostInboundScopeState
}

// hostInboundTightenedScopes returns sorted scope keys that narrowed from old
// to new in a way that can strand unguarded flows, together with their
// transition states for tuple-specific evidence attribution. Nil old (first
// commit) yields no transitions.
func hostInboundTightenedScopes(oldCfg, newCfg *config.Config) ([]string, map[string]hostInboundScopeTransition10752) {
	if oldCfg == nil || newCfg == nil {
		return nil, nil
	}
	oldStates := hostInboundScopeStates(oldCfg)
	if len(oldStates) == 0 {
		return nil, nil
	}
	newStates := hostInboundScopeStates(newCfg)
	unguarded := hostInboundUnguardedTokens10752()
	var out []string
	transitions := map[string]hostInboundScopeTransition10752{}
	mark := func(key string, old hostInboundScopeState, new []hostInboundScopeState) {
		for _, next := range new {
			if hostInboundScopeNarrowed10752(old, next, unguarded) {
				out = append(out, key)
				transitions[key] = hostInboundScopeTransition10752{old: old, new: new}
				return
			}
		}
	}
	for key, old := range oldStates {
		if neu, ok := newStates[key]; ok {
			mark(key, old, []hostInboundScopeState{neu})
			continue
		}
		if zone, ok := hostInboundZoneScopeName10752(key); ok {
			// A disappearing zone scope is compared with each member's
			// replacement state; a full override is a loosening, not a
			// denial. Keep those states for tuple-specific projection.
			mark(key, old, hostInboundZoneReplacementStates10752(oldCfg, newCfg, zone, newStates))
			continue
		}
		// A disappearing interface scope (member removed or moved away)
		// is denied in the new generation.
		mark(key, old, []hostInboundScopeState{{}})
	}
	sort.Strings(out)
	return out, transitions
}

// hostInboundScopeNarrowed10752 reports whether an old effective scope
// removed an unguarded-relevant admission. Full-admit loss always narrows;
// new full-admit is a loosening.
func hostInboundScopeNarrowed10752(old, neu hostInboundScopeState, unguarded map[string]bool) bool {
	if old.full {
		return !neu.full
	}
	if neu.full {
		return false
	}
	for tok := range old.tokens {
		if unguarded[tok] && !neu.tokens[tok] {
			return true
		}
	}
	return false
}

// hostInboundScopeAdmitsTuple10752 evaluates one retained conntrack tuple
// against the scope's precomputed SSOT matches, not a token/port union.
func hostInboundScopeAdmitsTuple10752(state hostInboundScopeState, tuple keptFlowTuple10752) bool {
	if state.full {
		return true
	}
	matches := state.ipMatches
	if tuple.src.Is6() {
		matches = state.ip6Matches
	}
	for _, match := range matches {
		if match.Reject || match.Proto != tuple.protocol {
			continue
		}
		if len(match.Ports) == 0 || portInRanges(tuple.srcPort, match.Ports) {
			return true
		}
	}
	return false
}

func hostInboundScopeTransitionLosesTuple10752(transition hostInboundScopeTransition10752, tuple keptFlowTuple10752) bool {
	if !hostInboundScopeAdmitsTuple10752(transition.old, tuple) {
		return false
	}
	for _, next := range transition.new {
		if !hostInboundScopeAdmitsTuple10752(next, tuple) {
			return true
		}
	}
	return len(transition.new) == 0
}

func hostInboundScopeTransitionLosesAddressTuple10752(
	scope string,
	addressScopes []string,
	transitions map[string]hostInboundScopeTransition10752,
	tuple keptFlowTuple10752,
) bool {
	if zone, ok := hostInboundZoneScopeName10752(scope); ok {
		prefix := "zone:" + zone + "|iface:"
		hasInterfaceScope := false
		for _, candidate := range addressScopes {
			if !strings.HasPrefix(candidate, prefix) {
				continue
			}
			hasInterfaceScope = true
			if transition, ok := transitions[candidate]; ok &&
				hostInboundScopeTransitionLosesTuple10752(transition, tuple) {
				return true
			}
		}
		if hasInterfaceScope {
			return false
		}
	}
	transition, ok := transitions[scope]
	return ok && hostInboundScopeTransitionLosesTuple10752(transition, tuple)
}

func sortedKeptTupleKeys10752(byTuple map[keptFlowTuple10752]keptTupleEvidence10752) []keptFlowTuple10752 {
	tuples := make([]keptFlowTuple10752, 0, len(byTuple))
	for tuple := range byTuple {
		tuples = append(tuples, tuple)
	}
	sort.Slice(tuples, func(i, j int) bool {
		a, b := tuples[i], tuples[j]
		if a.src != b.src {
			return a.src.Less(b.src)
		}
		if a.dst != b.dst {
			return a.dst.Less(b.dst)
		}
		if a.protocol != b.protocol {
			return a.protocol < b.protocol
		}
		if a.srcPort != b.srcPort {
			return a.srcPort < b.srcPort
		}
		return a.dstPort < b.dstPort
	})
	return tuples
}
func keptFlowTupleSample10752(tuple keptFlowTuple10752) string {
	src, dst := "?", "?"
	if tuple.src.IsValid() {
		src = tuple.src.String()
	}
	if tuple.dst.IsValid() {
		dst = tuple.dst.String()
	}
	return fmt.Sprintf("%s %s:%d→%s:%d",
		protoName10752(tuple.protocol), src, tuple.srcPort, dst, tuple.dstPort)
}

// hostInboundZoneScopeName10752 splits a "zone:<name>" scope key, reporting
// false for interface scopes.
func hostInboundZoneScopeName10752(key string) (string, bool) {
	if !strings.HasPrefix(key, "zone:") || strings.Contains(key, "|iface:") {
		return "", false
	}
	return strings.TrimPrefix(key, "zone:"), true
}

// hostInboundZoneReplacementStates10752 returns the new effective states to
// compare a disappeared zone scope against: one per member that enforced
// the OLD zone stanza and is still owned by the zone in NEW (its
// zone:<name>|iface:<unit> state, or zero when the member has no new
// state). Empty when nothing replaces the old enforcement (zone/member
// deleted or moved away) — the caller then compares against zero denial.
func hostInboundZoneReplacementStates10752(oldCfg, newCfg *config.Config, zone string, newStates map[string]hostInboundScopeState) []hostInboundScopeState {
	oldZone := oldCfg.Security.Zones[zone]
	if oldZone == nil {
		return nil
	}
	oldOwners := config.InterfaceZoneMap(oldCfg)
	oldOverrides := hostInboundOverrideIndex10752(oldCfg)
	oldLifelines := config.HostInboundLifelineSet(oldCfg)
	newOwners := config.InterfaceZoneMap(newCfg)
	var out []hostInboundScopeState
	for _, unit := range hostInboundOwnedMembers10752(oldCfg, zone, oldZone.Interfaces, oldOwners, oldLifelines) {
		if _, overridden := oldOverrides[unit]; overridden {
			continue
		}
		if newOwners[unit] != zone {
			continue
		}
		out = append(out, newStates["zone:"+zone+"|iface:"+unit])
	}
	if len(out) == 0 {
		out = append(out, hostInboundScopeState{})
	}
	return out
}

// hostInboundScopesForAddrs10752 maps kept box addresses to the OLD effective
// scope keys whose enforcement actually covered each address, group by
// group over the OLD views (each view is one effective-token group). A
// group contributes the interface scope of every owned member unit it can
// place the address on — authoritative stanza/VRRP ownership where it
// exists (a VIP joins its unit's group, so a VIP on an overridden unit
// enforces the override), else the group's own unit membership, which
// covers derived addresses (stable RETH link-locals) with the narrowed
// owners rather than dropping them. The zone scope joins per unit only
// where NO override applied, since the zone stanza is effective nowhere
// on an override-covered member — and per group only when the group
// yielded no unit scope at all (bare/base groups), so a shared derived
// address keeps its zone coverage alongside unit pins. Ownership and
// override applicability come from the OLD ownership map and canonical
// override index. Addresses covered nowhere (lifeline-only, unzoned)
// map to no scope. Kept flows can only have been stranded by transitions
// in the returned scopes. Scope identity is preserved end to end:
// projection intersects and names these exact keys.
func hostInboundScopesForAddrs10752(oldCfg *config.Config, oldViews []dpuserspace.ZoneHostInboundView, addrs []netip.Addr) map[netip.Addr][]string {
	targets := make(map[netip.Addr]bool, len(addrs))
	for _, addr := range addrs {
		targets[addr.Unmap()] = true
	}
	// Tier 1 (authoritative): stanza static + VRRP virtual addresses pin
	// their unit. Static addresses are CIDR; VRRP virtual addresses are
	// bare or CIDR (mirroring the view builder's hostIPFromCIDR).
	addrUnits := map[netip.Addr][]string{}
	var owners map[string]string
	var overrides map[string]*config.HostInboundTraffic
	var lifelines map[string]bool
	if oldCfg != nil {
		for base, ifCfg := range oldCfg.Interfaces.Interfaces {
			if ifCfg == nil {
				continue
			}
			for num, unit := range ifCfg.Units {
				if unit == nil {
					continue
				}
				literal := oldCfg.SplitInterfaceUnitRef(fmt.Sprintf("%s.%d", base, num)).Literal
				owns := func(raw string) {
					if ip, err := netip.ParseAddr(raw); err == nil {
						addrUnits[ip.Unmap()] = append(addrUnits[ip.Unmap()], literal)
						return
					}
					if pfx, err := netip.ParsePrefix(raw); err == nil && pfx.IsValid() {
						addr := pfx.Addr().Unmap()
						addrUnits[addr] = append(addrUnits[addr], literal)
					}
				}
				for _, raw := range unit.Addresses {
					owns(raw)
				}
				for _, vg := range unit.VRRPGroups {
					if vg == nil {
						continue
					}
					for _, raw := range vg.VirtualAddresses {
						owns(raw)
					}
				}
			}
		}
		owners = config.InterfaceZoneMap(oldCfg)
		overrides = hostInboundOverrideIndex10752(oldCfg)
		lifelines = config.HostInboundLifelineSet(oldCfg)
		for addr, units := range addrUnits {
			kept := units[:0]
			for _, unit := range units {
				if !config.HostInboundLifelineInterface(unit, lifelines) {
					kept = append(kept, unit)
				}
			}
			addrUnits[addr] = kept
		}
	}
	acc := map[netip.Addr][]string{}
	seen := map[netip.Addr]map[string]bool{}
	add := func(addr netip.Addr, scope string) {
		if seen[addr] == nil {
			seen[addr] = map[string]bool{}
		}
		if !seen[addr][scope] {
			seen[addr][scope] = true
			acc[addr] = append(acc[addr], scope)
		}
	}
	for _, v := range oldViews {
		var vifaces []string
		if oldCfg != nil {
			for _, raw := range v.Interfaces {
				if s := oldCfg.SplitInterfaceUnitRef(raw); s.HasUnit {
					vifaces = append(vifaces, s.Literal)
				}
			}
		}
		for _, raw := range append(append([]string(nil), v.V4Addrs...), v.V6Addrs...) {
			ip, err := netip.ParseAddr(raw)
			if err != nil {
				continue
			}
			addr := ip.Unmap()
			if !targets[addr] {
				continue
			}
			var vu []string
			if tier1 := addrUnits[addr]; len(tier1) > 0 {
				inView := map[string]bool{}
				for _, u := range vifaces {
					inView[u] = true
				}
				for _, u := range tier1 {
					if inView[u] {
						vu = append(vu, u)
					}
				}
			} else {
				vu = vifaces
			}
			var scoped []string
			for _, u := range vu {
				if owners[u] == "" || config.HostInboundLifelineInterface(u, lifelines) {
					continue
				}
				scoped = append(scoped, u)
			}
			if len(scoped) == 0 {
				add(addr, "zone:"+v.Zone)
				continue
			}
			for _, u := range scoped {
				zone := owners[u]
				add(addr, "zone:"+zone+"|iface:"+u)
				if _, ok := overrides[u]; !ok {
					add(addr, "zone:"+zone)
				}
			}
		}
	}
	out := map[netip.Addr][]string{}
	for addr, scopes := range acc {
		sort.Strings(scopes)
		out[addr] = scopes
	}
	return out
}

// silentClasses10752 are the stranded-flow shapes the conntrack sweep cannot
// observe, named identically in both commit-warning shapes.
const silentClasses10752 = "in-range customs (UDP, or TCP without a local LISTEN), ranges, post-sweep reconnects, or sweep misses"

// withTighteningWarningsForResponse10752 returns the config object a commit
// response projects: respCfg itself when nothing narrowed, else a shallow
// copy carrying the tightening warning lines. The copy shares every
// sub-object (read-only post-commit) but owns its Warnings storage — the
// applied original is never mutated.
//
// With stranded tuples observed in narrowed scopes: at most three lines — the
// customs line, the exempt/bare line (each present only when its class has
// exact tuples admitted by the OLD effective policy and denied by the NEW one,
// naming only scopes whose transition removed that tuple's admission, with
// counts and samples drawn only from those tuples), plus the silent-class
// pointer sentence. With narrowed scopes but zero matching tuples, one
// transition-only advisory names the narrowed scopes with honest
// zero-observed wording, so silent-class narrowings never pass commit-silent.
// The advisory is suppressed only when the narrowed scopes' zones own no
// address in either generation (zone-granular by design).
func (d *Daemon) withTighteningWarningsForResponse10752(respCfg, oldActive, compiled *config.Config) *config.Config {
	if respCfg == nil {
		return respCfg
	}
	scopes, transitions := hostInboundTightenedScopes(oldActive, compiled)
	if len(scopes) == 0 {
		return respCfg
	}
	evidence := d.stashedKeptSuspicious10752()
	addrs := make([]netip.Addr, 0, len(evidence))
	for addr := range evidence {
		addrs = append(addrs, addr)
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i].Less(addrs[j]) })
	attr := hostInboundScopesForAddrs10752(oldActive, dpuserspace.BuildZoneHostInboundViews(oldActive), addrs)
	var custom uint64
	var customSamples []string
	var other uint64
	var otherSamples []string
	namedCustom := map[string]bool{}
	namedOther := map[string]bool{}
	for _, addr := range addrs {
		ev := evidence[addr]
		for _, tuple := range sortedKeptTupleKeys10752(ev.byTuple) {
			tupleEv := ev.byTuple[tuple]
			if !tuple.src.IsValid() || tuple.src.Unmap() != addr.Unmap() {
				continue
			}
			var hit []string
			for _, scope := range attr[addr] {
				if hostInboundScopeTransitionLosesAddressTuple10752(scope, attr[addr], transitions, tuple) {
					hit = append(hit, scope)
				}
			}
			if tupleEv.custom > 0 && len(hit) > 0 {
				custom += tupleEv.custom
				if len(customSamples) < 5 {
					customSamples = append(customSamples, keptFlowTupleSample10752(tuple))
				}
				for _, scope := range hit {
					namedCustom[scope] = true
				}
			}
			if tupleEv.other > 0 && len(hit) > 0 {
				other += tupleEv.other
				if len(otherSamples) < 3 {
					otherSamples = append(otherSamples, keptFlowTupleSample10752(tuple))
				}
				for _, scope := range hit {
					namedOther[scope] = true
				}
			}
		}
	}
	var lines []string
	if len(namedCustom)+len(namedOther) > 0 {
		ordered := func(named map[string]bool) []string {
			var out []string
			for _, scope := range scopes {
				if named[scope] {
					out = append(out, scope)
				}
			}
			return out
		}
		if custom > 0 {
			lines = append(lines, fmt.Sprintf(
				"host-inbound tightening (%s) leaves %d box-oriented custom-port flow(s) with no current admit still authorized%s; "+
					"delete per Removal procedures for unguarded tuples in docs/host-inbound-service-matrix.md",
				scopeText10752(ordered(namedCustom)), custom, sampleSuffix10752(customSamples)))
		}
		if other > 0 {
			lines = append(lines, fmt.Sprintf(
				"host-inbound tightening (%s) leaves %d exempt/bare-protocol flow(s) with no current admit still authorized%s; "+
					"stop/disable the originator per Removal procedures for unguarded tuples in docs/host-inbound-service-matrix.md",
				scopeText10752(ordered(namedOther)), other, sampleSuffix10752(otherSamples)))
		}
		lines = append(lines, fmt.Sprintf(
			"The sweep cannot observe %s — verify those per Removal procedures for unguarded tuples in docs/host-inbound-service-matrix.md",
			silentClasses10752))
	} else {
		if !tightenedScopesHaveAddrs10752(scopes,
			dpuserspace.BuildZoneHostInboundViews(oldActive),
			dpuserspace.BuildZoneHostInboundViews(compiled)) {
			return respCfg
		}
		lines = append(lines, fmt.Sprintf(
			"host-inbound tightening (%s) observed no stranded flows in the narrowed scopes this sweep — "+
				"the sweep cannot observe %s; verify/delete per Removal procedures for unguarded tuples in docs/host-inbound-service-matrix.md",
			scopeText10752(scopes), silentClasses10752))
	}
	out := *respCfg
	warnings := make([]string, 0, len(respCfg.Warnings)+len(lines))
	warnings = append(warnings, respCfg.Warnings...)
	warnings = append(warnings, lines...)
	out.Warnings = warnings
	return &out
}

// tightenedScopesHaveAddrs10752 reports whether any narrowed scope's zone owns
// an address in either generation's views. Narrowings on addressless scopes
// (DHCP-pending or undeclared members, emptied zones) can strand nothing and
// offer nothing to verify, so the transition-only advisory stays silent for
// them. Zone-granular by design: interface precision would need per-unit
// address ownership in both generations for a one-line advisory.
func tightenedScopesHaveAddrs10752(scopes []string, views ...[]dpuserspace.ZoneHostInboundView) bool {
	zones := map[string]bool{}
	for _, scope := range scopes {
		zone := strings.TrimPrefix(scope, "zone:")
		if i := strings.IndexByte(zone, '|'); i >= 0 {
			zone = zone[:i]
		}
		zones[zone] = true
	}
	for _, vs := range views {
		for _, v := range vs {
			if zones[v.Zone] && len(v.V4Addrs)+len(v.V6Addrs) > 0 {
				return true
			}
		}
	}
	return false
}

func scopeText10752(scopes []string) string {
	if len(scopes) > 4 {
		return strings.Join(scopes[:4], ", ") + fmt.Sprintf(" (+%d more)", len(scopes)-4)
	}
	return strings.Join(scopes, ", ")
}

func sampleSuffix10752(samples []string) string {
	if len(samples) == 0 {
		return ""
	}
	shown := samples
	if len(shown) > 2 {
		shown = shown[:2]
	}
	return fmt.Sprintf(" (e.g. %s)", strings.Join(shown, ", "))
}
