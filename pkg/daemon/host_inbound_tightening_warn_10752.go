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
// while the stanza is still open. This file closes that gap at the one funnel
// that holds old and new together:
// applyAndSyncCommittedWithPeerSnapshotAuthorization (oldActive + compiled).
//
// Firing requires BOTH a narrowed scope AND stranded-flow evidence observed
// by this attempt's own conntrack sweep (stashed by
// flushDeniedHostInboundConntrack, cleared per attempt), INTERSECTED by
// effective scope: kept box addresses are mapped through the OLD config to
// the effective scopes whose enforcement actually covered them, and only
// narrowed scopes with intersecting evidence are named — with counts and
// samples drawn ONLY from those scopes' addresses. Transition-only stays
// silent (no stranded flows to name); evidence-only stays silent (no
// narrowing to report); and cross-scope evidence never names, inflates, or
// samples another scope's warning.
//
// A scope narrows two ways: it loses packet-wide full-admit (custom ports
// lose their only admission), or it loses an unguarded-relevant token (a
// service/protocol token contributing zero catalogued tuples, so its removal
// changes no guard or flush behavior — exempts, bare protocols, ranges).
// Narrowings that drop only catalogued tokens need no warning: flush+guard
// enforce those. Effective override state comes from the CANONICAL resolver
// (config.ResolveInterfaceHostInbound: physical∪unit union, quarantine), and
// the zone-level scope counts ONLY where no replacing override applies
// (#6515): a zone-level token shadowed on every member interface is
// effective nowhere, so its removal is not a transition.
//
// Projection mirrors the #9841 MTU discipline exactly: response-only shallow
// copy owning fresh Warnings storage (the applied original is never
// mutated — snapshot readers race with nothing), committed digest untouched
// (warnings participate in neither identity nor diff), and failed applies
// project nothing.

// keptAddrEvidence is one box address's kept-flow evidence: per-class counts
// with samples. The stash keys evidence by address (never aggregated) so
// commit projection attributes counts AND samples to the narrowed effective
// scopes whose OLD enforcement actually covered each address — a zone-B
// residual can neither inflate a zone-A count nor appear as its sample.
type keptAddrEvidence struct {
	custom        uint64
	customSamples []string
	other         uint64
	otherSamples  []string
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
			stash.byAddr[addr] = keptAddrEvidence{
				custom:        ev.custom,
				customSamples: append([]string(nil), ev.customSamples...),
				other:         ev.other,
				otherSamples:  append([]string(nil), ev.otherSamples...),
			}
		}
	}
	d.keptSuspiciousStash = stash
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
// plus expanded token set (namespaced "s:<svc>"/"p:<proto>", "all"
// expanded, full-admit tokens excluded since full carries them).
type hostInboundScopeState struct {
	full   bool
	tokens map[string]bool
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
		members := map[string]bool{}
		for _, ref := range zone.Interfaces {
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
		if len(members) == 0 {
			continue
		}
		zoneCovers := false
		for unit := range members {
			if _, ok := overrides[unit]; !ok {
				zoneCovers = true
				break
			}
		}
		if zoneCovers {
			out["zone:"+name] = hostInboundScopeTokens(zone.HostInboundTraffic)
		}
		for unit := range members {
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

// hostInboundTightenedScopes returns the sorted scope keys that narrowed from
// old to new in a way that can strand unguarded flows: lost packet-wide
// full-admit status (customs lose their only admission), or removed tokens
// from the unguarded set (exempts/bare/ranges whose removal changes no guard
// or flush behavior). Narrowings that drop only catalogued tokens need no
// warning: flush+guard enforce those. Nil old (first commit) yields nil.
func hostInboundTightenedScopes(oldCfg, newCfg *config.Config) []string {
	if oldCfg == nil || newCfg == nil {
		return nil
	}
	oldStates := hostInboundScopeStates(oldCfg)
	if len(oldStates) == 0 {
		return nil
	}
	newStates := hostInboundScopeStates(newCfg)
	unguarded := hostInboundUnguardedTokens10752()
	var out []string
	for key, old := range oldStates {
		neu := newStates[key]
		if old.full && !neu.full {
			out = append(out, key)
			continue
		}
		if old.full {
			continue
		}
		for tok := range old.tokens {
			if unguarded[tok] && !neu.tokens[tok] {
				out = append(out, key)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// hostInboundScopesForAddrs10752 maps kept box addresses to the OLD effective
// scope keys whose enforcement actually covered each address. Every owned
// stanza unit contributes its interface scope — the member's enforcement,
// whether the OLD generation sourced it from an override or the zone stanza
// (an override added in NEW still narrows the member's OLD zone-sourced
// admission). The zone scope joins only where NO override applied, since
// the zone stanza is effective nowhere on an override-covered member. Unit
// ownership comes from the OLD interface stanzas (authoritative addr→unit);
// zone and override applicability come from the OLD ownership map and
// canonical override index. Addresses on no stanza unit (VIPs, link-locals)
// fall back to the OLD views' addr→zone membership at zone granularity —
// still zone-precise, with within-zone interface precision kept only for
// stanza-addressed units. Addresses covered nowhere (lifeline-only,
// unzoned) map to no scope. Kept flows can only have been stranded by
// transitions in the returned scopes. Scope identity is preserved end to
// end: projection intersects and names these exact keys.
func hostInboundScopesForAddrs10752(oldCfg *config.Config, oldViews []dpuserspace.ZoneHostInboundView, addrs []netip.Addr) map[netip.Addr][]string {
	addrUnits := map[netip.Addr][]string{}
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
				for _, raw := range unit.Addresses {
					pfx, err := netip.ParsePrefix(raw)
					if err != nil || !pfx.IsValid() {
						continue
					}
					addr := pfx.Addr().Unmap()
					addrUnits[addr] = append(addrUnits[addr], literal)
				}
			}
		}
	}
	var owners map[string]string
	var overrides map[string]*config.HostInboundTraffic
	if oldCfg != nil {
		owners = config.InterfaceZoneMap(oldCfg)
		overrides = hostInboundOverrideIndex10752(oldCfg)
		lifelines := config.HostInboundLifelineSet(oldCfg)
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
	viewZones := map[netip.Addr][]string{}
	for _, v := range oldViews {
		for _, raw := range append(append([]string(nil), v.V4Addrs...), v.V6Addrs...) {
			ip, err := netip.ParseAddr(raw)
			if err != nil {
				continue
			}
			viewZones[ip.Unmap()] = append(viewZones[ip.Unmap()], v.Zone)
		}
	}
	out := map[netip.Addr][]string{}
	for _, addr := range addrs {
		seen := map[string]bool{}
		var scopes []string
		add := func(scope string) {
			if !seen[scope] {
				seen[scope] = true
				scopes = append(scopes, scope)
			}
		}
		for _, unit := range addrUnits[addr.Unmap()] {
			zone := owners[unit]
			if zone == "" {
				continue
			}
			add("zone:" + zone + "|iface:" + unit)
			if _, ok := overrides[unit]; !ok {
				add("zone:" + zone)
			}
		}
		// Zone-level fallback only when no unit pinned the address: an
		// override-covered address must never attribute to the zone
		// stanza, which is effective nowhere on it.
		if len(scopes) == 0 {
			for _, zone := range viewZones[addr.Unmap()] {
				add("zone:" + zone)
			}
		}
		if len(scopes) > 0 {
			sort.Strings(scopes)
			out[addr] = scopes
		}
	}
	return out
}

// withTighteningWarningsForResponse10752 returns the config object a commit
// response projects: respCfg itself unless this attempt both narrowed a scope
// AND observed stranded box-oriented flows on an address the OLD config
// covered in a narrowed effective scope, in which case a shallow copy
// carrying the aggregated warning line(s). The copy shares every sub-object
// (read-only post-commit) but owns its Warnings storage — the applied
// original is never mutated. At most two lines (customs, exempt/bare), each
// naming only narrowed scopes with intersecting evidence, counts and samples
// drawn only from those scopes' addresses — cross-scope evidence never
// names, inflates, or samples another scope's warning.
func (d *Daemon) withTighteningWarningsForResponse10752(respCfg, oldActive, compiled *config.Config) *config.Config {
	if respCfg == nil {
		return respCfg
	}
	scopes := hostInboundTightenedScopes(oldActive, compiled)
	if len(scopes) == 0 {
		return respCfg
	}
	tight := make(map[string]bool, len(scopes))
	for _, scope := range scopes {
		tight[scope] = true
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
	named := map[string]bool{}
	for _, addr := range addrs {
		ev := evidence[addr]
		intersects := false
		for _, scope := range attr[addr] {
			if tight[scope] {
				intersects = true
				named[scope] = true
			}
		}
		if !intersects {
			continue
		}
		custom += ev.custom
		for _, s := range ev.customSamples {
			if len(customSamples) >= 5 {
				break
			}
			customSamples = append(customSamples, s)
		}
		other += ev.other
		for _, s := range ev.otherSamples {
			if len(otherSamples) >= 3 {
				break
			}
			otherSamples = append(otherSamples, s)
		}
	}
	var lines []string
	if len(named) > 0 {
		var ordered []string
		for _, scope := range scopes {
			if named[scope] {
				ordered = append(ordered, scope)
			}
		}
		scopeText := scopeText10752(ordered)
		if custom > 0 {
			lines = append(lines, fmt.Sprintf(
				"host-inbound tightening (%s) leaves %d box-oriented custom-port flow(s) with no current admit still authorized%s; "+
					"delete per Removal procedures for unguarded tuples in docs/host-inbound-service-matrix.md",
				scopeText, custom, sampleSuffix10752(customSamples)))
		}
		if other > 0 {
			lines = append(lines, fmt.Sprintf(
				"host-inbound tightening (%s) leaves %d exempt/bare-protocol flow(s) with no current admit still authorized%s; "+
					"stop/disable the originator per Removal procedures for unguarded tuples in docs/host-inbound-service-matrix.md",
				scopeText, other, sampleSuffix10752(otherSamples)))
		}
	} else {
		return respCfg
	}
	out := *respCfg
	warnings := make([]string, 0, len(respCfg.Warnings)+len(lines))
	warnings = append(warnings, respCfg.Warnings...)
	warnings = append(warnings, lines...)
	out.Warnings = warnings
	return &out
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
