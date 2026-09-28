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
// tightening risk into commit output (#10752 round 4, extended round 5).
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
// flushDeniedHostInboundConntrack, cleared per attempt), INTERSECTED by zone:
// kept box addresses are mapped through the OLD views, and only narrowed
// scopes in a zone containing stranded flows are named. Transition-only would
// warn routine restrictions with zero stale flows; evidence-only would warn
// steady-state explicit-bind clients on unrelated commits; and global
// evidence would misattribute zone B's residual to zone A's tightening.
//
// A scope narrows two ways: it loses packet-wide full-admit (custom ports
// lose their only admission), or it loses an unguarded-relevant token (a
// service/protocol token contributing zero catalogued tuples, so its removal
// changes no guard or flush behavior — exempts, bare protocols, ranges).
// Narrowings that drop only catalogued tokens need no warning: flush+guard
// enforce those. Zone-level state counts ONLY where no replacing override
// applies (#6515): a zone-level token shadowed on every member interface is
// effective nowhere, so its removal is not a transition.
//
// Projection mirrors the #9841 MTU discipline exactly: response-only shallow
// copy owning fresh Warnings storage (the applied original is never
// mutated — snapshot readers race with nothing), committed digest untouched
// (warnings participate in neither identity nor diff), and failed applies
// project nothing.

// keptSuspiciousApplyReport is one flush sweep's kept-flow evidence.
type keptSuspiciousApplyReport struct {
	custom        uint64
	customSamples []string
	other         uint64
	otherSamples  []string
	addrs         []netip.Addr
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
// projection read. Called unconditionally at the end of every flush sweep
// (including zero-count sweeps, which overwrite stale evidence).
func (d *Daemon) recordKeptSuspicious10752(custom uint64, customSamples []string, other uint64, otherSamples []string, addrs []netip.Addr) {
	d.keptSuspiciousMu.Lock()
	defer d.keptSuspiciousMu.Unlock()
	d.keptSuspiciousStash = &keptSuspiciousApplyReport{
		custom: custom, customSamples: customSamples,
		other: other, otherSamples: otherSamples, addrs: addrs,
	}
}

// stashedKeptSuspicious10752 returns the current attempt's evidence, if any.
func (d *Daemon) stashedKeptSuspicious10752() (uint64, []string, uint64, []string, []netip.Addr) {
	d.keptSuspiciousMu.Lock()
	defer d.keptSuspiciousMu.Unlock()
	if d.keptSuspiciousStash == nil {
		return 0, nil, 0, nil, nil
	}
	s := d.keptSuspiciousStash
	return s.custom, s.customSamples, s.other, s.otherSamples, s.addrs
}

// hostInboundScopeState is one scope's effective admission: full-admit flag
// plus expanded token set (namespaced "s:<svc>"/"p:<proto>", "all"
// expanded, full-admit tokens excluded since full carries them).
type hostInboundScopeState struct {
	full   bool
	tokens map[string]bool
}

// hostInboundScopeStates returns every scope's effective state: "zone:<name>"
// for the zone-level stanza plus "zone:<name>|iface:<canonical-ref>" for each
// member or overridden interface, where an override REPLACES the zone level
// (#6515). Refs are canonicalized via SplitInterfaceUnitRef so alias spellings
// compare stably across configs. Lifeline interfaces are skipped (mirroring
// the view builders). The zone-level scope is emitted ONLY where the zone
// token is effective — i.e. some non-lifeline member has no applicable
// override (exact unit match or bare-physical covering the unit). A zone
// whose members are all override-covered enforces nothing at zone level, so
// narrowing the zone stanza there is not a transition.
func hostInboundScopeStates(cfg *config.Config) map[string]hostInboundScopeState {
	out := map[string]hostInboundScopeState{}
	if cfg == nil {
		return out
	}
	lifelines := config.HostInboundLifelineSet(cfg)
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
		type cand struct {
			literal string
			base    string
			hasUnit bool
		}
		candidates := map[string]cand{}
		for _, ref := range zone.Interfaces {
			if ref == "" || config.HostInboundLifelineInterface(ref, lifelines) {
				continue
			}
			split := cfg.SplitInterfaceUnitRef(ref)
			candidates[split.Literal] = cand{literal: split.Literal, base: split.Base, hasUnit: split.HasUnit}
		}
		overrides := map[string]*config.HostInboundTraffic{}
		for ref, override := range zone.InterfaceHostInbound {
			if ref == "" || override == nil {
				continue
			}
			if config.HostInboundLifelineInterface(ref, lifelines) {
				continue
			}
			split := cfg.SplitInterfaceUnitRef(ref)
			candidates[split.Literal] = cand{literal: split.Literal, base: split.Base, hasUnit: split.HasUnit}
			overrides[split.Literal] = override
			if !split.HasUnit {
				overrides["bare:"+split.Base] = override
			}
		}
		effective := func(literal string) *config.HostInboundTraffic {
			if override, ok := overrides[literal]; ok {
				return override
			}
			if c, ok := candidates[literal]; ok && c.hasUnit {
				if override, ok := overrides["bare:"+c.base]; ok {
					return override
				}
			}
			return zone.HostInboundTraffic
		}
		// Zone-level scope: emitted only if some candidate enforces the zone
		// stanza itself (no applicable override).
		zoneCovers := false
		for literal := range candidates {
			if effective(literal) == zone.HostInboundTraffic {
				zoneCovers = true
				break
			}
		}
		if zoneCovers {
			out["zone:"+name] = hostInboundScopeTokens(zone.HostInboundTraffic)
		}
		for literal := range candidates {
			out["zone:"+name+"|iface:"+literal] = hostInboundScopeTokens(effective(literal))
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

// hostInboundZonesForAddrs10752 maps box addresses to the zones whose OLD
// views own them (lifeline-excluded, quarantine-aware — the actual prior
// enforcement sets). Kept flows can only have been stranded by transitions
// in these zones.
func hostInboundZonesForAddrs10752(views []dpuserspace.ZoneHostInboundView, addrs []netip.Addr) map[string]bool {
	zones := map[string]bool{}
	byAddr := map[netip.Addr][]string{}
	for _, v := range views {
		for _, raw := range append(append([]string(nil), v.V4Addrs...), v.V6Addrs...) {
			ip, err := netip.ParseAddr(raw)
			if err != nil {
				continue
			}
			byAddr[ip.Unmap()] = append(byAddr[ip.Unmap()], v.Zone)
		}
	}
	for _, addr := range addrs {
		for _, zone := range byAddr[addr.Unmap()] {
			zones[zone] = true
		}
	}
	return zones
}

// withTighteningWarningsForResponse10752 returns the config object a commit
// response projects: respCfg itself unless this attempt both narrowed a scope
// AND observed stranded box-oriented flows for an address in a narrowed
// zone, in which case a shallow copy carrying the aggregated warning line(s).
// The copy shares every sub-object (read-only post-commit) but owns its
// Warnings storage — the applied original is never mutated. At most two
// lines (customs, exempt/bare), each naming only narrowed scopes in zones
// containing stranded flows — a zone-B residual never names a zone-A
// tightening.
func (d *Daemon) withTighteningWarningsForResponse10752(respCfg, oldActive, compiled *config.Config) *config.Config {
	if respCfg == nil {
		return respCfg
	}
	scopes := hostInboundTightenedScopes(oldActive, compiled)
	if len(scopes) == 0 {
		return respCfg
	}
	custom, customSamples, other, otherSamples, addrs := d.stashedKeptSuspicious10752()
	if custom+other == 0 || len(addrs) == 0 {
		return respCfg
	}
	keptZones := hostInboundZonesForAddrs10752(dpuserspace.BuildZoneHostInboundViews(oldActive), addrs)
	var named []string
	for _, scope := range scopes {
		zone := strings.TrimPrefix(scope, "zone:")
		if i := strings.IndexByte(zone, '|'); i >= 0 {
			zone = zone[:i]
		}
		if keptZones[zone] {
			named = append(named, scope)
		}
	}
	if len(named) == 0 {
		return respCfg
	}
	scopeText := strings.Join(named, ", ")
	if len(named) > 4 {
		scopeText = strings.Join(named[:4], ", ") + fmt.Sprintf(" (+%d more)", len(named)-4)
	}
	var lines []string
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
	out := *respCfg
	warnings := make([]string, 0, len(respCfg.Warnings)+len(lines))
	warnings = append(warnings, respCfg.Warnings...)
	warnings = append(warnings, lines...)
	out.Warnings = warnings
	return &out
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
