package daemon

import (
	"fmt"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// host_inbound_tightening_warn_10752.go projects the any-service→named
// tightening risk into commit output (#10752 round 4).
//
// The dangerous order is a transition: a zone/interface whose effective
// host-inbound set was a packet-wide full-admit (`any-service`) now admits a
// named set, while pre-existing box-oriented custom-port flows keep riding
// the broad reply accept. Commit-time ValidateConfig sees only the NEW
// config, so it cannot observe the transition — and the any-service breadth
// advisory fires only while the stanza is still open. This file closes that
// gap at the one funnel that holds old and new together:
// applyAndSyncCommittedWithPeerSnapshotAuthorization (oldActive + compiled).
//
// Firing requires BOTH a lost full-admit scope AND stranded-flow evidence
// observed by this attempt's own conntrack sweep (stashed by
// flushDeniedHostInboundConntrack, cleared per attempt). Transition-only
// would warn routine restrictions with zero stale flows; evidence-only would
// warn steady-state explicit-bind clients on unrelated commits.
//
// Projection mirrors the #9841 MTU discipline exactly: response-only shallow
// copy owning fresh Warnings storage (the applied original is never
// mutated — snapshot readers race with nothing), committed digest untouched
// (warnings participate in neither identity nor diff), and failed applies
// project nothing.

// keptSuspiciousApplyReport is one flush sweep's kept-suspicious evidence.
type keptSuspiciousApplyReport struct {
	kept    uint64
	samples []string
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
func (d *Daemon) recordKeptSuspicious10752(kept uint64, samples []string) {
	d.keptSuspiciousMu.Lock()
	defer d.keptSuspiciousMu.Unlock()
	d.keptSuspiciousStash = &keptSuspiciousApplyReport{kept: kept, samples: samples}
}

// stashedKeptSuspicious10752 returns the current attempt's evidence, if any.
func (d *Daemon) stashedKeptSuspicious10752() (uint64, []string) {
	d.keptSuspiciousMu.Lock()
	defer d.keptSuspiciousMu.Unlock()
	if d.keptSuspiciousStash == nil {
		return 0, nil
	}
	return d.keptSuspiciousStash.kept, d.keptSuspiciousStash.samples
}

// hostInboundFullAdmitScopes returns the scope keys whose EFFECTIVE
// host-inbound set is a packet-wide full-admit: "zone:<name>" for the
// zone-level stanza plus "zone:<name>|iface:<ref>" for each member or
// overridden interface, where an override REPLACES the zone level (#6515).
// Lifeline interfaces are skipped (mirroring the view builders), as are
// zones with no enforceable scope. Deterministic sorted output.
//
// This deliberately uses DECLARED refs rather than the full
// ResolveInterfaceHostInbound physical→unit expansion: aliasing edge cases
// resolve conservatively (a lost full-admit key fires) and the evidence gate
// (actual stranded flows observed this attempt) keeps precision.
func hostInboundFullAdmitScopes(cfg *config.Config) map[string]bool {
	out := map[string]bool{}
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
		zoneFull := hostInboundTokensFullAdmit(zone.HostInboundTraffic)
		hasEnforceable := false
		for _, ref := range zone.Interfaces {
			if config.HostInboundLifelineInterface(ref, lifelines) {
				continue
			}
			hasEnforceable = true
			effective := zone.HostInboundTraffic
			if override := zone.InterfaceHostInbound[ref]; override != nil {
				effective = override
			}
			if hostInboundTokensFullAdmit(effective) {
				out["zone:"+name+"|iface:"+ref] = true
			}
		}
		for ref, override := range zone.InterfaceHostInbound {
			if ref == "" || override == nil {
				continue
			}
			if config.HostInboundLifelineInterface(ref, lifelines) {
				continue
			}
			hasEnforceable = true
			if hostInboundTokensFullAdmit(override) {
				out["zone:"+name+"|iface:"+ref] = true
			}
		}
		if hasEnforceable && zoneFull {
			out["zone:"+name] = true
		}
	}
	return out
}

func hostInboundTokensFullAdmit(hi *config.HostInboundTraffic) bool {
	if hi == nil {
		return false
	}
	for _, svc := range hi.SystemServices {
		if config.HostInboundFullAdmitService(svc) {
			return true
		}
	}
	return false
}

// hostInboundTightenedFullAdmitScopes returns the sorted scope keys that lost
// packet-wide full-admit status from old to new (narrowing, override
// replacement, or zone/scope deletion). Nil old (first commit) yields nil:
// nothing was tightened from.
func hostInboundTightenedFullAdmitScopes(oldCfg, newCfg *config.Config) []string {
	if oldCfg == nil || newCfg == nil {
		return nil
	}
	oldFull := hostInboundFullAdmitScopes(oldCfg)
	if len(oldFull) == 0 {
		return nil
	}
	newFull := hostInboundFullAdmitScopes(newCfg)
	var out []string
	for scope := range oldFull {
		if !newFull[scope] {
			out = append(out, scope)
		}
	}
	sort.Strings(out)
	return out
}

// withTighteningWarningsForResponse10752 returns the config object a commit
// response projects: respCfg itself unless this attempt both tightened a
// full-admit scope AND observed stranded box-oriented custom-port flows, in
// which case a shallow copy carrying one aggregated warning. The copy shares
// every sub-object (read-only post-commit) but owns its Warnings storage —
// the applied original is never mutated. ONE aggregated line per commit, not
// one per scope (same rationale as the #7949 tunnel advisory: per-item lines
// train operators to filter).
func (d *Daemon) withTighteningWarningsForResponse10752(respCfg, oldActive, compiled *config.Config) *config.Config {
	if respCfg == nil {
		return respCfg
	}
	scopes := hostInboundTightenedFullAdmitScopes(oldActive, compiled)
	if len(scopes) == 0 {
		return respCfg
	}
	kept, samples := d.stashedKeptSuspicious10752()
	if kept == 0 {
		return respCfg
	}
	sampleText := ""
	if len(samples) > 0 {
		shown := samples
		if len(shown) > 2 {
			shown = shown[:2]
		}
		sampleText = fmt.Sprintf(" (e.g. %s)", strings.Join(shown, ", "))
	}
	out := *respCfg
	lines := make([]string, 0, len(respCfg.Warnings)+1)
	lines = append(lines, respCfg.Warnings...)
	lines = append(lines, fmt.Sprintf(
		"host-inbound tightening (%s) stranded %d box-oriented custom-port flow(s) still authorized under the prior any-service admit%s; "+
			"delete per the non-catalog TCP HIGH-residual procedure in docs/host-inbound-service-matrix.md (kept flows ride the reply accept until close/idle-timeout)",
		strings.Join(scopes, ", "), kept, sampleText))
	out.Warnings = lines
	return &out
}
