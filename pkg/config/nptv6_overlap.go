package config

import (
	"fmt"
	"net"
)

// NPTv6RuleRef is one NPTv6 rule together with the rule-set identity and the
// builder's membership verdict. Rules excluded by unsupported scope, dropped
// match leaves, or a tolerant undefined zone remain present for validation
// diagnostics, but Installed is false and they cannot participate in helper
// overlap findings.
type NPTv6RuleRef struct {
	RuleSet          *StaticNATRuleSet
	Rule             *StaticNATRule
	Index            int
	Installed        bool
	UndefinedZone    bool
	ScopeUnsupported bool
	ExcludedReason   string
}

// NPTv6Rules returns the canonical ordered NPTv6 rule population. The builder,
// prefix pre-pass, overlap checker, external-prefix validator, and both strict
// validators consume these same references so their IsNPTv6 / exclusion /
// unsupported-scope / #16008 rule-set membership cannot drift.
//
// Every NPTv6 rule is returned, including rules that will not be installed:
// compileNPTv6 and the strict validators still need to diagnose malformed
// prefixes and unsupported scope. Installed is the exact membership decision
// shared with buildNptv6Snapshots and overlap/external-prefix checks.
func NPTv6Rules(cfg *Config) []NPTv6RuleRef {
	if cfg == nil {
		return nil
	}
	var rules []NPTv6RuleRef
	for _, rs := range cfg.Security.NAT.Static {
		if rs == nil {
			continue
		}
		undefinedZone := cfg.LenientNATUndefinedZoneRuleSets[NATRuleSetRef{Kind: "static", Name: rs.Name}]
		for _, rule := range rs.Rules {
			if rule == nil || !rule.IsNPTv6 {
				continue
			}
			excludedReason := StaticNATRuleExcludedReason(rule)
			scopeUnsupported := NPTv6ScopeUnsupported(rs, rule)
			rules = append(rules, NPTv6RuleRef{
				RuleSet:          rs,
				Rule:             rule,
				Index:            len(rules),
				Installed:        !undefinedZone && !scopeUnsupported && excludedReason == "",
				UndefinedZone:    undefinedZone,
				ScopeUnsupported: scopeUnsupported,
				ExcludedReason:   excludedReason,
			})
		}
	}
	return rules
}

// NPTv6OverlapDirection identifies the prefix namespace whose first-match
// lookup would be ambiguous.
type NPTv6OverlapDirection uint8

const (
	NPTv6OverlapInternal NPTv6OverlapDirection = iota + 1
	NPTv6OverlapExternal
)

// NPTv6OverlapFinding is one overlap between two entries in the canonical
// helper population. Identical rule-set/rule names are not a self-skip: two
// emitted snapshots with those names still reach Rust as two entries, and the
// helper rejects an overlapping pair (including an exact duplicate).
type NPTv6OverlapFinding struct {
	Rule      NPTv6RuleRef
	Previous  NPTv6RuleRef
	Direction NPTv6OverlapDirection
}

// NPTv6OverlapFindings is the sole Go overlap engine. It follows snapshot
// order, uses independent internal/outbound and external/inbound namespaces,
// and partitions collisions with the helper's from-zone predicate. The helper
// accepts only /48 and /64 prefixes; those are word-aligned, so comparing the
// first min(prefix-words) 16-bit words is exact. Other lengths (including
// ::/0 and non-word-aligned /63 or /65) are rejected before overlap and are
// deliberately not promoted into this engine.
func NPTv6OverlapFindings(rules []NPTv6RuleRef) []NPTv6OverlapFinding {
	var findings []NPTv6OverlapFinding
	var internalSeen, externalSeen []nptv6Seen
	for _, rule := range rules {
		if !rule.Installed {
			continue
		}
		extWords, extN, extOK := nptv6PrefixWords(rule.Rule.Match)
		intWords, intN, intOK := nptv6PrefixWords(rule.Rule.Then)
		if !extOK || !intOK || extN != intN {
			// Rust rejects malformed, unsupported, mismatched, or host-bits-set
			// prefixes before it reaches find_overlap.
			continue
		}

		overlapFound := false
		if previous, ok := nptv6FindOverlap(internalSeen, intWords, intN, rule.RuleSet.FromZone); ok {
			findings = append(findings, NPTv6OverlapFinding{
				Rule: rule, Previous: previous, Direction: NPTv6OverlapInternal,
			})
			overlapFound = true
		}
		if previous, ok := nptv6FindOverlap(externalSeen, extWords, extN, rule.RuleSet.FromZone); ok {
			findings = append(findings, NPTv6OverlapFinding{
				Rule: rule, Previous: previous, Direction: NPTv6OverlapExternal,
			})
			overlapFound = true
		}
		if overlapFound {
			// Match validateNPTv6Strict's established diagnostic population:
			// an already-overlapping rule is not a baseline for later findings.
			continue
		}
		internalSeen = append(internalSeen, nptv6Seen{words: intWords, n: intN, rule: rule})
		externalSeen = append(externalSeen, nptv6Seen{words: extWords, n: extN, rule: rule})
	}
	return findings
}

// NPTv6OverlapConflict reports the first overlap in the canonical helper
// population, or "" when the Rust helper would accept the prefixes.
func NPTv6OverlapConflict(cfg *Config) string {
	findings := NPTv6OverlapFindings(NPTv6Rules(cfg))
	if len(findings) == 0 {
		return ""
	}
	finding := findings[0]
	return formatNPTv6OverlapConflict(finding)
}

func formatNPTv6OverlapConflict(finding NPTv6OverlapFinding) string {
	rule, previous := finding.Rule, finding.Previous
	if finding.Direction == NPTv6OverlapInternal {
		return fmt.Sprintf("rule-set %q rule %q nptv6-prefix %q overlaps rule-set %q rule %q",
			rule.RuleSet.Name, rule.Rule.Name, rule.Rule.Then,
			previous.RuleSet.Name, previous.Rule.Name)
	}
	return fmt.Sprintf("rule-set %q rule %q external prefix %q overlaps rule-set %q rule %q",
		rule.RuleSet.Name, rule.Rule.Name, rule.Rule.Match,
		previous.RuleSet.Name, previous.Rule.Name)
}

type nptv6Seen struct {
	words [4]uint16
	n     int
	rule  NPTv6RuleRef
}

func nptv6FindOverlap(seenList []nptv6Seen, candidate [4]uint16, candidateWords int, candidateZone string) (NPTv6RuleRef, bool) {
	for _, seen := range seenList {
		common := candidateWords
		if seen.n < common {
			common = seen.n
		}
		match := true
		for i := 0; i < common; i++ {
			if candidate[i] != seen.words[i] {
				match = false
				break
			}
		}
		if match && zonesConflictNPTv6(candidateZone, seen.rule.RuleSet.FromZone) {
			return seen.rule, true
		}
	}
	return NPTv6RuleRef{}, false
}

// zonesConflictNPTv6 mirrors the helper's zones_conflict: two scopes conflict
// when either is a wildcard or both name the same zone.
func zonesConflictNPTv6(a, b string) bool {
	return a == "" || b == "" || a == b
}

// nptv6PrefixWords parses one exact helper-supported prefix. Only /48 and /64
// are accepted; host bits are rejected instead of silently masking the
// operator's input. NPTv6OverlapFindings runs this after the shared membership
// selection, before comparing the word-aligned prefixes.
func nptv6PrefixWords(s string) ([4]uint16, int, bool) {
	var out [4]uint16
	_, network, err := net.ParseCIDR(s)
	if err != nil || network == nil {
		return out, 0, false
	}
	ones, _ := network.Mask.Size()
	if ones != 48 && ones != 64 {
		return out, 0, false
	}
	if natAddrFamily(natCIDRIPPart(s)) != "v6" {
		return out, 0, false
	}
	if hostBits, ok := nptv6PrefixHasHostBits(s, network); !ok || hostBits {
		return out, 0, false
	}
	ip := network.IP.To16()
	if ip == nil {
		return out, 0, false
	}
	for i := 0; i < len(out); i++ {
		out[i] = uint16(ip[i*2])<<8 | uint16(ip[i*2+1])
	}
	return out, ones / 16, true
}
