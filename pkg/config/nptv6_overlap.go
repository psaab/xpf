package config

import (
	"fmt"
	"net"
)

// NPTv6OverlapConflict reports the first cross-rule NPTv6 prefix overlap that
// `Nptv6State::try_from_snapshots` would REJECT, or "" when the helper would
// accept the whole set (#7078, closing the residual named in
// pkg/dataplane/compiler_validate_4960.go).
//
// It is the single source of truth for "would the helper refuse this rule set
// for overlap", in the same role NPTv6ScopeUnsupported plays for "does this rule
// reach the helper at all". Both the #4960 pre-pass and any future caller read
// one answer, so Go and Rust cannot drift on a rejection whose whole purpose is
// to predict the other side's verdict.
//
// # Why validateNPTv6Strict's overlap check could not be reused
//
// That one exists and is older, but its `seenPrefix` carries only
// `{net, ones, ruleSetName, ruleName}` — NO zone. The helper partitions by zone
// scope (#5176): `find_overlap` gates every candidate on `zones_conflict`, and
// two DISTINCT non-empty `from zone` scopes are disjoint, because a packet
// carries exactly one relevant zone. Reusing the unpartitioned check as the
// pre-pass would hard-fail split-horizon configurations the helper installs
// happily — converting a working apply into a failed one, which is the exact
// over-rejection the #4960 guard's three properties exist to prevent.
//
// # Mirroring the helper
//
//   - Two INDEPENDENT seen-sets, internal and external, because outbound matches
//     on the internal prefix and inbound on the external one. A collision
//     between an internal and an external prefix is not an overlap.
//   - Overlap is a common-prefix match at the SHORTER length
//     (`candidate[..common] == prefix[..common]` over `min(candidate_words,
//     words)`), not equality — a /48 and a /64 beneath it DO collide.
//   - Gated on zonesConflictNPTv6, mirroring `zones_conflict`.
//   - Rules the snapshot builder DROPS are skipped: an excluded rule never
//     reaches try_from_snapshots, so it cannot participate in a rejection the
//     helper makes. This is the same property-1 gate the parse class uses.
//   - Rules whose prefixes do not parse are skipped, because the helper rejects
//     those on the parse arm BEFORE it ever calls find_overlap. Reporting them
//     as overlaps would name the wrong reason for a correct rejection.
func NPTv6OverlapConflict(cfg *Config) string {
	if cfg == nil {
		return ""
	}
	var internalSeen, externalSeen []nptv6Seen

	// Config order, deliberately: Security.NAT.Static is a SLICE, and the helper
	// walks the snapshot in the order the builder emitted it. Which of an
	// overlapping PAIR is named as "already seen" depends on that order, so
	// walking the slice as-is reproduces the helper's choice rather than
	// inventing a different one.
	for _, rs := range cfg.Security.NAT.Static {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil {
				continue
			}
			if rule.Then == "" || rule.Match == "" {
				continue // not an NPTv6 rule
			}
			// Dropped by the snapshot builder — unsupported scope (#5818) or
			// unknown match leaves (#9877) — never reaches the helper, so it
			// can neither report nor trigger an overlap.
			if NPTv6ScopeUnsupported(rs, rule) || StaticNATRuleExcludedReason(rule) != "" {
				continue
			}
			extWords, extN, extOK := nptv6PrefixWords(rule.Match)
			intWords, intN, intOK := nptv6PrefixWords(rule.Then)
			if !extOK || !intOK || extN != intN {
				// The helper refuses these on its parse / length arm first.
				continue
			}
			if prev := nptv6FindOverlap(externalSeen, extWords, extN, rs.FromZone); prev != "" {
				return fmt.Sprintf("rule-set %q rule %q external prefix %q overlaps %s",
					rs.Name, rule.Name, rule.Match, prev)
			}
			if prev := nptv6FindOverlap(internalSeen, intWords, intN, rs.FromZone); prev != "" {
				return fmt.Sprintf("rule-set %q rule %q nptv6-prefix %q overlaps %s",
					rs.Name, rule.Name, rule.Then, prev)
			}
			externalSeen = append(externalSeen, nptv6Seen{extWords, extN, rs.Name, rule.Name, rs.FromZone})
			internalSeen = append(internalSeen, nptv6Seen{intWords, intN, rs.Name, rule.Name, rs.FromZone})
		}
	}
	return ""
}

// nptv6Seen is one already-admitted prefix, carrying the zone the helper's
// `find_overlap` gates on. The zone is the field validateNPTv6Strict's
// equivalent lacks, and its absence there is why that check could not be reused.
type nptv6Seen struct {
	words    [4]uint16
	n        int
	ruleSet  string
	rule     string
	fromZone string
}

// nptv6FindOverlap mirrors userspace-dp/src/nptv6.rs `find_overlap`.
func nptv6FindOverlap(seenList []nptv6Seen, candidate [4]uint16, candidateWords int, candidateZone string) string {
	for _, s := range seenList {
		common := candidateWords
		if s.n < common {
			common = s.n
		}
		match := true
		for i := 0; i < common; i++ {
			if candidate[i] != s.words[i] {
				match = false
				break
			}
		}
		if match && zonesConflictNPTv6(candidateZone, s.fromZone) {
			return fmt.Sprintf("rule-set %q rule %q", s.ruleSet, s.rule)
		}
	}
	return ""
}

// zonesConflictNPTv6 mirrors `zones_conflict`: a packet carries exactly one
// relevant zone, so two scopes conflict only when either is a wildcard (empty)
// or both name the same zone. Two distinct non-empty zones are disjoint —
// legitimate split-horizon (#5176).
func zonesConflictNPTv6(a, b string) bool {
	return a == "" || b == "" || a == b
}

// nptv6PrefixWords parses an NPTv6 prefix into the helper's [u16; 4] + word
// count. NPTv6 supports /48 and /64 only, both multiples of 16, so a word
// comparison is exactly a bit comparison.
func nptv6PrefixWords(s string) ([4]uint16, int, bool) {
	var out [4]uint16
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		return out, 0, false
	}
	ip := n.IP.To16()
	if ip == nil {
		return out, 0, false
	}
	ones, _ := n.Mask.Size()
	if ones != 48 && ones != 64 {
		return out, 0, false
	}
	for i := 0; i < 4; i++ {
		out[i] = uint16(ip[i*2])<<8 | uint16(ip[i*2+1])
	}
	return out, ones / 16, true
}
