package config

import (
	"fmt"
	"sort"
	"strings"
)

// validateNATMatchAddressLiteralsStrict (#7145) hard-rejects a NAT rule whose
// literal `match source-address` / `match destination-address` carries a value
// the dataplane cannot parse.
//
// THE DEFECT IT CLOSES IS AN ASYMMETRY, not a missing check in the abstract.
// Measured at bf10c6b7c over a base config that commits clean, `999.1.1.1/24`
// (and `zznotanaddr`, so this is not a near-miss in the CIDR grammar) landed
// on six (NAT kind x match leaf) slots with four different verdicts:
//
//	security nat source      rule-set RS rule R1 match source-address       ACCEPTED
//	security nat source      rule-set RS rule R1 match destination-address  ACCEPTED
//	security nat destination rule-set RD rule R1 match source-address       ACCEPTED
//	security nat destination rule-set RD rule R1 match destination-address  rejected (#3228)
//	security nat static      rule-set RT rule R1 match source-address       ACCEPTED
//	security nat static      rule-set RT rule R1 match destination-address  rejected (#3206)
//
// The same operator typo was refused in one slot of a rule and accepted in the
// sibling slot of the SAME rule. This gate covers the four accepting slots; the
// two already-rejecting slots keep their own (older, differently-worded) gates,
// which is why this walks only the four — a second complaint about a value
// already rejected would just reorder which message the operator sees.
//
// WHAT THE SILENT ACCEPT COSTS. These values are not inert. The Go snapshot
// builders copy the configured list to the wire WITHOUT filtering
// (pkg/dataplane/userspace/nat_source.go, nat_destination.go, nat_static.go)
// and each Rust consumer parses per entry, dropping what it cannot parse while
// recording only a bounded NAT parse-error counter (#4718):
//
//   - source NAT:      parse_match_prefix       (userspace-dp/src/nat/source.rs)
//   - destination NAT: DnatTable::from_snapshots (nat/destination.rs)
//   - static NAT:      SourceConstraint::from_list (nat/static_nat.rs)
//
// The `*_constrained` flag is keyed on the SNAPSHOT list being non-empty, not
// on how many entries parsed. So a malformed entry beside good ones NARROWS the
// rule below what was authored, and an all-malformed list leaves the rule
// constrained with zero prefixes — it matches NOTHING and stops translating.
// That fail-closed runtime posture is correct and is deliberately preserved
// (see the lenient note below); what was wrong is that the operator boundary was
// silent about a value the dataplane cannot use, while the sibling slot in the
// same rule was not.
//
// SCOPE: literal values only. `match source-address-name` / `match
// destination-address-name` are address-BOOK references and are validated by
// validateNATSourceAddressNameReferencesStrict; the snapshot builders append an
// unresolvable name's RAW token to the same wire list on purpose, as a
// fail-closed backstop (appendNATSourceAddressName), so this gate must never
// walk the post-resolution list — only the config leaf the operator authored.
//
// Strict on commit / commit-check (hard reject naming the NAT kind, rule-set,
// rule, match leaf, and the offending value); lenient on load / peer-sync
// (warn — #1960 no-brick). The lenient path warns and leaves the value in the
// compiled config ON PURPOSE. Dropping the entry Go-side would empty an
// all-malformed list, clear `*_constrained`, and collapse the rule back to
// MATCH-ANY — turning a fail-closed silent break into a fail-OPEN one (the
// exact regression the nat_destination.go #2416 comment warns about). Warn,
// keep the entry, let the dataplane drop it: the leniently-loaded config boots
// and forwards, and behaves exactly as it did before this gate existed.
func validateNATMatchAddressLiteralsStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	// Reported deterministically: rule-sets are walked in sorted name order,
	// rules in their configured order, and within a rule source-address before
	// destination-address — so the first-reported offender is stable across
	// runs and across the map-ordered scope expansion. Mirrors
	// validateDestinationNATAddressesStrict.
	check := func(kind, ruleSet, rule, leaf string, values []string) error {
		for _, raw := range values {
			if natMatchPrefixParses(raw) {
				continue
			}
			axis := "source"
			if leaf == "destination-address" {
				axis = "destination"
			}
			return fmt.Errorf(
				"%s rule-set %q rule %q: match %s %q is not a valid IP address or "+
					"CIDR prefix; the rule would commit but the dataplane cannot parse "+
					"the value and drops it from the %s match set (recorded only as a "+
					"NAT parse-error counter), so the rule matches a NARROWER set than "+
					"authored — and because the match list is still non-empty the rule "+
					"stays constrained, so a list whose values are ALL malformed matches "+
					"NOTHING and the rule silently translates no traffic (full list: %s)",
				kind, ruleSet, rule, leaf, raw, axis, strings.Join(values, ", "))
		}
		return nil
	}

	for _, rs := range sortedNATRuleSetsByName(cfg.Security.NAT.Source) {
		for _, rule := range rs.Rules {
			if rule == nil {
				continue
			}
			if err := check("source-nat", rs.Name, rule.Name, "source-address",
				natMatchValues(rule.Match.SourceAddresses, rule.Match.SourceAddress)); err != nil {
				return err
			}
			if err := check("source-nat", rs.Name, rule.Name, "destination-address",
				natMatchValues(rule.Match.DestinationAddresses, rule.Match.DestinationAddress)); err != nil {
				return err
			}
		}
	}

	if cfg.Security.NAT.Destination != nil {
		for _, rs := range sortedNATRuleSetsByName(cfg.Security.NAT.Destination.RuleSets) {
			for _, rule := range rs.Rules {
				if rule == nil {
					continue
				}
				// destination-address on this kind is validateDestination-
				// NATAddressesStrict's (#3228); only the source side is new.
				if err := check("destination-nat", rs.Name, rule.Name, "source-address",
					natMatchValues(rule.Match.SourceAddresses, rule.Match.SourceAddress)); err != nil {
					return err
				}
			}
		}
	}

	staticSets := append([]*StaticNATRuleSet(nil), cfg.Security.NAT.Static...)
	sort.SliceStable(staticSets, func(i, j int) bool {
		if staticSets[i] == nil || staticSets[j] == nil {
			return staticSets[i] != nil
		}
		return staticSets[i].Name < staticSets[j].Name
	})
	for _, rs := range staticSets {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil {
				continue
			}
			// destination-address on this kind is the #3206 arm of
			// validateNATHostMaskStrict; only the source side is new.
			if err := check("static-nat", rs.Name, rule.Name, "source-address",
				natMatchValues(rule.SourceAddresses, rule.SourceAddress)); err != nil {
				return err
			}
		}
	}
	return nil
}

// sortedNATRuleSetsByName returns a name-sorted copy of a NAT rule-set slice
// with the nil entries dropped, so a gate's first-reported offender does not
// depend on the map-ordered scope expansion that produced the slice. Stable, so
// the several rule-sets a multi-scope stanza expands into keep their relative
// order.
func sortedNATRuleSetsByName(in []*NATRuleSet) []*NATRuleSet {
	out := make([]*NATRuleSet, 0, len(in))
	for _, rs := range in {
		if rs != nil {
			out = append(out, rs)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
