package config

import (
	"fmt"
	"sort"
)

// validateRoutingPolicyProtocolsStrict rejects a `policy-options
// policy-statement <p> term <t> from protocol <tok>` naming a protocol the FRR
// renderer cannot emit (#7121).
//
// Why a hard reject rather than a warning: the token is rendered verbatim as
// ` match source-protocol <tok>`, FRR rejects an unknown one, and a single
// rejected line degrades the WHOLE managed reload (#1880/#2223). The blast
// radius of one typo is the managed FRR section, not the one policy — the same
// reasoning that makes the identically-spelled firewall-filter leaf a strict
// reject via filterProtocolResolvable.
//
// Strict on commit / commit-check. The tolerant load / peer-sync paths
// downgrade this to a warning and poison the offending term instead
// (#16577, #1960 no-brick): the term is forced to reject and renders as a
// bare deny with no `match source-protocol` line (see
// failClosedRoutingPolicyProtocols16577), so a persisted or peer-synced
// config carrying a Junos token FRR cannot emit — `aggregate`, `local`,
// `access-internal`, a typo — still boots rather than failing Store.Load
// into the bootstrap/lifeline state. Junos `ospf3`/`ospf2` do NOT reach
// this gate: FRRRoutingProtocolKeyword aliases them to ospf6/ospf, so
// they strict-commit as OSPFv3/OSPFv2.
//
// It reports the FIRST offending token with its full path. The leaf is
// multi-valued and a term can carry several protocols, so naming the term
// alone would leave the operator grepping.
func validateRoutingPolicyProtocolsStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	names := make([]string, 0, len(cfg.PolicyOptions.PolicyStatements))
	for name := range cfg.PolicyOptions.PolicyStatements {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, stmtName := range names {
		stmt := cfg.PolicyOptions.PolicyStatements[stmtName]
		if stmt == nil {
			continue
		}
		for _, term := range stmt.Terms {
			if term == nil {
				continue
			}
			for _, proto := range term.FromProtocols {
				if RoutingProtocolResolvable(proto) {
					continue
				}
				return fmt.Errorf(
					"policy-options policy-statement %q term %q: `from protocol %s` is not a "+
						"routing protocol this dataplane can match; FRR rejects an unknown "+
						"source-protocol, and ONE rejected line fails the whole managed FRR "+
						"reload: stale routing config stops being removed for every protocol, "+
						"not just this policy (#1880/#2223). Valid: direct "+
						"(connected), static, ospf (ospf2), ospf6 (ospf3), bgp, rip, ripng, isis, kernel",
					stmtName, term.Name, proto)
			}
		}
	}
	return nil
}

// failClosedRoutingPolicyProtocols16577 poisons every routing-policy term
// carrying a `from protocol` token the FRR renderer cannot emit, for the
// tolerant load / peer-sync paths (#16577). It mirrors
// failClosedUnknownPolicyFrom11779: the term is forced to `reject` and its
// NextPolicy jump is cleared, so the renderer emits a bare deny sequence
// with no `match source-protocol` line for it — the unknown token never
// reaches FRR (one rejected line would degrade the whole managed reload,
// #1880/#2223) and the term never widens to its authored accept. Only the
// offending terms are poisoned; sibling terms with resolvable protocols
// keep their authored action.
func failClosedRoutingPolicyProtocols16577(cfg *Config) {
	if cfg == nil {
		return
	}
	for _, stmt := range cfg.PolicyOptions.PolicyStatements {
		if stmt == nil {
			continue
		}
		for _, term := range stmt.Terms {
			if term == nil {
				continue
			}
			for _, proto := range term.FromProtocols {
				if !RoutingProtocolResolvable(proto) {
					term.NextPolicy = false
					term.Action = "reject"
					break
				}
			}
		}
	}
}
