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
// It reports the FIRST offending token with its full path. The leaf is
// multi-valued and a term can carry several protocols, so naming the term alone
// would leave the operator grepping.
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
						"(connected), static, ospf, ospf6, bgp, rip, ripng, isis, kernel",
					stmtName, term.Name, proto)
			}
		}
	}
	return nil
}
