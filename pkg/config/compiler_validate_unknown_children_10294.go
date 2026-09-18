package config

import "fmt"

// validateFirewallUnknownChildrenStrict closes the remaining TERM-level
// open-world paths in #10294. compileFirewall records direct term-body
// children other than `from` and `then`; compileNATSource records unknown
// children under the source-NAT action. The caller downgrades the same
// findings to warnings on tolerant load/peer-sync (#1960).
func validateFirewallUnknownChildrenStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	checkFilters := func(family string, filters map[string]*FirewallFilter) error {
		for name, filter := range filters {
			if filter == nil {
				continue
			}
			for _, term := range filter.Terms {
				if term == nil || len(term.unknownChildren) == 0 {
					continue
				}
				return fmt.Errorf(
					"firewall family %s filter %q term %q has unknown child %q at term level (#10294): "+
						"the compiler reads only from and then; remove the typo",
					family, name, term.Name, term.unknownChildren[0])
			}
		}
		return nil
	}
	if err := checkFilters("inet", cfg.Firewall.FiltersInet); err != nil {
		return err
	}
	if err := checkFilters("inet6", cfg.Firewall.FiltersInet6); err != nil {
		return err
	}

	for _, rs := range cfg.Security.NAT.Source {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil || len(rule.unknownThenLeaves) == 0 {
				continue
			}
			return fmt.Errorf(
				"security nat source rule-set %q rule %q has unknown child %q under `then source-nat` (#10294): "+
					"the compiler reads only interface, off, and pool; remove the typo",
					rs.Name, rule.Name, rule.unknownThenLeaves[0])
		}
	}
	return nil
}
