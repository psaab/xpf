package config

import (
	"fmt"
	"sort"
	"strings"
)

const namelessFirewallSyntheticPrefix17257 = "nameless-term-17257-"

// neutralizePackedNamelessTerms17257 restores terms lost by section lowering
// at the AST-authored ordinal. Existing nameless terms are replaced in place;
// missing terms are inserted before any later named term. A placeholder has
// no match constraints and terminates with discard, so the tolerant recovery is
// fail-closed rather than an accidental accept or a precedence inversion.
func neutralizePackedNamelessTerms17257(cfg *Config, firewallSites []firewallNamelessSite17257, policySites []policyNamelessSite17257) {
	if cfg == nil {
		return
	}
	for _, site := range firewallSites {
		if _, colliding := cfg.Firewall.CollidingNames[site.filter]; colliding {
			continue
		}
		var pools []struct {
			family  string
			filters map[string]*FirewallFilter
		}
		switch site.family {
		case "", "inet":
			pools = append(pools, struct {
				family  string
				filters map[string]*FirewallFilter
			}{"inet", cfg.Firewall.FiltersInet})
		case "inet6":
			pools = append(pools, struct {
				family  string
				filters map[string]*FirewallFilter
			}{"inet6", cfg.Firewall.FiltersInet6})
		case "any":
			pools = append(pools,
				struct {
					family  string
					filters map[string]*FirewallFilter
				}{"inet", cfg.Firewall.FiltersInet},
				struct {
					family  string
					filters map[string]*FirewallFilter
				}{"inet6", cfg.Firewall.FiltersInet6},
			)
		default:
			// Undeclared family tokens are quarantined by compileFirewall.
			continue
		}
		for _, pool := range pools {
			filter := pool.filters[site.filter]
			if filter == nil {
				continue
			}
			index := site.ordinal
			placeholder := &FirewallFilterTerm{
				Name:     firewallNamelessPlaceholderName17257(site.first, site.ordinal, filter.Terms),
				Action:   FilterActionDiscard,
				nameless: true,
			}
			if index < len(filter.Terms) && filter.Terms[index] != nil && filter.Terms[index].nameless {
				filter.Terms[index] = placeholder
				continue
			}
			if index > len(filter.Terms) {
				index = len(filter.Terms)
			}
			filter.Terms = append(filter.Terms, nil)
			copy(filter.Terms[index+1:], filter.Terms[index:])
			filter.Terms[index] = placeholder
		}
	}

	for _, site := range policySites {
		statement := cfg.PolicyOptions.PolicyStatements[site.policy]
		if statement == nil {
			continue
		}
		index := site.ordinal
		placeholder := &PolicyTerm{Name: site.first, nameless: true}
		if index < len(statement.Terms) && statement.Terms[index] != nil && statement.Terms[index].nameless {
			statement.Terms[index] = placeholder
			continue
		}
		if index > len(statement.Terms) {
			index = len(statement.Terms)
		}
		statement.Terms = append(statement.Terms, nil)
		copy(statement.Terms[index+1:], statement.Terms[index:])
		statement.Terms[index] = placeholder
	}
}

func firewallNamelessPlaceholderName17257(first string, ordinal int, terms []*FirewallFilterTerm) string {
	if first != "" {
		return first
	}
	base := fmt.Sprintf("%s%d", namelessFirewallSyntheticPrefix17257, ordinal)
	candidate := base
	for suffix := 1; ; suffix++ {
		used := false
		for _, term := range terms {
			if term != nil && term.Name == candidate {
				used = true
				break
			}
		}
		if !used {
			return candidate
		}
		candidate = fmt.Sprintf("%s-%d", base, suffix)
	}
}

// NamelessTermAlarmWarnings17257 re-derives the nameless-term alarm from
// retained term markers. The active config, not its transient cfg.Warnings,
// is authoritative so the alarm survives show-command recomputation and
// remains present for as long as tolerant compilation retains the marker.
func NamelessTermAlarmWarnings17257(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	var warnings []string
	for _, family := range []struct {
		name    string
		filters map[string]*FirewallFilter
	}{
		{name: "inet", filters: cfg.Firewall.FiltersInet},
		{name: "inet6", filters: cfg.Firewall.FiltersInet6},
	} {
		names := make([]string, 0, len(family.filters))
		for name := range family.filters {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			filter := family.filters[name]
			if filter == nil {
				continue
			}
			for _, term := range filter.Terms {
				if term == nil || !term.nameless {
					continue
				}
				first := term.Name
				if strings.HasPrefix(first, namelessFirewallSyntheticPrefix17257) {
					first = ""
				}
				warnings = append(warnings, firewallNamelessError12526(firewallNamelessSite17257{
					family: family.name, filter: name, first: first,
				}).Error())
			}
		}
	}
	for _, err := range policyNamelessTermErrors12521(cfg) {
		warnings = append(warnings, err.Error())
	}
	for i, warning := range warnings {
		warnings[i] = warning + " (nameless term retained from tolerant compilation)"
	}
	return warnings
}
