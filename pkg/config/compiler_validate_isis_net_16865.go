package config

// #16865: IS-IS NET derivation from `family iso address` and the
// missing-NET gate.
//
// Junos has no `protocols isis net` statement: the NET lives on an
// interface (preferably lo0) as `family iso address <NET>`. xpf only
// read its own `protocols isis net` leaf, so a Junos IS-IS config
// rendered `router isis xpf` with no `net` line — isisd had no
// system-id/area, formed no adjacency and originated no LSP, behind a
// green commit.
//
// Derivation (resolveISISNETFromISO16865, P5): when an IS-IS scope
// carries no explicit NET, the first valid NET on lo0 (any unit,
// lowest unit first) supplies it; a non-lo0 interface is the fallback
// (Junos permits a NET on any interface). An explicit NET always wins.
// A distinct second NET is left for the strict gate to reject.
//
// Gate (validateISISNETPresenceStrict): an enabled IS-IS scope with
// at least one enabled interface but no derivable NET is rejected at
// strict commit; on tolerant load it warns and the FRR renderer
// withholds the whole stanza (no `router isis`, no interface
// enrolment) so a NET-less process is never activated.

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"
)

// isoNETCandidates16865 returns every distinct `family iso address`
// value in cfg, lo0 first (lowest unit first), then other interfaces
// in name/unit order. Duplicates collapse.
func isoNETCandidates16865(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	add := func(v string) {
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}
	collect := func(ifc *InterfaceConfig) {
		if ifc == nil {
			return
		}
		nums := make([]int, 0, len(ifc.Units))
		for n := range ifc.Units {
			nums = append(nums, n)
		}
		sort.Ints(nums)
		for _, n := range nums {
			u := ifc.Units[n]
			if u == nil {
				continue
			}
			for _, v := range u.ISOAddresses {
				add(v)
			}
		}
	}
	collect(cfg.Interfaces.Interfaces["lo0"])
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		if name != "lo0" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		collect(cfg.Interfaces.Interfaces[name])
	}
	return out
}

// resolveISISNETFromISO16865 fills an empty ISISConfig.NET from the
// interface ISO addresses. Explicit NET wins; otherwise the first
// valid candidate wins. Invalid candidates are skipped here — the
// strict gate names them. Runs in P5 (resolveDerivedConfig) so every
// later gate and the renderer see the derived value.
func resolveISISNETFromISO16865(cfg *Config) {
	if cfg == nil {
		return
	}
	candidates := isoNETCandidates16865(cfg)
	if len(candidates) == 0 {
		return
	}
	derive := func(isis *ISISConfig) {
		if isis == nil || isis.NET != "" {
			return
		}
		for _, c := range candidates {
			if ValidISISNET(c) {
				isis.NET = c
				return
			}
		}
	}
	derive(cfg.Protocols.ISIS)
	for _, ri := range cfg.RoutingInstances {
		if ri != nil {
			derive(ri.ISIS)
		}
	}
}

// isisEnabledInterfaces16865 counts interfaces that would render an
// enrolment: non-nil, not disabled. A disabled protocol renders
// nothing and needs no NET.
func isisEnabledInterfaces16865(isis *ISISConfig) int {
	if isis == nil || isis.Disable {
		return 0
	}
	n := 0
	for _, iface := range isis.Interfaces {
		if iface != nil && !iface.Disable {
			n++
		}
	}
	return n
}

// validateISISNETPresenceStrict rejects (strict) or warns (lenient) an
// enabled IS-IS scope that has interfaces but no usable NET. It also
// rejects conflicting NET sources: an explicit NET that disagrees
// with a lo0 ISO NET, or two distinct valid ISO NETs with no explicit
// NET to arbitrate.
func validateISISNETPresenceStrict(cfg *Config, lenient bool) ([]string, error) {
	if cfg == nil {
		return nil, nil
	}
	var warnings []string
	candidates := isoNETCandidates16865(cfg)
	var validCandidates []string
	var invalidCandidates []string
	for _, c := range candidates {
		if ValidISISNET(c) {
			validCandidates = append(validCandidates, c)
		} else {
			invalidCandidates = append(invalidCandidates, c)
		}
	}
	report := func(msg string) error {
		if lenient {
			slog.Warn("config: IS-IS NET problem (#16865)", "detail", msg)
			warnings = append(warnings, msg)
			return nil
		}
		return fmt.Errorf("%s", msg)
	}
	check := func(scope string, isis *ISISConfig) error {
		if isis == nil || isis.Disable {
			return nil
		}
		if isisEnabledInterfaces16865(isis) == 0 {
			return nil
		}
		// Conflicting sources are ambiguous even when one would win.
		if isis.NET != "" {
			for _, c := range validCandidates {
				if c != isis.NET {
					return report(fmt.Sprintf("%s: IS-IS NET conflict — `protocols isis net %s` disagrees with `family iso address %s`; configure exactly one NET (#16865)", scope, isis.NET, c))
				}
			}
		} else if len(validCandidates) > 1 {
			return report(fmt.Sprintf("%s: multiple distinct IS-IS NETs in `family iso address` (%s); configure exactly one NET, or set `protocols isis net` explicitly (#16865)", scope, strings.Join(validCandidates, ", ")))
		}
		if isis.NET == "" {
			if len(invalidCandidates) > 0 && len(validCandidates) == 0 {
				return report(fmt.Sprintf("%s: `family iso address %s` is not a valid IS-IS NET (hex octets in dot-separated groups, 8 to 20 octets, e.g. 49.0001.0100.0000.0001.00); IS-IS has no NET and cannot form adjacencies — fix the ISO address or set `protocols isis net` (#16865)", scope, invalidCandidates[0]))
			}
			return report(fmt.Sprintf("%s: IS-IS is configured with interfaces but no NET — Junos carries the NET as `interfaces lo0 unit 0 family iso address <NET>` (or set `protocols isis net <NET>`); without a NET isisd has no system-id, forms no adjacency and originates no LSP (#16865)", scope))
		}
		if !ValidISISNET(isis.NET) {
			// The schema validator and the renderer belt already cover
			// the explicit leaf; a hand-built config reaches here.
			return report(fmt.Sprintf("%s: IS-IS NET %q is not a valid NET (hex octets in dot-separated groups, 8 to 20 octets, e.g. 49.0001.0100.0000.0001.00) (#16865)", scope, isis.NET))
		}
		return nil
	}
	if err := check("protocols isis", cfg.Protocols.ISIS); err != nil {
		return warnings, err
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		if err := check(fmt.Sprintf("routing-instance %q protocols isis", ri.Name), ri.ISIS); err != nil {
			return warnings, err
		}
	}
	return warnings, nil
}
