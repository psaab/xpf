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
// carries no explicit NET, the first valid NET on that scope's own
// interfaces supplies it — lo0 first. Scope ownership follows
// RoutingInstanceConfig.Interfaces (#16865 F2): the default scope
// owns interfaces claimed by no routing instance, an RI scope owns
// its members; a NET never crosses that boundary. An explicit NET
// always wins. A distinct second in-scope NET is left for the
// strict gate to reject.
//
// Identity comparison is by canonical NET bytes (canonicalNET16865),
// so hex case / dot-grouping spellings of the same NET are one
// identity (#16865 F4); the authored spelling is preserved for
// rendering and diagnostics.
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

// canonicalNET16865 returns the canonical byte identity of a NET:
// dot grouping removed, hex lower-cased. "" for an invalid NET.
func canonicalNET16865(s string) string {
	if !ValidISISNET(s) {
		return ""
	}
	return strings.ToLower(strings.ReplaceAll(s, ".", ""))
}

// isoNETSource16865 is one authored ISO NET with its interface ref.
type isoNETSource16865 struct {
	value string // authored spelling
	ref   string // e.g. "lo0.0"
}

// isoNETSources16865 lists every `family iso address` in cfg in
// deterministic order: lo0 first (lowest unit first), then other
// interfaces in name/unit order.
func isoNETSources16865(cfg *Config) []isoNETSource16865 {
	if cfg == nil {
		return nil
	}
	var out []isoNETSource16865
	collect := func(name string, ifc *InterfaceConfig) {
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
				out = append(out, isoNETSource16865{value: v, ref: fmt.Sprintf("%s.%d", name, n)})
			}
		}
	}
	collect("lo0", cfg.Interfaces.Interfaces["lo0"])
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		if name != "lo0" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		collect(name, cfg.Interfaces.Interfaces[name])
	}
	return out
}

// riOwnedRefs16865 returns the interface refs owned by routing
// instances: member refs themselves plus, for a bare member, every
// unit ref of that interface (Junos per-instance loopback units use
// the bare form).
func riOwnedRefs16865(cfg *Config) map[string]string {
	owned := map[string]string{}
	if cfg == nil {
		return owned
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		for _, m := range ri.Interfaces {
			owned[m] = ri.Name
			if !strings.Contains(m, ".") {
				if ifc := cfg.Interfaces.Interfaces[m]; ifc != nil {
					for n := range ifc.Units {
						owned[fmt.Sprintf("%s.%d", m, n)] = ri.Name
					}
				}
			}
		}
	}
	return owned
}

// isoNETCandidatesForScope16865 returns the distinct (by canonical
// bytes) ISO NETs visible to one scope. instance "" is the default
// scope (interfaces owned by no RI); otherwise only that instance's
// members. First-authored spelling wins per canonical identity.
func isoNETCandidatesForScope16865(cfg *Config, instance string) []isoNETSource16865 {
	owned := riOwnedRefs16865(cfg)
	seen := map[string]bool{}
	var out []isoNETSource16865
	for _, src := range isoNETSources16865(cfg) {
		owner := owned[src.ref]
		if instance == "" {
			if owner != "" {
				continue
			}
		} else if owner != instance {
			continue
		}
		key := canonicalNET16865(src.value)
		if key == "" {
			key = "\x00invalid:" + src.value
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, src)
	}
	return out
}

// resolveISISNETFromISO16865 fills an empty ISISConfig.NET from the
// scope's own interface ISO addresses. Explicit NET wins; otherwise
// the first valid in-scope candidate wins. Invalid candidates are
// skipped here — the strict gate names them. Runs in P5
// (resolveDerivedConfig) so every later gate and the renderer see
// the derived value.
func resolveISISNETFromISO16865(cfg *Config) {
	if cfg == nil {
		return
	}
	derive := func(isis *ISISConfig, instance string) {
		if isis == nil || isis.NET != "" {
			return
		}
		for _, c := range isoNETCandidatesForScope16865(cfg, instance) {
			if ValidISISNET(c.value) {
				isis.NET = c.value
				return
			}
		}
	}
	derive(cfg.Protocols.ISIS, "")
	for _, ri := range cfg.RoutingInstances {
		if ri != nil {
			derive(ri.ISIS, ri.Name)
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
// rejects conflicting in-scope NET sources: an explicit NET that
// disagrees (by canonical bytes) with an in-scope ISO NET, or two
// distinct valid in-scope ISO NETs with no explicit NET to arbitrate.
func validateISISNETPresenceStrict(cfg *Config, lenient bool) ([]string, error) {
	if cfg == nil {
		return nil, nil
	}
	var warnings []string
	report := func(msg string) error {
		if lenient {
			slog.Warn("config: IS-IS NET problem (#16865)", "detail", msg)
			warnings = append(warnings, msg)
			return nil
		}
		return fmt.Errorf("%s", msg)
	}
	check := func(scope string, isis *ISISConfig, instance string) error {
		if isis == nil || isis.Disable {
			return nil
		}
		if isisEnabledInterfaces16865(isis) == 0 {
			return nil
		}
		candidates := isoNETCandidatesForScope16865(cfg, instance)
		var validCandidates, invalidCandidates []isoNETSource16865
		for _, c := range candidates {
			if ValidISISNET(c.value) {
				validCandidates = append(validCandidates, c)
			} else {
				invalidCandidates = append(invalidCandidates, c)
			}
		}
		// Conflicting sources are ambiguous even when one would win.
		if isis.NET != "" {
			if canon := canonicalNET16865(isis.NET); canon != "" {
				for _, c := range validCandidates {
					if canonicalNET16865(c.value) != canon {
						return report(fmt.Sprintf("%s: IS-IS NET conflict — `protocols isis net %s` disagrees with `family iso address %s` on %s; configure exactly one NET (#16865)", scope, isis.NET, c.value, c.ref))
					}
				}
			}
		} else if len(validCandidates) > 1 {
			vals := make([]string, len(validCandidates))
			for i, c := range validCandidates {
				vals[i] = c.value
			}
			return report(fmt.Sprintf("%s: multiple distinct IS-IS NETs in `family iso address` (%s); configure exactly one NET, or set `protocols isis net` explicitly (#16865)", scope, strings.Join(vals, ", ")))
		}
		if isis.NET == "" {
			if len(invalidCandidates) > 0 && len(validCandidates) == 0 {
				return report(fmt.Sprintf("%s: `family iso address %s` on %s is not a valid IS-IS NET (hex octets in dot-separated groups, 8 to 20 octets, e.g. 49.0001.0100.0000.0001.00); IS-IS has no NET and cannot form adjacencies — fix the ISO address or set `protocols isis net` (#16865)", scope, invalidCandidates[0].value, invalidCandidates[0].ref))
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
	if err := check("protocols isis", cfg.Protocols.ISIS, ""); err != nil {
		return warnings, err
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		if err := check(fmt.Sprintf("routing-instance %q protocols isis", ri.Name), ri.ISIS, ri.Name); err != nil {
			return warnings, err
		}
	}
	return warnings, nil
}
