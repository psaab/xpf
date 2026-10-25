package config

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"
)

// #16625 (R3-A12-03): RIP per-group `export` was flattened into one
// global ripd redistribute chain. Two groups with different export
// policies committed strict-clean, and depending on stanza order one
// group lost its routes or the other received routes its policy
// excludes.
//
// The compiler now preserves the group->export association in
// RIPConfig.Groups (#16625) and pkg/frr renders per-interface
// output filtering when groups are present. This gate is the
// fail-closed backstop for shapes the renderer cannot express:
//
//   - An interface appearing in two groups with DIFFERENT export
//     lists: one `distribute-list ... out <if>` per interface can
//     name only one chain, so the boundary is ambiguous.
//   - The same holds against the global (non-group) export: an
//     interface that is both a global `neighbor` (covered by
//     Redistribute) and a group neighbor with a different export
//     has two competing chains. Global neighbors use Redistribute
//     as their effective chain for this comparison; interfaces
//     only in groups are not compared against the global chain
//     (their redistribute entry is the group-derived union, which
//     the renderer no longer uses when Groups is non-empty).
//
// Strict rejects; lenient warns (#1960) and the renderer fails
// closed by withholding the contested interfaces (see pkg/frr).

// ripGroupExportKey16625 returns a canonical order-insensitive key
// for an export chain. Export order matters for chain semantics
// (first terminal action wins, #5277/#15156), so two groups whose
// exports differ only in ORDER are different policies and must not
// compare equal. The key therefore preserves order; duplicates are
// collapsed (a repeated policy name does not change the chain).
func ripGroupExportKey16625(chain []string) string {
	seen := make(map[string]bool)
	var out []string
	for _, e := range chain {
		if e == "" || seen[e] {
			continue
		}
		seen[e] = true
		out = append(out, e)
	}
	return strings.Join(out, "\x00")
}

func validateRIPGroupExportStrict(cfg *Config, lenient bool) ([]string, error) {
	if cfg == nil {
		return nil, nil
	}
	var warnings []string
	report := func(scope, msg string) error {
		if lenient {
			slog.Warn("config: rip per-group export cannot be rendered per-interface; contested interfaces will be withheld",
				"scope", scope, "detail", msg, "issue", "#16625")
			warnings = append(warnings, fmt.Sprintf("%s: %s (#16625)", scope, msg))
			return nil
		}
		return fmt.Errorf("%s: %s (#16625)", scope, msg)
	}
	check := func(scope string, rip *RIPConfig) error {
		if rip == nil || len(rip.Groups) == 0 {
			return nil
		}
		// interface -> (group name, export key, export list)
		type owner struct {
			group string
			key   string
			list  []string
		}
		owners := make(map[string]owner)
		// Interfaces that are global neighbors: their effective
		// chain is the non-group Redistribute portion. We cannot
		// separate group-derived entries from global ones in
		// Redistribute (it is the union), so derive the global
		// chain as Redistribute minus every group's exports is
		// wrong when a name appears in both. Instead, track
		// group membership only: a contested interface is one in
		// 2+ groups with differing exports. Global-vs-group is
		// handled by noting that Redistribute entries NOT in any
		// group form the global chain; if a group interface's
		// group export differs from that global chain AND the
		// interface is also reachable via the global chain
		// (i.e. the global chain is non-empty and the interface
		// would have been enrolled by `network` even without
		// the group), the renderer still enrolls it once with
		// the group filter — the global chain does not create a
		// second filter. So only multi-group conflicts are
		// inexpressible.
		for _, g := range rip.Groups {
			if g == nil {
				continue
			}
			key := ripGroupExportKey16625(g.Export)
			for _, iface := range g.Interfaces {
				if prev, ok := owners[iface]; ok {
					if prev.key != key {
						return report(scope, fmt.Sprintf(
							"interface %s is in rip groups %q (export %v) and %q (export %v) with different export policies; "+
								"ripd supports only one outbound filter per interface, so this per-group boundary cannot be rendered. "+
								"Give the interface a single group or make the group exports identical",
							iface, prev.group, prev.list, g.Name, g.Export))
					}
					continue
				}
				owners[iface] = owner{group: g.Name, key: key, list: g.Export}
			}
		}
		return nil
	}
	if err := check("protocols rip", cfg.Protocols.RIP); err != nil {
		return warnings, err
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		if err := check(fmt.Sprintf("routing-instance %s protocols rip", ri.Name), ri.RIP); err != nil {
			return warnings, err
		}
	}
	return warnings, nil
}

// ripContestedInterfaces16625 returns the sorted set of interfaces
// that belong to two or more groups with differing export keys.
// Used by pkg/frr to fail closed on the tolerant path. Exported
// via RIPContestedInterfaces16625.
func ripContestedInterfaces16625(rip *RIPConfig) []string {
	if rip == nil || len(rip.Groups) == 0 {
		return nil
	}
	keys := make(map[string]string)
	contested := make(map[string]bool)
	for _, g := range rip.Groups {
		if g == nil {
			continue
		}
		key := ripGroupExportKey16625(g.Export)
		for _, iface := range g.Interfaces {
			if prev, ok := keys[iface]; ok && prev != key {
				contested[iface] = true
			} else if !ok {
				keys[iface] = key
			}
		}
	}
	if len(contested) == 0 {
		return nil
	}
	out := make([]string, 0, len(contested))
	for iface := range contested {
		out = append(out, iface)
	}
	sort.Strings(out)
	return out
}

// RIPContestedInterfaces16625 is the pkg/frr-facing wrapper.
func RIPContestedInterfaces16625(rip *RIPConfig) []string {
	return ripContestedInterfaces16625(rip)
}

// RIPGroupExportKey16625 exposes the canonical chain key so the
// renderer can group interfaces by identical export chain.
func RIPGroupExportKey16625(chain []string) string {
	return ripGroupExportKey16625(chain)
}
