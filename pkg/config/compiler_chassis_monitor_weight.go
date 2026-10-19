package config

import (
	"fmt"
	"strconv"
)

// compiler_chassis_monitor_weight.go carries the #6588 commit-side gate for a
// redundancy-group monitor weight that is present but UNUSABLE — malformed, or
// specified twice with different values.
//
// Why an AST pre-walk rather than a typed schema leaf or a compiled-struct
// check:
//
//   - The typed-leaf route is closed. `interface-monitor` packs
//     `<ifname> weight <n>` onto ONE node key, so schema_chassis.go declares it
//     `children: nil` (typing the weight would need a children/wildcard map,
//     which flips SetPath's replace-vs-container grouping). SchemaValidate
//     therefore never reaches the weight token at all — and for the PACKED
//     spelling it does not reach the ip-monitoring weights either, which sit
//     below the depth its walk descends.
//
//   - The compiled struct cannot tell these cases apart. compileChassis parses
//     the weight with strconv.Atoi and, on failure, leaves the pre-existing 0
//     default. `weight nope` and `weight 0` and no weight at all are all
//     Weight==0 by the time validateChassisClusterStrict sees them, so the
//     #6549 range gate — which is otherwise the right layer, and which #6588
//     extended to ip-monitoring — structurally cannot flag a parse failure.
//
// Both problems are the same class as the packed-statement drop this file's
// issue is about: the operator configures a monitor, `commit` succeeds with no
// error and no warning, and the redundancy group carries LESS demotion debt
// than was written — `interface-monitor ge-0/0/0 weight nope;` installs a
// monitor whose weight is 0, so the link going down demotes the group by
// nothing and failover does not happen.
//
// Duplicates were additionally SHAPE-DEPENDENT before this gate:
// `weight 100 weight 200` inline compiled to 200 (the inline scan overwrote)
// while `{ weight 100; weight 200; }` compiled to 100 (FindChild returns the
// first). The compiler is now uniformly first-wins via monitorWeightTokens, and
// this gate rejects the duplicate outright so the operator is never relying on
// which spelling they happened to use.
//
// Strictness follows the sibling chassis gates: hard-reject at commit /
// commit-check, downgrade to a cfg.Warnings entry on the tolerant load /
// peer-sync paths (#1960 no-brick) — an already-persisted or peer-pushed config
// an older binary accepted must still BOOT. The compiled 0 default is what the
// tolerant path keeps, now flagged rather than silent.

// validateMonitorWeightTokensAST walks the chassis cluster subtree and reports
// every redundancy-group monitor weight that is present but unusable. It runs
// on the group-expanded tree so an apply-groups-inherited weight is covered.
//
// It derives its entries from monitorEntryNodes / monitorWeightTokens — the
// same readers compileChassis uses — so the gate and the compiler cannot drift
// apart about which token is a weight, which entry it belongs to, or how a
// bracketed list splits.
//
// Returns (warnings, nil) when lenient, (nil, error) on the first offender when
// strict.
func validateMonitorWeightTokensAST(nodes []*Node, lenient bool) ([]string, error) {
	var warnings []string

	emit := func(format string, args ...interface{}) error {
		msg := fmt.Sprintf(format, args...)
		if lenient {
			warnings = append(warnings, msg)
			return nil
		}
		return fmt.Errorf("%s", msg)
	}

	// checkTokens applies the missing-value / non-integer / duplicate rules to
	// the value tokens of ONE weight-like field. Every field this gate covers
	// shares those rules because every one of them reaches the compiler through
	// the same Atoi-then-keep-0 coercion, so they are implemented once here
	// rather than per field.
	//
	// where identifies the offending field, already scoped to its redundancy
	// group (`redundancy-group 1 interface-monitor ge-0/0/0`). subject names
	// what was specified — `weight` for a monitored entry, `global-weight` /
	// `global-threshold` for an ip-monitoring global — and consequence spells
	// out the runtime effect, which differs between a per-entry weight and a
	// group-wide global.
	//
	// An empty token list means the field is absent, which is legal: the
	// documented 0 default (#6549). A PRESENT keyword with no value yields one
	// empty-string token from the readers below, so it is reported as malformed
	// rather than mistaken for absent.
	checkTokens := func(where, subject, consequence string, toks []string) error {
		if len(toks) == 0 {
			return nil
		}
		if len(toks) > 1 {
			distinct := false
			for _, t := range toks[1:] {
				if t != toks[0] {
					distinct = true
					break
				}
			}
			if distinct {
				return emit("chassis cluster %s: %s specified %d times with different "+
					"values %q — the compiled value would depend on the spelling; specify "+
					"exactly one %s", where, subject, len(toks), toks, subject)
			}
			return emit("chassis cluster %s: %s specified %d times; specify exactly one %s",
				where, subject, len(toks), subject)
		}
		if _, err := strconv.Atoi(toks[0]); err != nil {
			return emit("chassis cluster %s: %s %q is not an integer — it compiles to the 0 "+
				"default, so %s; set a %s in %d..%d",
				where, subject, toks[0], consequence, subject,
				MinInterfaceMonitorWeight, MaxInterfaceMonitorWeight)
		}
		return nil
	}

	// checkEntries validates every entry of one monitor statement. what names
	// the statement for the operator (e.g. `interface-monitor`).
	//
	// #15036: entries are ALSO checked for a duplicate interface. A
	// re-weighted monitor authored twice compiles (via the
	// compileRGInterfaceMonitors fold) to one entry, so the compiled
	// struct cannot show the duplicate — only this AST walk sees both
	// statements. Strict: reject; lenient: warn, and the fold keeps the
	// last weight so both runtime consumers read one weight.
	checkEntries := func(rgName, what string, entries []*Node, seen map[string]bool) error {
		for _, entry := range entries {
			name := entry.Name()
			if seen[name] {
				if err := emit("chassis cluster redundancy-group %s %s %s: "+
					"duplicate interface-monitor %s — specify the monitor exactly once with its "+
					"final weight; a second entry is not a re-weight, and the runtime would "+
					"apply the two entries in different orders",
					rgName, what, name, name); err != nil {
					return err
				}
			}
			seen[name] = true
			if err := checkTokens(
				fmt.Sprintf("redundancy-group %s %s %s", rgName, what, entry.Name()),
				monitorWeightKeyword,
				"the monitor going down deducts NO weight and the redundancy group never demotes",
				monitorWeightTokens(entry)); err != nil {
				return err
			}
		}
		return nil
	}

	// checkIPMonitoringGlobals validates the two group-wide ip-monitoring
	// values. They were missed when this gate was first written because it
	// walked only the ENTRY lists (interface-monitor names, family inet
	// addresses), and the globals are properties of the ip-monitoring statement
	// rather than entries of a list. The consequence is at least as bad: an
	// unusable global-weight is zero demotion debt for the WHOLE group, so no
	// number of failing probes demotes it. A typo'd weight is ordinary operator
	// input, so this is reachable in a way the value-position collision
	// documented on redundancyGroupStatements is not.
	checkIPMonitoringGlobals := func(rgName string, props []*Node) error {
		for _, subject := range []string{"global-weight", "global-threshold"} {
			if err := checkTokens(
				fmt.Sprintf("redundancy-group %s ip-monitoring", rgName),
				subject,
				"the redundancy group accrues NO demotion debt when its monitored "+
					"targets fail and never demotes",
				ipMonitoringGlobalTokens(props, subject)); err != nil {
				return err
			}
		}
		return nil
	}

	walkErr := forEachChild(nodes, "chassis", func(chassis *Node) error {
		return forEachChild(chassis.Children, "cluster", func(cluster *Node) error {
			for _, rgInst := range namedInstances(cluster.FindChildren("redundancy-group")) {
				// #15036: duplicate detection is per redundancy-group and
				// spans every statement in its (possibly multi-block,
				// #6543-folded) body, so both maps live outside the child loop.
				seenIfMon := make(map[string]bool)
				seenIP := make(map[string]bool)
				for _, child := range redundancyGroupBody(rgInst.node) {
					switch child.Name() {
					case "interface-monitor":
						if err := checkEntries(rgInst.name, "interface-monitor",
							monitorEntryNodes(child, 1), seenIfMon); err != nil {
							return err
						}
					case "ip-monitoring":
						// One packedStatementProps result feeds both the
						// globals and the family walk, so the gate sees
						// exactly the node set compileRGIPMonitoring compiles
						// from.
						ipmProps := packedStatementProps(child, 1, isIPMonitoringProp)
						if err := checkIPMonitoringGlobals(rgInst.name, ipmProps); err != nil {
							return err
						}
						for _, familyNode := range ipmProps {
							if familyNode.Name() != "family" {
								continue
							}
							inetNode, inetSkip := ipMonitoringInetNode(familyNode)
							if inetNode == nil {
								continue
							}
							if err := checkEntries(rgInst.name, "ip-monitoring family inet",
								monitorEntryNodes(inetNode, inetSkip), seenIP); err != nil {
								return err
							}
						}
					}
				}
			}
			return nil
		})
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return warnings, nil
}

// ipMonitoringInetNode resolves the node holding the monitored IPv4 addresses
// of an ip-monitoring `family` property, and how many of its leading Keys name
// the node itself rather than an address. The compound spelling
// (`family inet ...`, Keys[1]=="inet") and the nested one
// (`family { inet { ... } }`) differ by exactly one identity token, and getting
// that offset wrong silently shifts which token is read as an address — so both
// compileChassis and validateMonitorWeightTokensAST resolve it here rather than
// each open-coding the branch.
func ipMonitoringInetNode(familyNode *Node) (*Node, int) {
	if len(familyNode.Keys) >= 2 && familyNode.Keys[1] == "inet" {
		return familyNode, 2
	}
	return familyNode.FindChild("inet"), 1
}
