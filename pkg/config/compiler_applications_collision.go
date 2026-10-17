package config

import (
	"fmt"
	"sort"
)

// compiler_applications_collision.go carries the #3339 (Codex review 080 M07 +
// M08) reject-at-commit gate for application / application-set NAME COLLISIONS.
//
// compileApplications collects user applications and application-sets into two
// maps keyed by name (apps.Applications[name], apps.ApplicationSets[name]) and a
// multi-term application additionally MINTS an implicit application-set under the
// application's own name (apps.ApplicationSets[appName] = implicitSet). Every one
// of these writes is last-write-wins: a second definition silently OVERWRITES
// the first, with no commit error. The observable failures (#3339 and #12220):
//
//   - M07: an explicit `applications application-set <X>` silently replaces the
//     implicit set minted for a multi-term `applications application <X>` (or,
//     more generally, an application and an application-set share a name). A
//     policy referencing <X> then enforces whichever definition won the
//     map-write race — and policy expansion vs the AppID catalog disagree on
//     which that is (resolveUserspaceApplicationNames resolves application-first;
//     addPolicyApps resolves application-set-first), so a session can be
//     admitted by one definition but cataloged/labeled by the other.
//
//   - M08: two `term` statements under one application that generate the same
//     per-term application name (`<parent>-<term>`, with a protocol suffix only
//     when a single term carries multiple protocols) — the later
//     apps.Applications[name] = t silently overwrites the earlier while the
//     implicit set still lists the duplicated member. Ambiguous and silent.
//   - #12220: an authored `application-set <X>` — or a term-based authored
//     `application <X>`, which mints an implicit application-set <X> — can
//     shadow a predefined application `<X>` without overwriting either user
//     map. Direct references resolve application-first, while nested set
//     members resolve user-set-first, so the same token can have different
//     enforced meanings by reference path.
//
// Junos treats applications and application-sets as a SINGLE flat namespace and
// rejects a duplicate definition / a name used for both; this gate restores that
// parity. It is an AST pre-walk (run on the group-expanded, inactive-pruned tree
// in compileExpanded) rather than a post-compile check: duplicate definitions
// and authored app/set collisions can be merged away by last-write-wins, while
// #12220 must compare authored and implicit application-set names with predefined
// applications before the differing resolution paths are used. The raw AST
// preserves every authored stanza so one gate can handle both cases. This mirrors
// validateUnsupportedInterfaceStanzasAST and the other AST reject-at-commit gates.
//
// Strict path (commit / commit-check, lenient=false): the first collision is a
// hard compile error naming the offending name. Lenient path (load / peer-sync,
// lenient=true): every collision is returned as a warning and compilation
// continues with the existing last-write-wins maps so the config still BOOTS
// (#1960 / #3261 fail-closed-on-load doctrine). The colliding names are also
// recorded as compiler metadata; userspace refuses policy references to them
// with the unsupported-application sentinel and a non-empty rejection mirror,
// rather than publishing the arbitrary map winner.
//
// Scope notes:
//   - A SIMPLE (non-term) user `application junos-http` that shadows a predefined
//     application remains allowed — that is the legitimate shadow/extend case
//     from #3339. Likewise an authored application-set that shadows a predefined
//     application-SET remains allowed when it is the only authored kind
//     claiming the name (#4102 user-set-first on every path). A simple
//     application claiming a predefined-set name is NOT consistent (direct
//     set expansion is predefined-first, app/member resolution is app-first)
//     and is diagnosed by section 5 (#14339). A term-based application mints
//     an implicit application-set and is likewise diagnosed by section 5.
//   - A user `application-set` shadowing a predefined application is also
//     diagnosed in section 5: direct references resolve application-first, while
//     nested members resolve user-set-first. The same split-brain applies when
//     an authored application (simple or term-based/implicit-set) claims a
//     predefined application-SET name, or when BOTH authored kinds claim one
//     predefined-set name: direct/top-level expansion is predefined/user-set
//     first while ResolveApplication / nested members are user-app first.
//   - A multi-term application <X> minting an implicit set <X> is not itself a
//     collision: the application stanza and its synthesized set share a name
//     by design. If <X> is a predefined application or predefined set, section 5
//     diagnoses the differing direct and nested resolution paths. An explicit
//     `application-set <X>` is a separate operator-authored stanza and remains
//     the M07 implicit-set-overwrite case.
//   - Duplicate application or application-set definitions (the same name authored
//     twice in the same namespace) are also rejected; these survive as distinct
//     AST siblings only on a hierarchical file parse (the set-command config tree
//     merges same-named siblings), but rejecting them keeps the gate honest for
//     either representation.

// validateApplicationNameCollisionsAST walks the `applications` subtree of the
// group-expanded AST and rejects duplicate / cross-namespace application name
// definitions. See the file-level comment for the doctrine.
//
// #3472 extends the gate to the GENERATED per-term application names that #3339
// ignored: a generated `<parent>-<term>` name that overwrites an authored
// application (H01), collides cross-namespace with an authored application-set
// (H02), or collides with another parent's generated name (H03) is rejected
// under strict commit (warned on the tolerant load / peer-sync path). #14339
// extends section 6d: a generated name that shadows a predefined application
// OR a predefined application-set is rejected under strict commit and
// quarantined (warned) on the lenient path — the generated name was never
// authored as an application, so the legitimate authored-shadow doctrine does
// not cover it. See section 6 below.
func validateApplicationNameCollisionsAST(nodes []*Node, lenient bool) ([]string, map[string]struct{}, error) {
	// The compiler compiles EVERY top-level `applications` node (compiler.go's
	// `for _, node := range tree.Children` switch hits `case "applications"`
	// once per node), so a collision SPLIT across two sibling `applications {}`
	// blocks (which a hierarchical parse emits as separate top-level nodes) is
	// just as real as one inside a single block. Aggregate counts across ALL of
	// them rather than stopping at the first — stopping at the first missed the
	// exact #3339 bug for a split definition.
	var appsNodes []*Node
	for _, n := range nodes {
		if n.Name() == "applications" {
			appsNodes = append(appsNodes, n)
		}
	}
	if len(appsNodes) == 0 {
		return nil, nil, nil
	}

	var warnings []string
	var collidingNames map[string]struct{}
	markCollision := func(name string) {
		if collidingNames == nil {
			collidingNames = make(map[string]struct{})
		}
		collidingNames[name] = struct{}{}
	}
	emit := func(format string, args ...any) error {
		msg := fmt.Sprintf(format, args...)
		if !lenient {
			return fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg)
		return nil
	}

	// Count each name within its namespace across every `applications` block.
	// namedInstances enumerates every instance (it does NOT dedup), so a name
	// authored twice — in one block or split across blocks — yields count > 1.
	appCounts := map[string]int{}
	appOrder := []string{}
	setCounts := map[string]int{}
	for _, appsNode := range appsNodes {
		for _, inst := range namedInstances(appsNode.FindChildren("application")) {
			if inst.name == "" {
				continue
			}
			if appCounts[inst.name] == 0 {
				appOrder = append(appOrder, inst.name)
			}
			appCounts[inst.name]++
		}
		for _, inst := range namedInstances(appsNode.FindChildren("application-set")) {
			if inst.name == "" {
				continue
			}
			setCounts[inst.name]++
		}
	}

	// 1. Duplicate application definition (same name twice in the application
	//    namespace). Reported in first-seen order for a deterministic error.
	for _, name := range appOrder {
		if appCounts[name] > 1 {
			markCollision(name)
			if err := emit(
				"applications application %q is defined %d times — a duplicate "+
					"application definition is silently last-write-wins (the later "+
					"definition replaces the earlier with no commit error); remove "+
					"the duplicate or rename it (#3339)",
				name, appCounts[name]); err != nil {
				return nil, nil, err
			}
		}
	}

	// 2. Duplicate application-set definition (same name twice in the
	//    application-set namespace).
	setNames := make([]string, 0, len(setCounts))
	for name := range setCounts {
		setNames = append(setNames, name)
	}
	sort.Strings(setNames)
	for _, name := range setNames {
		if setCounts[name] > 1 {
			markCollision(name)
			if err := emit(
				"applications application-set %q is defined %d times — a duplicate "+
					"application-set definition is silently last-write-wins (the "+
					"later definition replaces the earlier with no commit error); "+
					"remove the duplicate or rename it (#3339)",
				name, setCounts[name]); err != nil {
				return nil, nil, err
			}
		}
	}

	// 3. Cross-namespace collision: a name authored as BOTH an application and an
	//    application-set. Applications and application-sets share one flat Junos
	//    namespace; a multi-term application additionally mints an implicit set
	//    under its own name, so an explicit `application-set <X>` here silently
	//    overwrites it. Either way enforcement (policy expansion) and the AppID
	//    catalog can resolve <X> to different definitions (M07). Reported in
	//    application first-seen order.
	for _, name := range appOrder {
		if setCounts[name] > 0 {
			markCollision(name)
			if err := emit(
				"name %q is defined as BOTH an application and an "+
					"application-set — they share one namespace, so the "+
					"application-set silently overwrites the application (or the "+
					"implicit set minted for a multi-term application), and a policy "+
					"referencing %q may enforce one definition while AppID catalogs "+
					"the other; rename one of them (#3339)",
				name, name); err != nil {
				return nil, nil, err
			}
		}
	}

	// 4. Duplicate generated per-term application name within one application
	//    (M08). Two terms whose generated `<parent>-<term>` names collide make
	//    the later overwrite the earlier in apps.Applications. Computed via the
	//    SAME parseApplicationTerms the compiler uses so the detected names match
	//    exactly what would be written. The seen/reported sets are keyed by
	//    application NAME (not per AST node) so a name whose terms are split
	//    across two `applications` blocks is still caught. Applications iterated
	//    in first-seen order.
	termSeen := map[string]map[string]bool{}
	termDupReported := map[string]map[string]bool{}
	// #3472: generated per-term application names land in the SAME flat namespace
	// as authored applications/sets — compileApplications writes each generated
	// term into apps.Applications[<parent>-<term>] (compiler_applications.go), and a
	// term-based application additionally mints an implicit set under its own name.
	// #3339's gate only counted AUTHORED names, so a generated name was invisible to
	// it and silently last-write-wins into the map. Build a global table of every
	// generated name -> the distinct parent applications that produce it (in
	// first-seen order) so the post-loop pass (section 6) can reject a generated
	// name that overwrites an authored application (H01), collides cross-namespace
	// with an authored application-set (H02), or collides with another parent's
	// generated name (H03), and warn on one that shadows a predefined junos-* app
	// (M03). genParents is populated for EVERY produced name (including a within-
	// parent duplicate) so the distinct-parent count is exact.
	genParents := map[string]map[string]bool{}
	var genOrder []string
	for _, appsNode := range appsNodes {
		for _, inst := range namedInstances(appsNode.FindChildren("application")) {
			appName := inst.name
			if appName == "" {
				continue
			}
			if termSeen[appName] == nil {
				termSeen[appName] = map[string]bool{}
				termDupReported[appName] = map[string]bool{}
			}
			seen := termSeen[appName]
			dupReported := termDupReported[appName]
			// #6524: enumerate terms through applicationTermNodes /
			// applicationTermKeys — the SAME walk compileApplications uses to
			// decide what to write. This loop previously scanned
			// inst.node.Children directly, which could not see a term reached
			// through a flat-set CHAIN (`application myapp description doc term
			// t1 protocol udp` nests the term under the `description` value
			// node). Once #6524 taught the compiler to follow that chain, such a
			// term was MINTED into apps.Applications but stayed invisible to
			// every gate below — so a generated `<parent>-<term>` could silently
			// overwrite an AUTHORED application (H01) with no commit error,
			// erasing a deny that referenced it. `description` is the entry route
			// on the strict path because it deliberately does not set
			// hasDirectBody (#3366), so MixedDirectTermApps never engages; on the
			// tolerant path that gate is only a warning, so no `description`
			// prefix is even needed. The sibling spelling was always caught here
			// — only the chained shape evaded it.
			for _, prop := range applicationTermNodes(inst.node) {
				allKeys := applicationTermKeys(prop)
				if len(allKeys) == 0 {
					continue
				}
				for _, t := range parseApplicationTerms(appName, allKeys) {
					// #3472: record this generated name and the parent that
					// produced it for the global flat-namespace pass below.
					if genParents[t.Name] == nil {
						genParents[t.Name] = map[string]bool{}
						genOrder = append(genOrder, t.Name)
					}
					genParents[t.Name][appName] = true

					if seen[t.Name] {
						if !dupReported[t.Name] {
							dupReported[t.Name] = true
							markCollision(t.Name)
							if err := emit(
								"applications application %q has terms that generate "+
									"the duplicate application name %q — the later term "+
									"silently overwrites the earlier (with no commit "+
									"error) while the implicit set still lists the "+
									"duplicate member; give the terms distinct names "+
									"(#3339)",
								appName, t.Name); err != nil {
								return nil, nil, err
							}
						}
						continue
					}
					seen[t.Name] = true
				}
			}
		}
	}
	// 5. A user application-set shadowing a predefined application makes the
	//    same member token resolve differently by reference path: direct
	//    application resolution finds the predefined application, while nested
	//    set expansion selects the user-defined application-set first. A
	//    term-based application under that name also mints an implicit set, so
	//    nested references resolve differently from direct references. The
	//    simple, non-term application shadow remains allowed. #14339 mirrors
	//    this for predefined application-SETS (see below).
	for _, name := range setNames {
		if appCounts[name] > 0 || len(genParents[name]) > 0 {
			continue
		}
		if _, isPredefinedApplication := PredefinedApplications[name]; !isPredefinedApplication {
			continue
		}
		markCollision(name)
		if err := emit(
			"application-set %q shadows predefined application %q — direct application "+
				"references resolve to the predefined application, but nested "+
				"application-set members resolve the user-defined set; a policy can "+
				"therefore enforce different applications by reference path (rename "+
				"the application-set) (#12220)",
			name, name); err != nil {
			return nil, nil, err
		}
	}

	// A term-based application <X> mints an implicit application-set named <X>
	// and writes no apps.Applications[<X>] entry. This shadows the predefined
	// application/set for nested members while direct references still resolve
	// to the predefined service. Do not diagnose an explicit set of the same
	// name twice; the authored-set check above owns that diagnostic.
	for _, name := range appOrder {
		if len(termSeen[name]) == 0 || setCounts[name] > 0 {
			continue
		}
		if _, isPredefinedApplication := PredefinedApplications[name]; isPredefinedApplication {
			markCollision(name)
			if err := emit(
				"term-based application %q mints an implicit application-set that shadows "+
					"predefined application %q — direct references resolve to the predefined "+
					"application, but nested application-set members expand the implicit set; "+
					"rename the application (#12220)",
				name, name); err != nil {
				return nil, nil, err
			}
			continue
		}
		if _, isPredefSet := PredefinedApplicationSets[name]; isPredefSet {
			markCollision(name)
			if err := emit(
				"term-based application %q mints an implicit application-set that shadows "+
					"predefined application-set %q — direct application-set expansion "+
					"resolves the predefined set, but nested application-set members "+
					"expand the implicit set; rename the application (#14339)",
				name, name); err != nil {
				return nil, nil, err
			}
		}
	}

	// #14339: an authored simple application claiming a predefined
	// application-SET name (no authored set of that name) splits by path:
	// ExpandApplicationSet("junos-cifs") resolves the predefined set, while
	// ResolveApplication and nested members (memberIsNestedSet user-app-first)
	// resolve the single custom application. A lone authored application-set
	// claiming a predefined-set name stays allowed (#4102 user-set-first, all
	// paths agree); both-kinds is already rejected by section 3.
	for _, name := range appOrder {
		if setCounts[name] > 0 || len(termSeen[name]) > 0 {
			continue
		}
		if _, isPredefSet := PredefinedApplicationSets[name]; !isPredefSet {
			continue
		}
		markCollision(name)
		if err := emit(
			"application %q shadows predefined application-set %q — direct "+
				"application-set expansion resolves the predefined set, but direct "+
				"application references and nested application-set members resolve "+
				"the user application; a policy can therefore enforce different "+
				"applications by reference path (rename the application) (#14339)",
			name, name); err != nil {
			return nil, nil, err
		}
	}

	// 6. Generated per-term application names vs the rest of the flat Junos
	//    namespace (#3472). compileApplications writes every generated
	//    `<parent>-<term>` into apps.Applications and mints each term-based
	//    parent's implicit set, but #3339's appCounts/setCounts only enumerated
	//    AUTHORED `application`/`application-set` nodes — a generated name was in
	//    neither table, so three collision classes silently last-write-wins:
	//
	//      H01 — a generated name equals an authored application. Both write
	//            apps.Applications[name]; the later write wins, so policy / AppID
	//            can enforce or label the wrong application.
	//      H02 — a generated name equals an authored application-set. The two
	//            live in different maps (Applications vs ApplicationSets), and the
	//            resolution paths disagree: userspace policy expansion resolves
	//            application-first (resolveUserspaceApplicationNames) while the
	//            AppID catalog resolves set-first (pkg/appid/runtime.go), so the
	//            same token enforces one definition and is attributed to the other.
	//      H03 — the same generated name is produced by two DIFFERENT parents;
	//            #3339's termSeen is scoped per parent, so the later term silently
	//            overwrites the earlier across parents.
	//
	//    All three hard-reject under strict commit and downgrade to a warning on
	//    the tolerant load / peer-sync path (the shared emit helper). Iterated in
	//    generated-name first-seen order for a deterministic error.
	for _, g := range genOrder {
		parents := make([]string, 0, len(genParents[g]))
		for p := range genParents[g] {
			parents = append(parents, p)
		}
		sort.Strings(parents)

		// 6a. H03 — cross-parent generated-name collision.
		if len(parents) > 1 {
			markCollision(g)
			if err := emit(
				"applications %v each generate the per-term application name %q — "+
					"the generated name collides across parents and the later term "+
					"silently overwrites the earlier in apps.Applications (with no "+
					"commit error); rename a term or parent so the generated %q is "+
					"unique (#3472)",
				parents, g, g); err != nil {
				return nil, nil, err
			}
		}

		// 6b. H01 — generated name overwrites an authored application.
		//     Mechanism-agnostic phrasing: a SIMPLE authored application named %q
		//     writes apps.Applications[%q] (a direct overwrite of the generated
		//     term), but a TERM-BASED authored application named %q writes its
		//     implicit set into apps.ApplicationSets[%q] instead — so the exact
		//     map collision differs by sub-case. Both share the one flat Junos
		//     namespace with the generated name and resolve last-write-wins /
		//     ambiguously, which is the defect; the message describes the namespace
		//     collision rather than a specific map write that does not always hold.
		if appCounts[g] > 0 {
			markCollision(g)
			if err := emit(
				"generated per-term application name %q (from %v) collides with the "+
					"authored application name %q in the flat application namespace — "+
					"generated term names share one namespace with authored "+
					"applications / application-sets, so this is ambiguous and "+
					"last-write-wins (with no commit error) and policy / AppID may "+
					"enforce or label the wrong application; rename one of them (#3472)",
				g, parents, g); err != nil {
				return nil, nil, err
			}
		}

		// 6c. H02 — generated name collides with an authored application-set.
		if setCounts[g] > 0 {
			markCollision(g)
			if err := emit(
				"generated per-term application name %q (from %v) collides with the "+
					"authored application-set %q — they share one flat namespace but live "+
					"in different maps, and policy expansion resolves application-first "+
					"while the AppID catalog resolves application-set-first, so the same "+
					"token enforces one definition and is attributed to the other; rename "+
					"one of them (#3472)",
				g, parents, g); err != nil {
				return nil, nil, err
			}
		}

		// 6d. #14339 — generated name shadows a predefined application or
		//     predefined application-set. Strict: hard reject via emit;
		//     lenient: warning + markCollision quarantine. Unlike an authored
		//     simple application, a generated <parent>-<term> name was never
		//     written as an application by the operator, so the documented
		//     authored-shadow doctrine does not cover it: `application junos
		//     term ssh` silently hijacks junos-ssh (tcp/22 -> author port) and
		//     `application junos term cifs` hijacks the junos-cifs predefined
		//     set on the ResolveApplication/nested-member path while direct
		//     ExpandApplicationSet still resolves the predefined set.
		if _, isPredef := PredefinedApplications[g]; isPredef {
			markCollision(g)
			if err := emit(
				"generated per-term application name %q (from %v) shadows predefined "+
					"application %q — the generated name was never authored as an "+
					"application, but ResolveApplication prefers the generated "+
					"application over the predefined service, so the predefined %q "+
					"is hijacked by reference path; rename the term or parent (#14339)",
				g, parents, g, g); err != nil {
				return nil, nil, err
			}
		} else if _, isPredefSet := PredefinedApplicationSets[g]; isPredefSet {
			markCollision(g)
			if err := emit(
				"generated per-term application name %q (from %v) shadows predefined "+
					"application-set %q — direct application-set expansion resolves "+
					"the predefined set, but ResolveApplication and nested "+
					"application-set members resolve the generated application; a "+
					"policy can therefore enforce different applications by "+
					"reference path (rename the term or parent) (#14339)",
				g, parents, g); err != nil {
				return nil, nil, err
			}
		}
	}

	return warnings, collidingNames, nil
}
