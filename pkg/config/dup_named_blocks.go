package config

import (
	"fmt"
	"sort"
)

// nonInterfaceIfKeyword lists the non-leaf children that may appear directly
// under an `interfaces { }` stanza but are NOT interface definitions, so the
// duplicate-interface gate must not treat a repeat of one as a dropped
// interface. `interface-range` legitimately repeats (one block per range) and
// `traceoptions` / `apply-macro` are container leaves, not interfaces.
var nonInterfaceIfKeyword = map[string]bool{
	"interface-range":     true,
	"traceoptions":        true,
	"apply-macro":         true,
	"apply-groups":        true,
	"apply-groups-except": true,
}

// screenIDSFamily lists the ids-option sub-stanzas compileScreen reads with
// FindChild (first-sibling only): a repeated same-family block inside one
// ids-option is silently dropped. Keep in sync with compileScreen
// (compiler_security_screen.go).
var screenIDSFamily = map[string]bool{
	"icmp":          true,
	"ip":            true,
	"tcp":           true,
	"udp":           true,
	"limit-session": true,
}

// dupBlock is one detected duplicate authored hierarchical named block.
type dupBlock struct {
	kind   string // human category, e.g. "interface" / "screen ids-option"
	name   string // the duplicated name
	effect dupContainerEffect
}

// validateDuplicateNamedBlockAST rejects (strict) or warns (lenient) when the
// candidate authors the SAME named hierarchical block twice inside a container
// whose compiler does whole-object last-writer-wins replacement — dropping the
// earlier block's config silently (#5180, consolidating codex-177 A3-b2-F3 +
// A3-b3-F1). Four containers are affected:
//
//   - groups { <name> { … } }  — expandGroups keeps only the last definition
//     (ast_groups.go: groups[name] = g).
//   - interfaces { <ifname> { … } } — compileInterfaces overwrites
//     Interfaces[ifName] (compiler_interfaces.go).
//   - security { screen { ids-option <name> { … } } } — compileScreen overwrites
//     Screen[profile.Name]; WITHIN one ids-option it also reads each
//     icmp/ip/tcp/udp/limit-session family with FindChild (first sibling only),
//     so a repeated family block is dropped too.
//   - system { login { user <name> { … } } } — compileSystemLogin folds a
//     duplicated name into ONE entry, per-leaf last-authored-wins (#6992), so
//     the earlier block's uid / class / keys disappear. Before that fold the
//     duplicate was WORSE than a drop: both blocks survived and two readers
//     picked different ones, so an SSH key authored under a VIEW-only block
//     could authenticate into a super-user CLI.
//
// This is a dual-AST-equivalence gate. Under flat `set` these statements MERGE:
// tree.SetPath collapses `set interfaces ge-0/0/0 …` written twice onto ONE
// node, so the flat shape never produces a duplicate sibling and compiles the
// union. The hierarchical shape, by contrast, produced two sibling nodes and
// silently dropped one — a fail-open divergence (an authored deny/enforcement
// block could vanish). Rejecting the hierarchical duplicate (or, on the
// tolerant path, warning that the earlier block was dropped) makes the two
// shapes agree on the invariant "no authored block silently disappears": the
// flat shape merges it in, the hierarchical shape is told to author it once.
//
// It runs PRE-expansion on the (inactive-pruned) clone alongside the tunnel /
// zone / routing-instance collision gates, and it walks ONLY the top-level
// `groups`/`interfaces`/`security` stanzas — never a group body — so a legitimate
// apply-groups inheritance (expandGroups deep-MERGES a group's interface/screen
// config into the target, producing no duplicate sibling) is not misreported.
// The `groups` check is inherently top-level. A quoted-empty group / interface /
// screen-ids-option name is recorded as an empty-name defect (#6455) rather than
// skipped. Strict on commit / commit-check; lenient on tolerant load / peer-sync
// (#1960 no-brick), where the runtime keeps the historical last-writer-wins result
// and boots.
//
// A duplicate authored ENTIRELY inside an applied group body is NOT caught here —
// this gate is pre-expansion by design; it is caught by
// validateDuplicateNamesExpandedAST (dup_names_expanded_6455.go, #6455
// Finding 1), which re-runs THIS function on a group-expanded clone.
func validateDuplicateNamedBlockAST(tree *ConfigTree, lenient bool) ([]string, error) {
	if tree == nil {
		return nil, nil
	}
	var dups []dupBlock
	var emptyKinds []string
	emptySeen := map[string]bool{}
	recordEmpty := func(kind string) {
		if !emptySeen[kind] {
			emptyKinds = append(emptyKinds, kind)
			emptySeen[kind] = true
		}
	}

	// 1. groups { <name> { … } } — mirror ast_groups.go name extraction; an empty
	// group name is an empty-name defect.
	seenGroup := map[string]bool{}
	reportedGroup := map[string]bool{}
	for _, child := range tree.Children {
		if child.Name() != "groups" {
			continue
		}
		for _, g := range child.Children {
			name := groupDefinitionName(g)
			if name == "" {
				if len(g.Keys) >= 1 {
					recordEmpty("group")
				}
				continue
			}
			if seenGroup[name] {
				if !reportedGroup[name] {
					dups = append(dups, dupBlock{"group", name, dupEffectLastWins})
					reportedGroup[name] = true
				}
			} else {
				seenGroup[name] = true
			}
		}
	}

	// 2. interfaces { <ifname> { … } } — mirror compileInterfaces (non-leaf
	// child keyed by Name(), skipping the non-interface container keywords).
	// Union across every top-level `interfaces` stanza so a name split across
	// two stanzas (also last-writer-wins in compileSections) is caught.
	seenIf := map[string]bool{}
	reportedIf := map[string]bool{}
	for _, child := range tree.Children {
		if child.Name() != "interfaces" {
			continue
		}
		for _, ifc := range child.Children {
			if ifc.IsLeaf {
				continue
			}
			name := ifc.Name()
			if name == "" {
				if len(ifc.Keys) >= 1 {
					recordEmpty("interface")
				}
				continue
			}
			if nonInterfaceIfKeyword[name] {
				continue
			}
			if seenIf[name] {
				if !reportedIf[name] {
					dups = append(dups, dupBlock{"interface", name, dupEffectLastWins})
					reportedIf[name] = true
				}
			} else {
				seenIf[name] = true
			}
		}
	}

	// 3. Table-driven named containers (namedDupRules). This replaces two
	// hand-written copies of the same walk (screen ids-option, login user) and
	// carries the six #6768 rows on the same code path, so a container added to
	// the registry is covered by the strict gate, the lenient warning, and the
	// #6455 group-expanded re-run without any of the three being edited.
	// Union across every top-level stanza and every intermediate container
	// therein, matching what the hand-written walks did.
	for _, rule := range namedDupRules {
		seen := map[string]bool{}
		reported := map[string]bool{}
		for _, child := range tree.Children {
			if child.Name() != rule.stanza {
				continue
			}
			holders := []*Node{child}
			if rule.inner != "" {
				holders = child.FindChildren(rule.inner)
			}
			for _, holder := range holders {
				for _, inst := range namedInstances(holder.FindChildren(rule.keyword)) {
					if inst.name == "" {
						recordEmpty(rule.kind)
						continue
					}
					if seen[inst.name] {
						if !reported[inst.name] {
							dups = append(dups, dupBlock{rule.kind, inst.name, rule.effect})
							reported[inst.name] = true
						}
						continue
					}
					seen[inst.name] = true
				}
			}
		}
	}

	// 3b. Duplicate ids-option FAMILY block within ONE profile. This is not a
	// named container — the duplicate is the family keyword itself — so it
	// keeps its own walk. compileScreen reads each family with FindChild, so a
	// repeat is first-sibling-only, not last-writer-wins. Inspect the packed
	// body expansion too: `ids-option s1 icmp ... icmp ...;` has no authored
	// family children, but packedBody synthesizes the same siblings
	// compileScreen will consume.
	idsSchema := schemaForPath("security", "screen", "ids-option")
	for _, child := range tree.Children {
		if child.Name() != "security" {
			continue
		}
		for _, screen := range child.FindChildren("screen") {
			for _, inst := range namedInstances(screen.FindChildren("ids-option")) {
				if inst.name == "" {
					continue // already recorded by the table walk above
				}
				famSeen := map[string]bool{}
				famReported := map[string]bool{}
				body := packedBody(inst.node, idsSchema)
				for _, fam := range body.Children {
					fn := fam.Name()
					if !screenIDSFamily[fn] {
						continue
					}
					if famSeen[fn] {
						if !famReported[fn] {
							dups = append(dups, dupBlock{
								kind:   fmt.Sprintf("screen ids-option %q family", inst.name),
								name:   fn,
								effect: dupEffectFirstWins,
							})
							famReported[fn] = true
						}
						continue
					}
					famSeen[fn] = true
				}
			}
		}
	}

	// 4. Singleton containers (singletonDupRules) — #6768. These carry no name,
	// so the duplicate IS the keyword. compileServices reads each with
	// FindChild, so every block after the first is silently ignored in full.
	for _, rule := range singletonDupRules {
		want := make(map[string]bool, len(rule.keywords))
		for _, k := range rule.keywords {
			want[k] = true
		}
		seen := map[string]bool{}
		reported := map[string]bool{}
		for _, child := range tree.Children {
			if child.Name() != rule.stanza {
				continue
			}
			holders := []*Node{child}
			if rule.inner != "" {
				holders = child.FindChildren(rule.inner)
			}
			for _, holder := range holders {
				for _, c := range holder.Children {
					name := c.Name()
					if !want[name] || c.IsLeaf {
						continue
					}
					if seen[name] {
						if !reported[name] {
							dups = append(dups, dupBlock{rule.kind, name, dupEffectFirstWins})
							reported[name] = true
						}
						continue
					}
					seen[name] = true
				}
			}
		}
	}

	// #8704: containers that sit below a named-instance level, which
	// namedDupRule's stanza/inner/keyword shape cannot express. Folded in here
	// rather than given their own emit path so they inherit the SAME message
	// vocabulary on both paths — dupEffectStrict / dupEffectLenient already
	// distinguish first-wins / last-wins / split-instances, and a second
	// diagnostic vocabulary for the same defect is how the two drift.
	dups = append(dups, findDeepDupBlocks(tree)...)

	if len(dups) == 0 && len(emptyKinds) == 0 {
		return nil, nil
	}
	// Deterministic order: kind, then name.
	sort.Slice(dups, func(i, j int) bool {
		if dups[i].kind != dups[j].kind {
			return dups[i].kind < dups[j].kind
		}
		return dups[i].name < dups[j].name
	})
	sort.Strings(emptyKinds)

	if !lenient {
		// Duplicates keep first-error priority so the pre-#6455 messages are
		// unchanged when no empty name is present.
		if len(dups) > 0 {
			d := dups[0]
			return nil, fmt.Errorf("duplicate %s %q: %s — author it once (flat `set` "+
				"merges repeated statements automatically) (#5180)",
				d.kind, d.name, dupEffectStrict(d.effect))
		}
		return nil, emptyNameError(emptyKinds[0])
	}

	warnings := make([]string, 0, len(dups)+len(emptyKinds))
	for _, d := range dups {
		warnings = append(warnings, fmt.Sprintf("duplicate %s %q: %s — author it "+
			"once to avoid silently losing config (#5180)",
			d.kind, d.name, dupEffectLenient(d.effect)))
	}
	for _, k := range emptyKinds {
		warnings = append(warnings, emptyNameWarning(k))
	}
	return warnings, nil
}

// groupDefinitionName extracts the group name from a group-definition node,
// mirroring the extraction in ConfigTree.expandGroups (ast_groups.go): the name
// is Keys[0], or Keys[1] when the node carries a merged two-key head.
func groupDefinitionName(g *Node) string {
	if len(g.Keys) < 1 {
		return ""
	}
	if len(g.Keys) > 1 {
		return g.Keys[1]
	}
	return g.Keys[0]
}

// dupContainerEffect names WHAT a duplicate costs for one container, so the
// operator message states the truth for that container instead of a single
// blanket sentence. The three shapes differ, and saying "the earlier block is
// dropped" about a first-sibling-only read would be exactly backwards.
type dupContainerEffect int

const (
	// dupEffectLastWins: the compiler stores by name into a map, so the LAST
	// authored block replaces the earlier one wholesale.
	dupEffectLastWins dupContainerEffect = iota
	// dupEffectFirstWins: the compiler reads the container with FindChild —
	// the FIRST sibling only — so every LATER block is silently ignored.
	dupEffectFirstWins
	// dupEffectSplitInstances: the compiler loops over every instance with
	// per-instance local state, so neither block is dropped but neither sees
	// the other's settings; children authored under one block do not inherit
	// what was authored under the other.
	dupEffectSplitInstances
)

// namedDupRule describes one NAMED container to check for duplicate
// hierarchical siblings: `<stanza> { [<inner> {] <keyword> <name> { … } [}] }`.
//
// The four original #5180 checks were four hand-written copies of this walk.
// Two of them (screen ids-option, login user) are exactly this shape and are
// now table rows; `groups` and `interfaces` keep bespoke walks because their
// name extraction and skip rules genuinely differ (a merged two-key head, and
// the non-interface keyword allowlist). A divergence between copies of one walk
// is always a bug, so the copies that CAN be single-sourced are.
type namedDupRule struct {
	stanza  string // top-level stanza, e.g. "security"
	inner   string // optional intermediate container, "" if none
	keyword string // the named container keyword, e.g. "stream"
	kind    string // human category used in the message and the empty-name report
	effect  dupContainerEffect
}

// singletonDupRule describes an UNNAMED container that may legitimately be
// authored only once: `<stanza> { [<inner> {] <keyword> { … } [}] }`. The
// compiler reads it with FindChild, so a repeat is not last-writer-wins — every
// later block is silently ignored.
type singletonDupRule struct {
	stanza   string
	inner    string
	keywords []string
	kind     string
}

// namedDupRules and singletonDupRules are the registry this gate walks. Adding
// a container is one row; the walk itself exists once.
//
// #6768 added the six rows below the original two. They were derived from the
// stated predicate — a container that can be authored twice as a hierarchical
// sibling and whose compile silently loses configuration the FLAT spelling
// would have merged — not from the three effects the issue happened to name.
// Each was measured at master before it was added; see
// duplicate_container_6768_test.go, which reproduces the loss for every row.
var namedDupRules = []namedDupRule{
	{stanza: "security", inner: "screen", keyword: "ids-option", kind: "screen ids-option", effect: dupEffectLastWins},
	{stanza: "system", inner: "login", keyword: "user", kind: "login user", effect: dupEffectLastWins},

	// #6768. `security log stream <n>` and `profile <n>` are stored as
	// Streams[name] / Profiles[name] (compiler_security_log.go), so a second
	// block replaces the first — measured: a stream authored with
	// `transport { protocol tls; }` in the first block and `severity info` in
	// the second compiles to severity=info and NO transport at all, which is
	// the TLS syslog transport silently reverting to plain UDP.
	{stanza: "security", inner: "log", keyword: "stream", kind: "security log stream", effect: dupEffectLastWins},
	{stanza: "security", inner: "log", keyword: "profile", kind: "security log profile", effect: dupEffectLastWins},

	// #6768. `protocols bgp group <n>` is compiled by a loop with per-instance
	// local state (compiler_protocols.go: groupExport, peerAS, … are declared
	// inside the namedInstances range), so two blocks do not merge — measured:
	// `group g { peer-as 65001; export P; }` plus `group g { neighbor N; }`
	// compiles N with peerAS=0 and export=[]. The export policy the operator
	// authored never reaches the neighbour, and only the peer-as half warns.
	{stanza: "protocols", inner: "bgp", keyword: "group", kind: "bgp group", effect: dupEffectSplitInstances},

	// #8433. `security ike proposal <n>` and `security ipsec proposal <n>` are
	// stored as IKEProposals[name] / Proposals[name] (compiler_ipsec.go), so a
	// second block replaces the first. Measured at master before adding the
	// rows, which is what the predicate above asks for:
	//
	//   ike proposal P1 { authentication-method pre-shared-keys; dh-group group14; }
	//   ike proposal P1 { authentication-algorithm sha-256; encryption-algorithm aes-256-cbc; }
	//     -> method="" dh=0 — the whole first block is gone
	//
	//   ipsec proposal Q1 { protocol esp; }
	//   ipsec proposal Q1 { authentication-algorithm hmac-sha-256-128; encryption-algorithm aes-256-cbc; }
	//     -> protocol="" — the ESP selection is gone
	//
	// This is worse than the average last-wins row. A proposal with no
	// authentication-method, no DH group or no protocol is not a weaker tunnel;
	// it is an INCOMPLETE crypto proposal, and the operator authored every part
	// of it. The flat spelling merges the two blocks correctly, so this is a
	// hierarchical-file / `load merge` hazard rather than a `set` one.
	{stanza: "security", inner: "ike", keyword: "proposal", kind: "ike proposal", effect: dupEffectLastWins},
	{stanza: "security", inner: "ipsec", keyword: "proposal", kind: "ipsec proposal", effect: dupEffectLastWins},
}

var singletonDupRules = []singletonDupRule{}

// dupEffectStrict / dupEffectLenient render what a duplicate actually costs for
// one container. The original single sentence said the EARLIER block is
// dropped, which is true for a last-writer-wins map store and exactly backwards
// for a FindChild first-sibling-only read — a wrong message here is a wrong
// diagnosis, not a wording nit, because it sends the operator to delete the
// wrong block.
func dupEffectStrict(e dupContainerEffect) string {
	switch e {
	case dupEffectFirstWins:
		return "the compiler reads only the FIRST block, so every later block is " +
			"silently ignored in full"
	case dupEffectSplitInstances:
		return "each block is compiled independently with its own state, so " +
			"settings authored in one block do not reach children authored in the " +
			"other — the config is silently split, not merged"
	default:
		return "a repeated hierarchical block is silently reduced to " +
			"last-writer-wins, dropping the earlier block's configuration"
	}
}

func dupEffectLenient(e dupContainerEffect) string {
	switch e {
	case dupEffectFirstWins:
		return "only the FIRST hierarchical block is read (every later block ignored)"
	case dupEffectSplitInstances:
		return "each hierarchical block compiles independently, so neither sees the " +
			"other's settings"
	default:
		return "only the LAST hierarchical block is kept (earlier block dropped)"
	}
}
