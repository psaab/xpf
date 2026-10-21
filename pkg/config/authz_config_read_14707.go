package config

import (
	"fmt"
	"strings"
)

// #14707: configuration READS were never adjudicated against the
// *-configuration regexes or the path/format-scoped *-commands regexes.
//
// ShowConfig / ShowCompare / ShowRollback (and their REST twins) rendered
// the full secret-redacted tree for any class the coarse permission bits
// admitted. deny-configuration "^security" denied `set security …` on
// every surface yet concealed nothing on read, and deny-commands
// "^show configuration security" or "display set" never fired because
// the gRPC gate flattened the RPC to the bare "show configuration".
// #14144 fixed Complete by reference to what "ShowConfig/Set conceal" —
// ShowConfig did not, in fact, conceal it. This file is the shared read
// decision so gRPC and REST cannot drift on it.
//
// Semantics, deliberately mirroring the surfaces operators already know:
//
//   - An explicit subtree path is adjudicated exactly as the CLI
//     adjudicates `show configuration <path>`: the configuration regexes
//     on the joined path (the same string checkConfigRegex /
//     AuthorizeConfigMutation evaluate, minus the verb) AND the
//     operational regexes on "show configuration <path>" with the bare
//     "show configuration" as an alternate form (EvaluateForms), so an
//     anchored `^show configuration$` still covers sub-paths and a
//     path-scoped `^show configuration security` fires.
//   - #15995: a subtree render discloses every descendant of the
//     requested path, so the path verdict alone is not the render's
//     price. AuthorizeConfigShowPathRendered (and the tree-aware
//     wrappers the surfaces call) additionally adjudicate every
//     rendered descendant path of the tree(s) that will actually be
//     rendered: a strict descendant the *-configuration pair denies —
//     or an allow-configuration allowlist does not cover — refuses the
//     ancestor read, exactly as the whole-tree refusal below refuses
//     what cannot be enumerated. The operational pair is NOT charged
//     per descendant: `show configuration security` is one command,
//     and a `^show configuration security ipsec$` deny is a command
//     spelling the operator never typed (mirroring whole-tree, where
//     a path-scoped operational deny does not refuse). A class with
//     no configuration regexes pays no tree walk.
//   - A whole-tree render, a candidate diff, and a rollback render have
//     no single path: like AuthorizeConfigLoad's override arm and
//     AuthorizeConfigRollback, they are REFUSED for a class with
//     configuration regexes, because the subtrees they would disclose
//     cannot be enumerated from the request. For the operational pair
//     the whole render is the bare `show configuration` command; a
//     path-scoped deny does not refuse it, a bare deny does.
//   - A class with no regexes in a family is untouched by that family.
//     An invalid regex denies (fail closed, as every sibling gate).
//   - Format is part of the operational command: `| display set` (and
//     json/xml/inheritance) reformats what a deny may withhold, exactly
//     as the CLI counts the pipe as part of the command (#7172). The
//     hierarchical form carries no suffix.

// AuthorizeConfigShowPath adjudicates an explicit `show configuration
// <path>` subtree read WITHOUT the rendered trees: only the requested
// path is priced. Prefer AuthorizeConfigShowPathRendered wherever the
// rendered tree is available — this form cannot see denied strict
// descendants below path (#15995) and remains only for callers that
// have already priced the descendants (AuthorizeConfigPathOnly's CLI
// arm, whose operational pair was charged on the full command line).
// displaySuffix is "display set" / "display json" / "display xml" /
// "display inheritance", or "" for the hierarchical form.
func AuthorizeConfigShowPath(cfg *Config, class string, path []string, displaySuffix string) error {
	if class == "" {
		return nil
	}
	joined := strings.Join(path, " ")
	if err := authorizeConfigReadPath(cfg, class, joined); err != nil {
		return err
	}
	return authorizeShowCommand(cfg, class, "show configuration "+joined, displaySuffix)
}

// AuthorizeConfigShowPathRendered adjudicates an explicit subtree read
// against every path the render will disclose: the requested path plus
// every descendant path present in trees (the tree(s) the handler will
// render — active/candidate for ShowConfig, both compare arms for a
// scoped compare, the rollback slot for a scoped rollback). A strict
// descendant denied by the *-configuration pair (deny match, or outside
// an allow-configuration allowlist) refuses the whole ancestor read;
// filtering the denied subtree out of the render instead would silently
// present a partial tree as the requested subtree. Nil trees are
// skipped (a missing candidate renders nothing). The operational pair
// is charged once, on the requested command, as in
// AuthorizeConfigShowPath.
func AuthorizeConfigShowPathRendered(cfg *Config, class string, path []string, displaySuffix string, trees ...*ConfigTree) error {
	if class == "" {
		return nil
	}
	if err := AuthorizeConfigShowPath(cfg, class, path, displaySuffix); err != nil {
		return err
	}
	return authorizeConfigRenderedDescendants(cfg, class, path, trees)
}

// AuthorizeConfigShowCompareAtPathRendered is
// AuthorizeConfigShowCompareAtPath priced over the rendered compare
// arms: a candidate (or rollback) descendant below path that the
// *-configuration pair denies refuses the scoped diff, because the
// diff lines disclose it (#15995). A nil/empty path is the global
// compare (AuthorizeConfigShowCompare).
func AuthorizeConfigShowCompareAtPathRendered(cfg *Config, class string, path []string, trees ...*ConfigTree) error {
	if class == "" || len(path) == 0 {
		return AuthorizeConfigShowCompare(cfg, class)
	}
	return AuthorizeConfigShowPathRendered(cfg, class, path, "", trees...)
}

// AuthorizeConfigShowRollbackAtPathRendered is
// AuthorizeConfigShowRollbackAtPath priced over the rendered rollback
// tree: a denied strict descendant below path refuses the scoped
// rollback render (#15995). A nil/empty path is the whole-tree
// rollback (AuthorizeConfigShowRollback).
func AuthorizeConfigShowRollbackAtPathRendered(cfg *Config, class string, path []string, displaySuffix string, trees ...*ConfigTree) error {
	if class == "" || len(path) == 0 {
		return AuthorizeConfigShowRollback(cfg, class, displaySuffix)
	}
	return AuthorizeConfigShowPathRendered(cfg, class, path, displaySuffix, trees...)
}

// authorizeConfigRenderedDescendants adjudicates every descendant path
// of path present in any of trees against the *-configuration pair.
// The requested path itself was already adjudicated by the caller;
// only strict descendants are priced here. A class with no
// configuration regexes returns before any tree is touched, so the
// common unrestricted read pays nothing.
func authorizeConfigRenderedDescendants(cfg *Config, class string, path []string, trees []*ConfigTree) error {
	rules, ok, err := ConfigurationLoginRegexesFor(cfg, class)
	if err != nil {
		return fmt.Errorf("permission denied: login class %q has an invalid configuration regex: %w", class, err)
	}
	if !ok {
		return nil
	}
	for _, tree := range trees {
		if tree == nil {
			continue
		}
		matches := navigatePath(tree.Children, path)
		for _, m := range matches {
			if err := authorizeRenderedNode(cfg, class, rules, path, m); err != nil {
				return err
			}
		}
	}
	return nil
}

// authorizeRenderedNode prices n (already at prefix) and, recursively,
// every descendant path below it. The first denied descendant refuses
// the render, naming only the path root (configAuditRoot) as every
// sibling gate does — descendant identity tokens are operator data.
func authorizeRenderedNode(cfg *Config, class string, rules CompiledLoginRegexes, prefix []string, n *Node) error {
	for _, child := range n.Children {
		childPath := append(append([]string(nil), prefix...), child.Keys...)
		joined := strings.Join(childPath, " ")
		if decision := rules.Evaluate(joined); !decision.Allowed {
			return fmt.Errorf("permission denied: login class %q denies configuration under %q (%s); "+
				"the requested subtree %q renders that descendant, so the ancestor read is refused — "+
				"request an allowed subtree instead (#15995)",
				class, configAuditRoot(joined), decision.Reason, configAuditRoot(strings.Join(prefix, " ")))
		}
		if err := authorizeRenderedNode(cfg, class, rules, childPath, child); err != nil {
			return err
		}
	}
	return nil
}

// AuthorizeConfigShowWhole adjudicates a whole-tree configuration read
// (ShowConfig with no path, in any target/format). A class with
// configuration regexes is refused: the render includes subtrees the
// request cannot enumerate. The operational pair is evaluated against
// the bare command (plus format suffix).
func AuthorizeConfigShowWhole(cfg *Config, class string, displaySuffix string) error {
	if class == "" {
		return nil
	}
	if err := authorizeConfigWhole(cfg, class, "show configuration"); err != nil {
		return err
	}
	return authorizeShowCommand(cfg, class, "show configuration", displaySuffix)
}

// AuthorizeConfigShowCompare adjudicates a candidate diff render
// (ShowCompare, both arms). The diff discloses candidate content under
// arbitrary paths, so a configuration-restricted class is refused, as
// with load override. Operationally it is the bare `show configuration`.
func AuthorizeConfigShowCompare(cfg *Config, class string) error {
	if class == "" {
		return nil
	}
	if err := authorizeConfigWhole(cfg, class, "show configuration"); err != nil {
		return err
	}
	return authorizeShowCommand(cfg, class, "show configuration", "")
}

// AuthorizeConfigShowCompareAtPath adjudicates a candidate diff filtered
// to path (#15272 B24-03): the diff discloses only that subtree, so it is
// priced as a path read (AuthorizeConfigShowPath), not refused as a
// whole-tree render. A nil/empty path is the global compare.
func AuthorizeConfigShowCompareAtPath(cfg *Config, class string, path []string) error {
	if class == "" || len(path) == 0 {
		return AuthorizeConfigShowCompare(cfg, class)
	}
	return AuthorizeConfigShowPath(cfg, class, path, "")
}

// AuthorizeConfigShowRollback adjudicates a rollback-slot render
// (ShowRollback). Same whole-tree shape as AuthorizeConfigShowWhole.
func AuthorizeConfigShowRollback(cfg *Config, class string, displaySuffix string) error {
	if class == "" {
		return nil
	}
	if err := authorizeConfigWhole(cfg, class, "show system rollback"); err != nil {
		return err
	}
	return authorizeShowCommand(cfg, class, "show configuration", displaySuffix)
}

// AuthorizeConfigShowRollbackAtPath adjudicates a rollback-slot render
// scoped to path (#15942 H2-04): the render discloses only that
// subtree, so it is priced as a path read (AuthorizeConfigShowPath),
// not refused as a whole-tree render and not waved through by a gate
// that never saw the path. A nil/empty path is the whole-tree rollback
// (AuthorizeConfigShowRollback).
func AuthorizeConfigShowRollbackAtPath(cfg *Config, class string, path []string, displaySuffix string) error {
	if class == "" || len(path) == 0 {
		return AuthorizeConfigShowRollback(cfg, class, displaySuffix)
	}
	return AuthorizeConfigShowPath(cfg, class, path, displaySuffix)
}

// AuthorizeConfigShowSystemPath adjudicates an operational
// `show system <subtree>` render of an explicit configuration path
// (login, root-authentication): *-configuration on the path,
// *-commands on the real command spelling `show system <name>` with
// the bare `show configuration` as alternate form (mirroring
// AuthorizeConfigShowRollback's alternate-form shape), so an anchored
// `^show configuration$` deny covers these renders and a path-scoped
// `show system login` deny fires. Added for #14987.
func AuthorizeConfigShowSystemPath(cfg *Config, class string, path []string, command string) error {
	if class == "" {
		return nil
	}
	joined := strings.Join(path, " ")
	if err := authorizeConfigReadPath(cfg, class, joined); err != nil {
		return err
	}
	return authorizeShowCommand(cfg, class, command, "")
}

// AuthorizeConfigShowRescue adjudicates `show system configuration
// rescue`: a whole-tree text render, refused for a *-configuration-
// restricted class like AuthorizeConfigShowWhole, and evaluated
// operationally on its real spelling with the bare form as alternate.
// Added for #14987.
func AuthorizeConfigShowRescue(cfg *Config, class string) error {
	if class == "" {
		return nil
	}
	if err := authorizeConfigWhole(cfg, class, "show system configuration rescue"); err != nil {
		return err
	}
	return authorizeShowCommand(cfg, class, "show system configuration rescue", "")
}

func authorizeConfigReadPath(cfg *Config, class, joined string) error {
	rules, ok, err := ConfigurationLoginRegexesFor(cfg, class)
	if err != nil {
		return fmt.Errorf("permission denied: login class %q has an invalid configuration regex: %w", class, err)
	}
	if !ok {
		return nil
	}
	if decision := rules.Evaluate(joined); !decision.Allowed {
		return fmt.Errorf("permission denied: login class %q denies configuration under %q (%s)",
			class, configAuditRoot(joined), decision.Reason)
	}
	return nil
}

func authorizeConfigWhole(cfg *Config, class, what string) error {
	_, restricted, err := ConfigurationLoginRegexesFor(cfg, class)
	if err != nil {
		return fmt.Errorf("permission denied: login class %q has an invalid configuration regex: %w", class, err)
	}
	if !restricted {
		return nil
	}
	return fmt.Errorf("permission denied: login class %q restricts configuration paths, and "+
		"%s renders the whole configuration, so the subtrees it discloses cannot be "+
		"adjudicated one by one; request an allowed subtree instead (#14707)", class, what)
}

// AuthorizeConfigPathOnly adjudicates one config path against the
// *-configuration pair alone, WITHOUT the rendered trees. For surfaces
// that already charged the operational pair on the full command line
// (the on-box CLI's checkCommandRegex) and must not double-charge it
// against a shorter string. Prefer AuthorizeConfigPathOnlyRendered
// wherever the rendered tree is available (#15995).
func AuthorizeConfigPathOnly(cfg *Config, class string, path []string) error {
	if class == "" {
		return nil
	}
	return authorizeConfigReadPath(cfg, class, strings.Join(path, " "))
}

// AuthorizeConfigPathOnlyRendered is AuthorizeConfigPathOnly plus the
// rendered-descendant price (#15995): every strict descendant of path
// present in trees is adjudicated against the *-configuration pair,
// and a denied one refuses the ancestor read.
func AuthorizeConfigPathOnlyRendered(cfg *Config, class string, path []string, trees ...*ConfigTree) error {
	if class == "" {
		return nil
	}
	if err := AuthorizeConfigPathOnly(cfg, class, path); err != nil {
		return err
	}
	return authorizeConfigRenderedDescendants(cfg, class, path, trees)
}

// authorizeShowCommand evaluates the operational pair against the
// canonical show command. The bare "show configuration" is measured as
// an alternate form so an anchored deny on it covers sub-paths
// (EvaluateForms max-per-side, #9022 shape), and the display suffix is
// part of the matched string so "display set" fires.
func authorizeShowCommand(cfg *Config, class, command, displaySuffix string) error {
	rules, ok, err := OperationalLoginRegexesFor(cfg, class)
	if err != nil {
		return fmt.Errorf("permission denied: login class %q has an invalid command regex: %w", class, err)
	}
	if !ok {
		return nil
	}
	// #14987: callers pass the suffix in two spellings — the CLI's
	// displaySuffix14707 strips "display " to the bare format word
	// ("set"), while gRPC/REST pass ConfigShowDisplaySuffix output
	// ("display set"). The matched string must be the operator's
	// `| display set` in both cases; passing the bare word produced
	// `show configuration … | set`, which a `display set` deny never
	// matches. Normalize here, the one place the string is built.
	suffix := displaySuffix
	switch suffix {
	case "set", "json", "xml", "inheritance":
		suffix = "display " + suffix
	}
	full := command
	if suffix != "" {
		full = command + " | " + suffix
	}
	if decision := rules.EvaluateForms(full, "show configuration"); !decision.Allowed {
		return fmt.Errorf("permission denied: login class %q denies %q (%s)", class, command, decision.Reason)
	}
	return nil
}

// ConfigShowDisplaySuffix renders a display-format selector as the CLI
// pipe suffix operators write ("display set", …). format is the
// caller-surface spelling: "set", "json", "xml", "inheritance", or ""
// (hierarchical). Unknown spellings yield "" — the caller's own format
// validation rejects them; authorization must not invent a form.
func ConfigShowDisplaySuffix(format string) string {
	switch format {
	case "set", "json", "xml", "inheritance":
		return "display " + format
	}
	return ""
}
