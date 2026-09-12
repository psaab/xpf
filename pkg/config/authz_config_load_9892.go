package config

import (
	"fmt"
	"strings"
)

// #9892: `load` BYPASSED THE deny-configuration REGEXES ON TWO OF THREE
// SURFACES, AND THE CLI'S BYPASS WAS THE QUIET ONE.
//
// A `*-configuration` regex is an authorization control over configuration
// mutation, so a denied path must stay denied whatever verb carries it. `load`
// is the verb that can carry EVERY denied path at once — `load override`
// replaces the whole candidate and `load merge` can bring a whole denied
// subtree in one call (up to 16 MiB on REST).
//
// State before this file:
//
//   - gRPC: CLOSED by #9633, which evaluated set/merge content line by line and
//     refused override for a restricted class.
//   - REST: `load` was absent from restConfigMutationRoutes, recorded there as a
//     stated remaining gap.
//   - CLI: worse than absent. cli_dispatch.go DOES call checkConfigRegex on
//     every config-mode line INCLUDING `load` — the gate runs. It delegates to
//     configMutationPath, which returns ok=false for any verb not in
//     configMutationVerbs, and `load` is not in that map. So the gate executed,
//     declined to adjudicate, and returned nil. A reader auditing that path
//     sees a gate on it.
//
// ONE EVALUATOR, THREE CALLERS. The content parsing lives here rather than in
// each surface because two copies of "render hierarchical content as set lines"
// drift, and the drift is invisible: each copy looks right on its own. This is
// also why the gRPC implementation moved here rather than being duplicated —
// #9633's logic is the reference, and there is now exactly one of it.

// loadFlatVerbs are the first words that make a load body set-format. They are
// the mutation verbs AuthorizeConfigMutation gates, because a set-format body
// is a sequence of exactly those lines.
var loadFlatVerbs = map[string]bool{
	"set": true, "delete": true, "deactivate": true, "activate": true,
	"copy": true, "rename": true, "insert": true, "annotate": true,
}

// LoadMutationLines returns the set-form mutation lines a load body writes.
//
// Set-format content is taken line by line. Hierarchical content is parsed and
// rendered as set lines, so every leaf path it writes is checked. Content that
// does not parse yields its parsed part; the store's own Load refuses what it
// cannot parse, and adjudicating the parsable part is strictly better than
// adjudicating nothing.
func LoadMutationLines(content string) []string {
	var lines []string
	flat := false
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if f := strings.Fields(line); len(f) > 0 && loadFlatVerbs[f[0]] {
			flat = true
			lines = append(lines, line)
		}
	}
	if flat {
		return lines
	}
	tree, _ := NewParser(content).Parse()
	if tree == nil {
		return nil
	}
	for _, line := range strings.Split(tree.FormatSet(), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// AuthorizeConfigLoad adjudicates a `load` against the caller's configuration
// regexes. mode is "override", "merge" or "set"; content is the body.
//
// `override` is REFUSED for a restricted class rather than adjudicated, and
// that distinction is deliberate: it replaces the entire candidate, so the
// paths it DELETES cannot be enumerated one by one. Refusal is the honest
// answer, and the docs must say refusal rather than implying coverage.
func AuthorizeConfigLoad(cfg *Config, class, mode, content string) error {
	if class == "" {
		return nil
	}
	_, restricted, err := ConfigurationLoginRegexesFor(cfg, class)
	if err != nil {
		return fmt.Errorf("permission denied: login class %q has an invalid configuration regex: %w", class, err)
	}
	if !restricted {
		return nil
	}
	if mode == "override" {
		return fmt.Errorf("permission denied: login class %q restricts configuration paths, and "+
			"load override replaces the whole candidate, so the paths it deletes cannot be "+
			"adjudicated one by one; use load merge or load set (#9892)", class)
	}
	for _, line := range LoadMutationLines(content) {
		if err := AuthorizeConfigMutation(cfg, class, nil, line); err != nil {
			return err
		}
	}
	return nil
}

// AuthorizeConfigRollback adjudicates `rollback n` for a restricted class.
//
// Same shape as load override and closed here for the same reason: `rollback n`
// for n>0 replaces the candidate with an older configuration whose paths cannot
// be adjudicated individually. `rollback 0` returns the candidate to the
// COMMITTED configuration — every path in which was adjudicated when it was
// written — and stays available.
//
// Included with #9892 because it is the identical mechanism on the identical
// surfaces: #9633 closed it on gRPC, and the REST route table's own exemption
// text already said rollback was "the same class as load". Closing one and not
// the other would leave a gap whose own documentation admits it.
func AuthorizeConfigRollback(cfg *Config, class string, n int) error {
	if class == "" || n == 0 {
		return nil
	}
	_, restricted, err := ConfigurationLoginRegexesFor(cfg, class)
	if err != nil {
		return fmt.Errorf("permission denied: login class %q has an invalid configuration regex: %w", class, err)
	}
	if !restricted {
		return nil
	}
	return fmt.Errorf("permission denied: login class %q restricts configuration paths, and "+
		"rollback %d replaces the candidate with an older configuration whose paths cannot "+
		"be adjudicated one by one; rollback 0 remains available (#9892)", class, n)
}
