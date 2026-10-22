package cli

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/cmdtree"
	"github.com/psaab/xpf/pkg/config"
)

// completionNode is an alias for the canonical cmdtree.Node type.
type completionNode = cmdtree.Node

// operationalTree references the canonical tree in pkg/cmdtree.
var operationalTree = cmdtree.OperationalTree

// configTopLevel references the canonical config tree in pkg/cmdtree.
var configTopLevel = cmdtree.ConfigTopLevel

// completionCandidate holds a command name and its description.
type completionCandidate struct {
	name string
	desc string
}

// cliCompleter implements readline.AutoCompleter.
type cliCompleter struct {
	cli         *CLI
	helpWritten bool // set by ? Listener to suppress duplicate help from Do()
}

// helpWriter returns the io.Writer that completion help is drawn to. It is the
// readline-managed stdout when a readline instance is wired (the live CLI),
// and io.Discard otherwise. The nil guard lets Do() run without a readline
// instance — both for tests that drive the completer directly and as a
// defensive measure against a completion firing before Run() wires c.rl
// (#2288).
func (cc *cliCompleter) helpWriter() io.Writer {
	if cc.cli != nil && cc.cli.rl != nil {
		return cc.cli.rl.Stdout()
	}
	return io.Discard
}

func (cc *cliCompleter) Do(line []rune, pos int) ([][]rune, int) {
	// If the ? Listener already wrote help, suppress duplicate output.
	if cc.helpWritten {
		cc.helpWritten = false
		return nil, 0
	}

	text := string(line[:pos])

	// Pipe filter completion: "show ... | <tab>"
	if pipeCandidates, handled := completePipeFilter(text); handled {
		if len(pipeCandidates) == 0 {
			return nil, 0
		}
		// Determine partial (text after "| ")
		idx := strings.LastIndex(text, "|")
		after := strings.TrimLeft(text[idx+1:], " ")
		partial := after

		sort.Slice(pipeCandidates, func(i, j int) bool { return pipeCandidates[i].name < pipeCandidates[j].name })
		if len(pipeCandidates) == 1 {
			suffix, ok := completionSuffix(pipeCandidates[0].name, partial)
			if !ok {
				return nil, 0
			}
			return [][]rune{[]rune(suffix + " ")}, len(partial)
		}
		writeCompletionHelp(cc.helpWriter(), pipeCandidates)
		names := make([]string, len(pipeCandidates))
		for i, c := range pipeCandidates {
			names[i] = c.name
		}
		cp := commonPrefix(names)
		suffix, ok := completionSuffix(cp, partial)
		if !ok || suffix == "" {
			return nil, 0
		}
		return [][]rune{[]rune(suffix)}, len(partial)
	}

	words := strings.Fields(text)
	trailingSpace := len(text) > 0 && text[len(text)-1] == ' '

	var partial string
	if !trailingSpace && len(words) > 0 {
		partial = words[len(words)-1]
		words = words[:len(words)-1]
	}

	// #14988: TAB goes through the same gated computation as `?`.
	candidates := cc.cli.completeForHelp(words, partial)
	if len(candidates) == 0 {
		return nil, 0
	}

	sort.Slice(candidates, func(i, j int) bool { return candidates[i].name < candidates[j].name })

	if len(candidates) == 1 {
		suffix, ok := completionSuffix(candidates[0].name, partial)
		if !ok {
			return nil, 0
		}
		return [][]rune{[]rune(suffix + " ")}, len(partial)
	}

	// Multiple matches: show descriptions above prompt.
	writeCompletionHelp(cc.helpWriter(), candidates)

	// Complete common prefix.
	names := make([]string, len(candidates))
	for i, c := range candidates {
		names[i] = c.name
	}
	cp := commonPrefix(names)
	suffix, ok := completionSuffix(cp, partial)
	if !ok || suffix == "" {
		return nil, 0
	}
	return [][]rune{[]rune(suffix)}, len(partial)
}

// completeConfigWithDesc is kept for existing callers/tests; it now
// routes through the #14988 gated computation (completeForHelp's
// config arm) so no caller can reach the ungated schema/tree.
func (c *CLI) completeConfigWithDesc(words []string, partial string) []completionCandidate {
	auth := c.completionAuthz()
	return c.completeConfigWithDescAuth(&auth, words, partial)
}

// resolveCommand performs Junos-style prefix matching.
// Given a partial input and a list of valid commands, it returns:
// - The full command name if exactly one match
// - "" and an error if ambiguous (multiple matches)
// - "" and an error if no match
func resolveCommand(input string, validCommands []string) (string, error) {
	if input == "" {
		return "", fmt.Errorf("missing command")
	}
	// Exact match first
	for _, cmd := range validCommands {
		if cmd == input {
			return cmd, nil
		}
	}
	// Prefix match
	var matches []string
	for _, cmd := range validCommands {
		if strings.HasPrefix(cmd, input) {
			matches = append(matches, cmd)
		}
	}
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("unknown command: %s", input)
	case 1:
		return matches[0], nil
	default:
		sort.Strings(matches)
		return "", fmt.Errorf("'%s' is ambiguous.\nPossible completions:\n%s",
			input, formatAmbiguousMatches(matches))
	}
}

func formatAmbiguousMatches(matches []string) string {
	var sb strings.Builder
	maxWidth := 0
	for _, m := range matches {
		if len(m) > maxWidth {
			maxWidth = len(m)
		}
	}
	for _, m := range matches {
		sb.WriteString(fmt.Sprintf("  %s\n", m))
	}
	return sb.String()
}

// completeFromTreeWithDesc mirrors completeFromTree but returns name+desc pairs.
func completeFromTreeWithDesc(tree map[string]*completionNode, words []string, partial string, cfg *config.Config) []completionCandidate {
	treeCands := cmdtree.CompleteFromTreeWithDesc(tree, words, partial, cfg)
	candidates := make([]completionCandidate, 0, len(treeCands))
	for _, c := range treeCands {
		candidates = append(candidates, completionCandidate{name: c.Name, desc: c.Desc})
	}
	return candidates
}

// writeCompletionHelp prints aligned completion candidates to w.
// The entire output is built as a single string and written in one call
// so that the readline wrapWriter triggers only one Refresh cycle,
// cleanly re-drawing the prompt+line below.
func writeCompletionHelp(w io.Writer, candidates []completionCandidate) {
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].name < candidates[j].name })
	maxWidth := 20
	for _, c := range candidates {
		if len(c.name)+2 > maxWidth {
			maxWidth = len(c.name) + 2
		}
	}
	var sb strings.Builder
	sb.WriteString("Possible completions:\n")
	for _, c := range candidates {
		if c.desc != "" {
			fmt.Fprintf(&sb, "  %-*s %s\n", maxWidth, c.name, c.desc)
		} else {
			fmt.Fprintf(&sb, "  %s\n", c.name)
		}
	}
	io.WriteString(w, sb.String())
}

// keysFromTree returns a sorted list of keys from a completionNode map.
// Delegates to cmdtree.KeysFromTree.
func keysFromTree(tree map[string]*completionNode) []string {
	return cmdtree.KeysFromTree(tree)
}

// treeHelpCandidates returns completionCandidates from a tree's children.
func treeHelpCandidates(tree map[string]*completionNode) []completionCandidate {
	candidates := make([]completionCandidate, 0, len(tree))
	for name, node := range tree {
		candidates = append(candidates, completionCandidate{name: name, desc: node.Desc})
	}
	return candidates
}

func filterTreeCandidates(tree map[string]*completionNode, prefix string) []completionCandidate {
	candidates := make([]completionCandidate, 0, len(tree))
	for name, node := range tree {
		if prefix == "" || strings.HasPrefix(name, prefix) {
			candidates = append(candidates, completionCandidate{name: name, desc: node.Desc})
		}
	}
	return candidates
}

func resolveUniqueTreePrefix(tree map[string]*completionNode, input string) (string, bool) {
	return cmdtree.ResolveUniquePrefix(keysFromTree(tree), input)
}

func showConfigurationSubPath(words []string) ([]string, bool) {
	if len(words) < 2 {
		return nil, false
	}
	show, ok := resolveUniqueTreePrefix(operationalTree, words[0])
	if !ok || show != "show" {
		return nil, false
	}
	showNode := operationalTree[show]
	if showNode == nil || showNode.Children == nil {
		return nil, false
	}
	conf, ok := resolveUniqueTreePrefix(showNode.Children, words[1])
	if !ok || conf != "configuration" {
		return nil, false
	}
	return words[2:], true
}

// commonPrefix returns the longest shared prefix among the given strings.
func commonPrefix(items []string) string {
	return cmdtree.CommonPrefix(items)
}

// completionSuffix returns the portion of name that follows the already-typed
// partial, suitable for echoing back to readline. It guards the slice
// expression name[len(partial):] against panics: candidate names can be
// SHORTER than the typed partial (e.g. an over-typed token like "show f zzzzz"
// where cmdtree returns the unfiltered "f" matches and commonPrefix("filter",
// "flow") = "f" is shorter than "zzzzz"), and they need not even share a prefix
// with partial. Returns (suffix, true) only when name is a genuine extension of
// partial (name has partial as a prefix); otherwise (\"\", false) so callers
// emit no completion instead of crashing (#2288).
func completionSuffix(name, partial string) (string, bool) {
	if len(partial) > len(name) || !strings.HasPrefix(name, partial) {
		return "", false
	}
	return name[len(partial):], true
}

// pipeFilters defines the available pipe filter names and descriptions.
var pipeFilters = []completionCandidate{
	{name: "count", desc: "Count occurrences"},
	{name: "display", desc: "Show additional kinds of information"},
	{name: "except", desc: "Show only text that does not match a pattern"},
	{name: "find", desc: "Search for first occurrence of pattern"},
	{name: "grep", desc: "Show only text that matches a pattern"},
	{name: "last", desc: "Display end of output only"},
	{name: "match", desc: "Show only text that matches a pattern"},
	{name: "no-more", desc: "Don't paginate output"},
}

// completePipeFilter returns pipe filter candidates matching the partial prefix.
// Returns nil if the line doesn't contain a pipe.
func completePipeFilter(text string) (candidates []completionCandidate, handled bool) {
	idx := strings.LastIndex(text, "|")
	if idx < 0 {
		return nil, false
	}
	after := strings.TrimSpace(text[idx+1:])
	trailingSpace := len(text) > 0 && text[len(text)-1] == ' '

	// Right after "|" or "| " — show all filters
	if after == "" || (trailingSpace && after == "") {
		return pipeFilters, true
	}

	// If trailing space, user has already typed a complete filter name —
	// no more completion (the filter argument is freeform text).
	if trailingSpace {
		return nil, true
	}

	// Partial filter name typed
	for _, f := range pipeFilters {
		if strings.HasPrefix(f.name, after) {
			candidates = append(candidates, f)
		}
	}
	return candidates, true
}

// completionConfig returns the config completion draws from and whether
// the predefined catalogue is suppressed (#15272 B24-04, #5763): in
// config mode a candidate compile cached by generation, so candidate-
// created names are offered and candidate-deleted names are not;
// otherwise (or when the candidate does not compile) the active config.
// The catalogue stays suppressed until the first commit (#5763).
func (c *CLI) completionConfig() (*config.Config, bool) {
	if c == nil || c.store == nil {
		return nil, false
	}
	if c.store.InConfigMode() {
		if cfg, ok := c.store.CandidateConfigForCompletion(); ok {
			// #5763: the predefined catalogue is gated on a committed
			// config, not on candidate presence.
			return cfg, !c.store.EverCommitted()
		}
	}
	return c.store.ActiveConfig(), false
}

// valueProvider delegates to the shared config.ProvideValues (#16160).
// Snapshot acquisition (completionConfig) stays here because it is
// per-frontend store/candidate logic; the nil-config guard mirrors the
// pre-share behaviour (no config, no live values).
func (c *CLI) valueProvider(hint config.ValueHint, path []string) []config.SchemaCompletion {
	cfg, catalogueSuppressed := c.completionConfig()
	if cfg == nil {
		return nil
	}
	return config.ProvideValues(cfg, hint, path, catalogueSuppressed)
}
