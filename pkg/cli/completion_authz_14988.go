package cli

import (
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// #14988 (D37-03): TAB completion, `?` context help and the `help`
// command bypassed checkPermission, checkCommandRegex and
// ConfigurationLoginRegexesFor, leaking live ActiveConfig values.
// The gRPC Complete RPC was gated for the same disclosure in
// #14144/#14708/#14952; this is the on-box twin. The gate is at the
// DATA SOURCE, mirroring completionAuth there:
//
//   - coarse: a candidate whose command the class cannot run
//     (checkPermission on the candidate's full command line, plus a
//     canonical-prefix retry for partials) is not offered. Config-mode
//     candidates require the class to be able to enter configure at
//     all; `run …` candidates are priced as operational commands.
//   - *-commands: live cmdtree DynamicFn values are computed from a
//     nil config when any typed operational prefix is denied (nil-safe
//     providers, #5196), and `show configuration …` candidates are
//     withheld when the canonical command is denied.
//   - *-configuration: live valueProvider values are offered only for
//     allowed consumed paths (cursor AND the hint's owning subtree,
//     #14708); a denied consumed config path offers no candidates.
//
// Fail closed throughout: an unknown class, or a class whose regexes
// do not compile, gets no live values and (for the coarse gate, which
// checkPermission already denies) no candidates. An unset class (the
// legacy no-RBAC mode) and a class with no regexes in a family are
// untouched by that family, so neighbouring legitimate completion is
// bit-identical.

// completionAuthz is the session class's posture for one completion,
// resolved once per completion call from ActiveConfig.
type completionAuthz struct {
	unrestricted   bool // unset class: legacy no-RBAC mode
	identified     bool // class name is non-empty
	cfg            *config.Config
	confRules      config.CompiledLoginRegexes
	confRestricted bool
	confErr        bool
	opRules        config.CompiledLoginRegexes
	opRestricted   bool
	opErr          bool
}

func (c *CLI) completionAuthz() completionAuthz {
	if c == nil || c.userClass == "" {
		return completionAuthz{unrestricted: true}
	}
	a := completionAuthz{identified: true}
	if c.store != nil {
		a.cfg = c.store.ActiveConfig()
	}
	if a.cfg == nil {
		// No snapshot to evaluate against: suppress live values. The
		// coarse gate still applies (it resolves built-ins with nil cfg).
		a.confErr = true
		a.opErr = true
		return a
	}
	if rules, ok, err := config.ConfigurationLoginRegexesFor(a.cfg, c.userClass); err != nil {
		a.confErr = true
	} else {
		a.confRules, a.confRestricted = rules, ok
	}
	if rules, ok, err := config.OperationalLoginRegexesFor(a.cfg, c.userClass); err != nil {
		a.opErr = true
	} else {
		a.opRules, a.opRestricted = rules, ok
	}
	return a
}

// liveAllowed reports whether any live-config-derived value may be offered.
func (a completionAuthz) liveAllowed() bool {
	if a.unrestricted {
		return true
	}
	return a.identified && a.cfg != nil && !a.confErr && !a.opErr
}

// --- coarse permission gate -------------------------------------------

// operationalCandidateAllowed reports whether the class may run the
// operational command that candidate `name` at consumed `words` would
// start. The candidate command is judged as typed and, when that does
// not resolve, by canonical prefix expansion — the same two spellings
// checkPermission's abbreviation handling covers.
func (c *CLI) operationalCandidateAllowed(a *completionAuthz, words []string, name string) bool {
	if a.unrestricted {
		return true
	}
	parts := append(append([]string(nil), words...), name)
	if c.checkPermission(parts) == nil {
		return true
	}
	// A partial candidate/word may not resolve yet; if the typed prefix
	// expands uniquely to a canonical command, judge that instead.
	if canon := canonicalCompletionPrefix(words, name); len(canon) > 0 {
		return c.checkPermission(canon) == nil
	}
	// `?` (dispatchOperational's help verb) is not a command; never offer
	// help verbs as candidates (they are not in the trees, but stay safe).
	return false
}

// canonicalCompletionPrefix expands words+name through the operational
// tree's unique-prefix rule. Returns nil when any token does not
// uniquely resolve (ambiguous/unknown ⇒ fail closed at the caller).
func canonicalCompletionPrefix(words []string, name string) []string {
	toks := append(append([]string(nil), words...), name)
	current := operationalTree
	out := make([]string, 0, len(toks))
	for i, tok := range toks {
		resolved, ok := resolveUniqueTreePrefix(current, tok)
		if !ok {
			// Last token may be a value (dynamic/placeholder slot):
			// judge by the resolved keyword prefix alone.
			if i == len(toks)-1 && len(out) > 0 {
				return out
			}
			return nil
		}
		node := current[resolved]
		if node == nil {
			return nil
		}
		out = append(out, resolved)
		if node.Children == nil {
			if i == len(toks)-1 {
				return out
			}
			// Value tokens after a leaf: judge by the leaf command.
			return out
		}
		current = node.Children
	}
	return out
}

// filterOperationalCandidates drops candidates the coarse gate denies.
// Static keywords for an allowed command survive; only the command
// word itself is priced (its live values are priced separately).
func (c *CLI) filterOperationalCandidates(a *completionAuthz, words []string, cands []completionCandidate) []completionCandidate {
	if a.unrestricted || len(cands) == 0 {
		return cands
	}
	out := make([]completionCandidate, 0, len(cands))
	for _, cand := range cands {
		if c.operationalCandidateAllowed(a, words, cand.name) {
			out = append(out, cand)
		}
	}
	return out
}

// --- *-configuration gate ----------------------------------------------

// hintRoots14988 maps a ValueHint to the config subtree(s) its live
// values are read from (#14708, same map as the gRPC gate).
var hintRoots14988 = map[config.ValueHint][]string{
	config.ValueHintZoneName:      {"security zones"},
	config.ValueHintAddressName:   {"security address-book"},
	config.ValueHintAppName:       {"applications"},
	config.ValueHintAppSetName:    {"applications"},
	config.ValueHintPoolName:      {"security nat"},
	config.ValueHintInterfaceName: {"interfaces"},
	config.ValueHintScreenProfile: {"security screen"},
	config.ValueHintStreamName:    {"security log"},
	config.ValueHintPolicyAddress: {"security address-book"},
	config.ValueHintPolicyApp:     {"applications"},
}

// providerHintAllowed adjudicates one valueProvider call by BOTH the
// cursor path and the hint's owning subtree(s).
func (a completionAuthz) providerHintAllowed(hint config.ValueHint, path []string) bool {
	if a.unrestricted {
		return true
	}
	if !a.liveAllowed() {
		return false
	}
	if a.confRestricted && len(path) > 0 {
		if !a.confRules.Evaluate(strings.Join(path, " ")).Allowed {
			return false
		}
	}
	if !a.confRestricted {
		return true
	}
	switch hint {
	case config.ValueHintNone, config.ValueHintPolicyName, config.ValueHintUnitNumber:
		return true
	}
	roots, ok := hintRoots14988[hint]
	if !ok {
		return false
	}
	for _, root := range roots {
		if !a.confRules.Evaluate(root).Allowed {
			return false
		}
	}
	return true
}

// wrapValueProvider returns the provider completions may use: live
// values only where providerHintAllowed permits.
func (c *CLI) wrapValueProvider(a *completionAuthz) config.ValueProvider {
	base := c.valueProvider
	if a.unrestricted {
		return base
	}
	return func(hint config.ValueHint, path []string) []config.SchemaCompletion {
		if !a.providerHintAllowed(hint, path) {
			return nil
		}
		return base(hint, path)
	}
}

// configPathAllowed adjudicates a consumed config path for structural
// completion in config mode and under `show configuration`: a denied
// path offers no candidates at all. Edit-path tokens are prepended by
// the caller (the effective cursor).
func (a completionAuthz) configPathAllowed(path []string) bool {
	if a.unrestricted {
		return true
	}
	if a.confErr {
		return false
	}
	if !a.confRestricted || len(path) == 0 {
		return true
	}
	return a.confRules.Evaluate(strings.Join(path, " ")).Allowed
}

// showConfigPathAllowed additionally evaluates the canonical
// `show configuration …` command against the operational regexes.
func (a completionAuthz) showConfigPathAllowed(path []string) bool {
	if a.unrestricted {
		return true
	}
	if a.opErr || !a.configPathAllowed(path) {
		return false
	}
	if a.opRestricted {
		full := "show configuration"
		if len(path) > 0 {
			full += " " + strings.Join(path, " ")
		}
		if !a.opRules.EvaluateForms(full, "show configuration").Allowed {
			return false
		}
	}
	return true
}

// --- *-commands gate for operational live values -----------------------

// operationalConfigPaths14988: see grpcapi.operationalConfigPaths.
func operationalConfigPaths14988(words []string) []string {
	if len(words) >= 2 && words[0] == "test" && words[1] == "policy" {
		return []string{"security zones", "security policies"}
	}
	if len(words) >= 2 && words[0] == "test" && words[1] == "security-zone" {
		return []string{"interfaces"}
	}
	return nil
}

func (a completionAuthz) operationalLiveAllowed(words []string) bool {
	if a.unrestricted {
		return true
	}
	if !a.liveAllowed() {
		return false
	}
	if a.opRestricted {
		for i := 1; i <= len(words); i++ {
			if !a.opRules.Evaluate(strings.Join(words[:i], " ")).Allowed {
				return false
			}
		}
	}
	if a.confRestricted && len(words) > 1 {
		if words[0] == "show" {
			if !a.confRules.Evaluate(strings.Join(words[1:], " ")).Allowed {
				return false
			}
		}
		for _, root := range operationalConfigPaths14988(words) {
			if !a.confRules.Evaluate(root).Allowed {
				return false
			}
		}
	}
	return true
}

// treeConfigFor returns the config the cmdtree walkers may draw dynamic
// values from for words, or nil when live values are denied there.
func (c *CLI) treeConfigFor(a *completionAuthz, words []string) *config.Config {
	if c == nil || c.store == nil {
		return nil
	}
	if !a.operationalLiveAllowed(words) {
		return nil
	}
	return c.store.ActiveConfig()
}

// --- shared candidate computation (TAB + `?`) --------------------------

// completeForHelp computes completion candidates for consumed `words`
// plus `partial`, gated. It is the ONE computation both
// cliCompleter.Do (TAB) and the `?` listener in Run use, so the two
// cannot drift into disagreeing about what a class may see.
func (c *CLI) completeForHelp(words []string, partial string) []completionCandidate {
	auth := c.completionAuthz()
	if c.store != nil && c.store.InConfigMode() {
		return c.completeConfigGated(&auth, words, partial)
	}
	return c.completeOperationalGated(&auth, words, partial)
}

func (c *CLI) completeOperationalGated(a *completionAuthz, words []string, partial string) []completionCandidate {
	// "show configuration <path>" — delegate sub-path to config schema.
	if subPath, ok := showConfigurationSubPath(words); ok {
		if resolvedPath, resolved := config.ResolveConsumedSetPathTokens(subPath); resolved {
			subPath = resolvedPath
		}
		if !a.showConfigPathAllowed(subPath) {
			return nil
		}
		schemaCompletions := config.CompleteSetPathWithValues(subPath, c.wrapValueProvider(a))
		if schemaCompletions != nil {
			var candidates []completionCandidate
			for _, sc := range schemaCompletions {
				if partial == "" || strings.HasPrefix(sc.Name, partial) {
					candidates = append(candidates, completionCandidate{name: sc.Name, desc: sc.Desc})
				}
			}
			if len(candidates) > 0 {
				return candidates
			}
		}
		// Fall through to the tree walk (gRPC parity: an empty schema
		// answer still offers tree keywords for an allowed path).
	}
	cfg := c.treeConfigFor(a, words)
	candidates := completeFromTreeWithDesc(operationalTree, words, partial, cfg)
	return c.filterOperationalCandidates(a, words, candidates)
}

func (c *CLI) completeConfigGated(a *completionAuthz, words []string, partial string) []completionCandidate {
	// Coarse: config-mode candidates require entering configure.
	// `run …` candidates are operational and priced there instead.
	isRun := len(words) > 0 && words[0] == "run"
	if !a.unrestricted && !isRun {
		if c.checkPermission([]string{"configure"}) != nil {
			return nil
		}
	}
	cands := c.completeConfigWithDescAuth(a, words, partial)
	if a.unrestricted {
		return cands
	}
	if isRun {
		return c.filterOperationalCandidates(a, words[1:], cands)
	}
	return cands
}

// completeConfigWithDescAuth is completeConfigWithDesc with the gated
// provider / tree config / path checks.
func (c *CLI) completeConfigWithDescAuth(a *completionAuthz, words []string, partial string) []completionCandidate {
	if len(words) == 0 {
		return filterTreeCandidates(configTopLevel, partial)
	}
	resolvedTop, ok := resolveUniqueTreePrefix(configTopLevel, words[0])
	if !ok {
		if len(words) == 1 {
			return filterTreeCandidates(configTopLevel, words[0])
		}
		return nil
	}
	switch resolvedTop {
	case "set", "delete", "activate", "deactivate", "show", "edit":
		pathWords := words[1:]
		if resolvedPath, resolved := config.ResolveConsumedSetPathTokens(pathWords); resolved {
			pathWords = resolvedPath
		}
		// Effective cursor: edit path + typed path (#14716 spelling —
		// the gate matches the resolved path, never the fragment).
		effective := pathWords
		if c.store != nil {
			if ep := c.store.GetEditPath(); len(ep) > 0 {
				effective = append(append([]string(nil), config.NormalizeEditPathTokens(ep)...), pathWords...)
			}
		}
		if !a.configPathAllowed(effective) {
			return nil
		}
		schemaCompletions := config.CompleteSetPathWithValues(pathWords, c.wrapValueProvider(a))
		if schemaCompletions == nil {
			return nil
		}
		var candidates []completionCandidate
		for _, sc := range schemaCompletions {
			if strings.HasPrefix(sc.Name, partial) {
				candidates = append(candidates, completionCandidate{name: sc.Name, desc: sc.Desc})
			}
		}
		return candidates
	case "run":
		return c.completeOperationalGated(a, words[1:], partial)
	case "commit", "load":
		if len(words) == 1 {
			node := configTopLevel[resolvedTop]
			if node == nil || node.Children == nil {
				return nil
			}
			var candidates []completionCandidate
			for name, child := range node.Children {
				if strings.HasPrefix(name, partial) {
					candidates = append(candidates, completionCandidate{name: name, desc: child.Desc})
				}
			}
			return candidates
		}
		return nil
	default:
		return nil
	}
}

// --- help ---------------------------------------------------------------

// filteredOperationalHelp returns the operational help candidates the
// class may see (`?`/`help` at the top level).
func (c *CLI) filteredOperationalHelp() []completionCandidate {
	auth := c.completionAuthz()
	return c.filterOperationalCandidates(&auth, nil, treeHelpCandidates(operationalTree))
}

// filteredConfigHelp returns the config-mode help candidates the class
// may see: none when the class cannot enter configure.
func (c *CLI) filteredConfigHelp() []completionCandidate {
	auth := c.completionAuthz()
	if !auth.unrestricted && c.checkPermission([]string{"configure"}) != nil {
		return nil
	}
	return treeHelpCandidates(configTopLevel)
}
