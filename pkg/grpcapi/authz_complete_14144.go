package grpcapi

import (
	"context"
	"strings"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/cmdtree"
	"github.com/psaab/xpf/pkg/config"
)

// #14144: Complete disclosure.
//
// Complete was priced at PermView and classified as a config-mode method
// (#9633), so authorizeRPCCommand exempted it from the operational regexes,
// and authorizeRPCConfigMutation never saw it (configMutationLineFor returns
// ok=false for a completion request, so it fell through to Load/Rollback
// handling and returned nil). Neither *-configuration nor *-commands was ever
// consulted. Yet the handler returns live-config-derived candidates — zone,
// policy, address-book, application, interface and VRF names together with
// their configured descriptions and CIDRs — built by valueProvider and by the
// cmdtree DynamicFns from ActiveConfig. A PermView class with
// deny-configuration "^security" (or deny-commands "^show configuration")
// could therefore enumerate exactly the subtree those gates conceal from
// ShowConfig/Set, one Tab press at a time.
//
// The fix is at the DATA SOURCE, not the RPC price: raising Complete to
// PermConfig would take tab completion away from every read-only operator,
// including for paths they may read. Instead, when the admitted principal's
// class carries regexes, live values are offered only for paths those regexes
// allow, and the cmdtree walkers receive a nil config (their providers are
// nil-safe by contract, #5196) when the completed command is denied. Schema
// keywords — the public grammar, available in the shipped docs — are still
// offered for allowed parent paths, so completion stays usable; a candidate
// whose consumed path is itself denied is not offered at all. Fail-closed
// throughout: an invalid regex, an unidentified principal, or a class-less
// principal suppresses live values, mirroring the interceptor's posture
// (which denies such callers before the handler in production; the handler
// posture keeps direct/in-process calls safe too).

// #14708 (D15-03): the #14144 gate above adjudicated only the CURSOR path,
// but a ValueHint reads a FIXED hierarchy regardless of where the cursor
// sits — ValueHintInterfaceName enumerates cfg.Interfaces from an OSPF,
// BGP, routing-instance or zone cursor; ValueHintPolicyAddress enumerates
// the global address book from a policy-match cursor. A class denying
// ^interfaces (or ^security address-book) therefore still received the
// denied subtree's names, descriptions and CIDRs from any allowed cursor.
// hintRoots maps each hint to the canonical config path(s) whose subtree
// its values are drawn from; wrapProvider requires EVERY root to be
// allowed in addition to the cursor path. Roots are stated in the same
// space-joined spelling the *-configuration regexes match (the form the
// operator writes in `set …` / `show configuration …`), so an anchored
// deny on the owning subtree fires here exactly as it does at its home
// cursor. PolicyName is deliberately absent: its values come from the
// zone pair named in the cursor path itself (or the global policy list
// under … policies global), so the cursor-path check already prices the
// exact subtree read. UnitNumber likewise reads the interface named in
// the cursor path under interfaces. PolicyAddress/PolicyApp also offer
// built-in literals (any, any-ipv4, predefined junos-* names): those are
// public catalogue data, not configured values, but gating the whole
// hint on the owning subtree is the fail-closed reading — a class denied
// the address book loses the slot's live completions entirely rather
// than receiving a filtered view that still confirms the slot exists.

// completionAuth is the admitted principal's regex posture for one Complete
// call, resolved once from the same snapshot the interceptor used.
type completionAuth struct {
	unrestricted   bool // superuser, or a legacy direct (non-RPC) caller path
	identified     bool
	hasClass       bool
	cfg            *config.Config
	confRules      config.CompiledLoginRegexes
	confRestricted bool
	confErr        bool
	opRules        config.CompiledLoginRegexes
	opRestricted   bool
	opErr          bool
}

// legacyCompletionAuth is the posture for the direct completeConfigPairs /
// completeOperationalPairs entry points used by in-process callers and tests:
// no principal exists on that path, and the pre-#14144 behaviour (schema plus
// live values from the store) is preserved there. The RPC handler never uses
// it — it resolves completionAuthFor from the admitted principal.
func legacyCompletionAuth() completionAuth { return completionAuth{unrestricted: true} }

func (s *Server) completionAuthFor(ctx context.Context) completionAuth {
	p, identified := s.completionPrincipal(ctx)
	if identified && p.Superuser {
		return completionAuth{unrestricted: true, identified: true}
	}
	a := completionAuth{identified: identified, hasClass: p.Class != ""}
	if !identified || p.Class == "" {
		return a
	}
	cfg := s.activeConfig()
	a.cfg = cfg
	if cfg == nil {
		// Cannot evaluate the class's rules — fail closed for live values.
		a.confErr = true
		a.opErr = true
		return a
	}
	if rules, ok, err := config.ConfigurationLoginRegexesFor(cfg, p.Class); err != nil {
		a.confErr = true
	} else {
		a.confRules, a.confRestricted = rules, ok
	}
	if rules, ok, err := config.OperationalLoginRegexesFor(cfg, p.Class); err != nil {
		a.opErr = true
	} else {
		a.opRules, a.opRestricted = rules, ok
	}
	return a
}

func (s *Server) completionPrincipal(ctx context.Context) (authz.Principal, bool) {
	if ctx == nil {
		return authz.Principal{}, false
	}
	if p, ok := authorizedPrincipalFromContext(ctx); ok {
		return p, true
	}
	if _, ok := ctx.Value(connPeerKey{}).(*connPeer); ok {
		return principalFromContext(ctx, s.activeConfig()), true
	}
	return authz.Principal{}, false
}

// liveAllowed reports whether any live-config-derived value may be offered.
func (a completionAuth) liveAllowed() bool {
	if a.unrestricted {
		return true
	}
	return a.identified && a.hasClass && a.cfg != nil && !a.confErr && !a.opErr
}

// providerPathAllowed adjudicates one ValueProvider call: path is the config
// path consumed so far (e.g. [security zones security-zone]).
func (a completionAuth) providerPathAllowed(path []string) bool {
	if a.unrestricted {
		return true
	}
	if !a.liveAllowed() {
		return false
	}
	if !a.confRestricted || len(path) == 0 {
		return true
	}
	return a.configPathFormsAllowed(path)
}

// effectiveConfigPaths returns the config path spellings a
// *-configuration rule must judge for a cursor typed under
// `groups <name> …` (#15942 H1-02): the group's BODY is effective
// configuration at the unwrapped path, so a class denied
// `security policies` must not be offered policy names merely because
// the literal cursor starts with the allowed word `groups`.
func effectiveConfigPaths(path []string) [][]string {
	if len(path) >= 2 && path[0] == "groups" {
		return [][]string{path, path[2:]}
	}
	return [][]string{path}
}

// configPathFormsAllowed reports whether every effective spelling of
// path is allowed by the *-configuration rules.
func (a completionAuth) configPathFormsAllowed(path []string) bool {
	if !a.confRestricted {
		return true
	}
	for _, p := range effectiveConfigPaths(path) {
		if len(p) == 0 {
			continue
		}
		if !a.confRules.Evaluate(strings.Join(p, " ")).Allowed {
			return false
		}
	}
	return true
}

// hintRoots maps a ValueHint to the config subtree(s) its live values are
// read from, in the space-joined spelling *-configuration regexes match.
// A hint absent from the map draws only on the cursor path itself (or on
// no configured data), so the cursor check suffices for it. Unknown hints
// fail closed in providerHintAllowed.
var hintRoots = map[config.ValueHint][]string{
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
	config.ValueHintPolicyName:    {"security policies"},
	config.ValueHintUnitNumber:    {"interfaces"},
}

// providerHintAllowed adjudicates one ValueProvider call by BOTH the cursor
// path and the hint's owning subtree(s) (#14708). Either denial suppresses
// the hint's live values.
func (a completionAuth) providerHintAllowed(hint config.ValueHint, path []string) bool {
	if !a.providerPathAllowed(path) {
		return false
	}
	if a.unrestricted || !a.confRestricted {
		return true
	}
	if hint == config.ValueHintNone {
		return true
	}
	roots, ok := hintRoots[hint]
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

// wrapProvider returns the value provider Complete may use: live values only
// where providerPathAllowed permits, schema placeholders otherwise (the
// provider returning nil leaves placeholders/keywords intact).
func (a completionAuth) wrapProvider(s *Server) config.ValueProvider {
	base := s.completionValueProvider()
	if a.unrestricted {
		return base
	}
	return func(hint config.ValueHint, path []string) []config.SchemaCompletion {
		if base == nil || !a.providerHintAllowed(hint, path) {
			return nil
		}
		return base(hint, path)
	}
}

// configPathAllowed adjudicates a consumed config path for STRUCTURAL
// (schema-keyword) completion in config mode and under
// `show configuration`: a path the class's *-configuration regexes deny
// offers no candidates at all.
func (a completionAuth) configPathAllowed(path []string) bool {
	if a.unrestricted {
		return true
	}
	if a.confErr {
		return false
	}
	if !a.confRestricted || len(path) == 0 {
		return true
	}
	return a.configPathFormsAllowed(path)
}

// showConfigPathAllowed adjudicates `show configuration <path>` completion:
// the configuration gate on the sub-path AND the operational gate on the
// canonical `show configuration …` command.
func (a completionAuth) showConfigPathAllowed(path []string) bool {
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

// operationalConfigPaths maps an operational command prefix to the config
// subtree(s) its cmdtree DynamicFns enumerate, in *-configuration spelling.
// Most operational completions outside `show` never touch configured data,
// so the map is deliberately small: `test policy from-zone/to-zone`
// enumerate security zones (and the lookup is a security policies query),
// and `test security-zone interface` enumerates interfaces. Any other
// prefix returns nil and is priced by the show arm in operationalAllowed
// or by the operational regexes alone.
func operationalConfigPaths(words []string) []string {
	if len(words) >= 2 && words[0] == "test" && words[1] == "policy" {
		return []string{"security zones", "security policies"}
	}
	if len(words) >= 2 && words[0] == "test" && words[1] == "security-zone" {
		return []string{"interfaces"}
	}
	return nil
}

// canonicalOperationalWords expands uniquely-abbreviated operational
// words to their canonical spelling before any regex is judged
// (#15942 H1-02, twin of the CLI gate): the cmdtree completion walkers
// resolve abbreviations via the same unique-prefix rule, so judging
// the raw words priced a different command from the one whose
// DynamicFn values were about to be read. See the CLI twin for the
// prefix-expansion contract.
func canonicalOperationalWords(words []string) []string {
	if len(words) == 0 {
		return nil
	}
	if canon, res := cmdtree.Canonicalize(cmdtree.OperationalTree, words); res == cmdtree.CanonicalOK {
		return canon
	}
	out := make([]string, 0, len(words))
	current := cmdtree.OperationalTree
	var options map[string]*cmdtree.Node
	for _, w := range words {
		resolved, ok := cmdtree.ResolveUniquePrefix(cmdtree.KeysOf(current), w)
		var node *cmdtree.Node
		if ok {
			node = current[resolved]
		}
		if !ok && options != nil {
			if r2, ok2 := cmdtree.ResolveUniquePrefix(cmdtree.KeysOf(options), w); ok2 {
				resolved, node, ok = r2, options[r2], true
			}
		}
		if !ok {
			out = append(out, words[len(out):]...)
			break
		}
		out = append(out, resolved)
		if node == nil {
			break
		}
		if node.Options {
			options = node.Children
		}
		if node.Children == nil {
			if options == nil {
				out = append(out, words[len(out):]...)
				break
			}
			current = options
			continue
		}
		current = node.Children
	}
	return out
}

// operationalAllowed reports whether live cmdtree DynamicFn values may be
// computed for an operational command prefix (canonical spelling, see
// canonicalOperationalWords). Every typed prefix is checked against the
// operational regexes (a deny on any ancestor command conceals its
// dynamic values), and the config subtrees the command's providers
// enumerate are checked against the configuration regexes: the words
// after `show` for `show …` commands (most `show …` dynamic providers
// enumerate configured objects — zones, policies, routing instances),
// and the mapped owning subtree for the non-show providers in
// operationalConfigPaths (#14708: `test policy from-zone` previously
// evaluated "policy from-zone", which no ^security deny matches, and
// leaked zone names).
func (a completionAuth) operationalAllowed(words []string) bool {
	if a.unrestricted {
		return true
	}
	if !a.liveAllowed() {
		return false
	}
	canon := canonicalOperationalWords(words)
	if canon == nil {
		return false
	}
	if a.opRestricted {
		for i := 1; i <= len(canon); i++ {
			if !a.opRules.Evaluate(strings.Join(canon[:i], " ")).Allowed {
				return false
			}
		}
	}
	if a.confRestricted && len(canon) > 1 {
		if canon[0] == "show" {
			if !a.confRules.Evaluate(strings.Join(canon[1:], " ")).Allowed {
				return false
			}
		}
		for _, root := range operationalConfigPaths(canon) {
			if !a.confRules.Evaluate(root).Allowed {
				return false
			}
		}
	}
	return true
}

// treeConfig returns the config the cmdtree walkers may draw dynamic values
// from for words, or nil when live values are denied there.
func (a completionAuth) treeConfig(s *Server, words []string) *config.Config {
	if s == nil || s.store == nil {
		return nil
	}
	if !a.operationalAllowed(words) {
		return nil
	}
	if !a.unrestricted {
		return s.store.ActiveConfig()
	}
	cfg, _ := s.completionConfig()
	return cfg
}
