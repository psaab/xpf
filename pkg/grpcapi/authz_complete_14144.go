package grpcapi

import (
	"context"
	"strings"

	"github.com/psaab/xpf/pkg/authz"
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
	return a.confRules.Evaluate(strings.Join(path, " ")).Allowed
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
		if base == nil || !a.providerPathAllowed(path) {
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
	return a.confRules.Evaluate(strings.Join(path, " ")).Allowed
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

// operationalAllowed reports whether live cmdtree DynamicFn values may be
// computed for an operational command prefix. Every typed prefix is checked
// against the operational regexes (a deny on any ancestor command conceals
// its dynamic values), and the words after `show` are also checked as a
// config path, because most `show …` dynamic providers enumerate configured
// objects (zones, policies, routing instances).
func (a completionAuth) operationalAllowed(words []string) bool {
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
		if !a.confRules.Evaluate(strings.Join(words[1:], " ")).Allowed {
			return false
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
	return s.store.ActiveConfig()
}
