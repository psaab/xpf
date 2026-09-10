package policymatch

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// zones builds a defined-zone set for globalScopeMatches resolution.
func zones(names ...string) map[string]*config.ZoneConfig {
	out := make(map[string]*config.ZoneConfig, len(names))
	for _, n := range names {
		out[n] = &config.ZoneConfig{Name: n}
	}
	return out
}

// TestWildcardZoneAndScopedGlobalPrecedence pins the #3283 parity fix: the
// simulator must replicate the dataplane precedence chain
// (userspace-dp/src/policy.rs evaluate_policy_result_with_icmp) —
//
//	exact zone-pair -> from-any/to-any single-wildcard (config order) ->
//	both-any -> global (scoped by #3148 match from/to-zone) -> default.
//
// Each case below returns the OPPOSITE verdict on the pre-#3283 simulator,
// which only knew exact-zone-pair -> unconditional-global -> default.
func TestWildcardZoneAndScopedGlobalPrecedence(t *testing.T) {
	tests := []struct {
		name       string
		cfg        *config.Config
		q          Query
		wantAction config.PolicyAction
		wantName   string // "" => default (no match)
		wantGlobal bool
		// wantContentRejected: the helper refuses the WHOLE snapshot for this
		// config (#9410), so there is no enforced verdict to compare. Asserted
		// rather than folded into wantName=="" because "no match" and "no
		// snapshot" are different facts and the operator is told different
		// things.
		wantContentRejected bool
	}{
		{
			// #3283 example 1: `from-zone any to-zone untrust deny` is invisible
			// to the old simulator, which then reports the default permit.
			name: "from-any wildcard deny beats default permit",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyPermit,
				Zones:         zones("trust", "untrust"),
				Policies: []*config.ZonePairPolicies{
					zonePair("any", "untrust", deny("block-admin", config.PolicyMatch{})),
				},
			}, config.ApplicationsConfig{}),
			q:          Query{FromZone: "trust", ToZone: "untrust"},
			wantAction: config.PolicyDeny, wantName: "block-admin",
		},
		{
			name: "to-any wildcard deny beats default permit",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyPermit,
				Zones:         zones("trust", "untrust"),
				Policies: []*config.ZonePairPolicies{
					zonePair("trust", "any", deny("lockdown", config.PolicyMatch{})),
				},
			}, config.ApplicationsConfig{}),
			q:          Query{FromZone: "trust", ToZone: "untrust"},
			wantAction: config.PolicyDeny, wantName: "lockdown",
		},
		{
			name: "both-any wildcard deny beats default permit",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyPermit,
				Zones:         zones("trust", "untrust"),
				Policies: []*config.ZonePairPolicies{
					zonePair("any", "any", deny("global-block", config.PolicyMatch{})),
				},
			}, config.ApplicationsConfig{}),
			q:          Query{FromZone: "trust", ToZone: "untrust"},
			wantAction: config.PolicyDeny, wantName: "global-block",
		},
		{
			// Exact zone-pair MUST outrank a wildcard, even though the wildcard
			// is configured first.
			name: "exact zone-pair outranks earlier wildcard",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyDeny,
				Zones:         zones("trust", "untrust"),
				Policies: []*config.ZonePairPolicies{
					zonePair("any", "untrust", deny("wild-deny", config.PolicyMatch{})),
					zonePair("trust", "untrust", permit("exact-permit", config.PolicyMatch{})),
				},
			}, config.ApplicationsConfig{}),
			q:          Query{FromZone: "trust", ToZone: "untrust"},
			wantAction: config.PolicyPermit, wantName: "exact-permit",
		},
		{
			// Single-wildcard tier merges from-any and to-any in config order:
			// `from-zone any to-zone trust deny` configured BEFORE
			// `from-zone untrust to-zone any permit` wins for untrust->trust.
			name: "single-wildcard tier honors config order across from/to-any",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyDeny,
				Zones:         zones("trust", "untrust"),
				Policies: []*config.ZonePairPolicies{
					zonePair("any", "trust", deny("any-to-trust-deny", config.PolicyMatch{})),
					zonePair("untrust", "any", permit("untrust-to-any-permit", config.PolicyMatch{})),
				},
			}, config.ApplicationsConfig{}),
			q:          Query{FromZone: "untrust", ToZone: "trust"},
			wantAction: config.PolicyDeny, wantName: "any-to-trust-deny",
		},
		{
			// #4410 (F8): the SWAPPED companion of the case above. With the two
			// single-wildcard sets in the OPPOSITE config order —
			// `from-zone untrust to-zone any permit` BEFORE `from-zone any
			// to-zone trust deny` — the SAME untrust->trust query must now flip to
			// the PERMIT. The prior case alone cannot prove the merge honors config
			// order: its winner (the from-any deny) is ALSO the config-first rule,
			// so it is equally consistent with a buggy "from-any bucket always
			// outranks to-any" precedence. This swapped pair pins genuine
			// config-order interleaving across the from-any / to-any boundary —
			// the winner is whichever wildcard set appears first, not a fixed
			// from-any/to-any tier. A regression that split the merge into two
			// ordered passes (all from-any, then all to-any, or vice versa) would
			// keep the earlier case green and turn THIS one RED.
			name: "single-wildcard tier honors config order (swapped: to-any first)",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyDeny,
				Zones:         zones("trust", "untrust"),
				Policies: []*config.ZonePairPolicies{
					zonePair("untrust", "any", permit("untrust-to-any-permit", config.PolicyMatch{})),
					zonePair("any", "trust", deny("any-to-trust-deny", config.PolicyMatch{})),
				},
			}, config.ApplicationsConfig{}),
			q:          Query{FromZone: "untrust", ToZone: "trust"},
			wantAction: config.PolicyPermit, wantName: "untrust-to-any-permit",
		},
		{
			// #3283 example 2: a zone-scoped global must NOT apply outside its
			// scope. The old simulator applied every global unconditionally.
			name: "scoped global does NOT apply to non-matching zone",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyPermit,
				Zones:         zones("trust", "untrust", "dmz"),
				GlobalPolicies: []*config.Policy{
					{Name: "scoped-deny", Action: config.PolicyDeny,
						Match: config.PolicyMatch{FromZones: []string{"trust"}, ToZones: []string{"untrust"}}},
				},
			}, config.ApplicationsConfig{}),
			q:          Query{FromZone: "dmz", ToZone: "untrust"},
			wantAction: config.PolicyPermit, wantName: "", // falls through to default permit
		},
		{
			name: "scoped global applies to matching zone pair",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyPermit,
				Zones:         zones("trust", "untrust", "dmz"),
				GlobalPolicies: []*config.Policy{
					{Name: "scoped-deny", Action: config.PolicyDeny,
						Match: config.PolicyMatch{FromZones: []string{"trust"}, ToZones: []string{"untrust"}}},
				},
			}, config.ApplicationsConfig{}),
			q:          Query{FromZone: "trust", ToZone: "untrust"},
			wantAction: config.PolicyDeny, wantName: "scoped-deny", wantGlobal: true,
		},
		{
			// #9410 RE-ANCHORED THIS CASE, and the old expectation was wrong in the
			// direction its own name denied.
			//
			// It asserted that an unresolved (typo'd) global scope "fails closed —
			// it matches nothing and the verdict is the default", with
			// DefaultPolicy PERMIT and wantAction PolicyPermit. Falling through to
			// a default PERMIT is failing OPEN, not closed, and more importantly it
			// is not what the dataplane does. `build_global_zone_scope`
			// (userspace-dp/src/policy.rs:343-380) on a single-element set that is
			// neither empty nor "any" resolves the element, gets None, and returns
			// Err(SnapshotIntegrityError::UnresolvableZoneReference) — so
			// snapshot.rs sets response.ok = false and the helper REFUSES THE WHOLE
			// SNAPSHOT, retaining previous-good or fresh-booting default-deny. It
			// never serves this config's default at all.
			//
			// So the old expectation encoded a Go-only behaviour and pinned it as
			// correct. docs/userspace-dataplane-architecture.md called the same
			// thing a "deliberate divergence" that "neither path ever serves"
			// because "a typo can never commit" — false on the tolerant
			// Store.Load / Store.SyncApply path, which is how this is reachable.
			// That paragraph is corrected in the same change.
			//
			// The case is KEPT rather than deleted because its subject is still
			// load-bearing: an undefined global scope must not match and must not
			// produce a fabricated verdict. Only the expected FORM of "no verdict"
			// moved, from "the default" to "content rejected".
			name: "undefined global scope is CONTENT-REJECTED, not served as the default",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyPermit,
				Zones:         zones("trust", "untrust"),
				GlobalPolicies: []*config.Policy{
					{Name: "typo-deny", Action: config.PolicyDeny,
						Match: config.PolicyMatch{FromZones: []string{"trsut"}}}, // typo
				},
			}, config.ApplicationsConfig{}),
			q:          Query{FromZone: "trust", ToZone: "untrust"},
			wantAction: config.PolicyDeny, wantName: "",
			wantContentRejected: true,
		},
		{
			// An empty/"any" global scope still applies to every zone pair.
			name: "unscoped global applies everywhere",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyPermit,
				Zones:         zones("trust", "untrust", "dmz"),
				GlobalPolicies: []*config.Policy{
					{Name: "broad-deny", Action: config.PolicyDeny,
						Match: config.PolicyMatch{FromZones: []string{"any"}}}, // explicit any
				},
			}, config.ApplicationsConfig{}),
			q:          Query{FromZone: "dmz", ToZone: "untrust"},
			wantAction: config.PolicyDeny, wantName: "broad-deny", wantGlobal: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := Match(tt.cfg, tt.q)
			if res.ContentRejected != tt.wantContentRejected {
				t.Errorf("ContentRejected = %v, want %v (reasons %v)",
					res.ContentRejected, tt.wantContentRejected, res.ContentRejectionReasons)
			}
			if tt.wantContentRejected {
				// The gate returns before any tier runs, so the remaining columns
				// describe nothing. Assert only that no policy was attributed.
				if res.Matched || res.PolicyName != "" {
					t.Errorf("a content-rejected config still attributed policy %q (Matched=%v)",
						res.PolicyName, res.Matched)
				}
				if res.Action != tt.wantAction {
					t.Errorf("Action = %v, want %v", res.Action, tt.wantAction)
				}
				return
			}
			if res.Action != tt.wantAction {
				t.Errorf("Action = %v, want %v", res.Action, tt.wantAction)
			}
			if tt.wantName == "" {
				if res.Matched {
					t.Errorf("expected default (no match), got policy %q", res.PolicyName)
				}
				return
			}
			if !res.Matched {
				t.Errorf("expected match %q, got default", tt.wantName)
			}
			if res.PolicyName != tt.wantName {
				t.Errorf("PolicyName = %q, want %q", res.PolicyName, tt.wantName)
			}
			if res.Global != tt.wantGlobal {
				t.Errorf("Global = %v, want %v", res.Global, tt.wantGlobal)
			}
		})
	}
}
