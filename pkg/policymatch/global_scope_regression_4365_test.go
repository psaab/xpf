package policymatch

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// TestSharedMatcherGlobalScopeRegressionMatrix locks the #3148 global-policy
// from-zone/to-zone match-scope tier (Tier 4, `globalScopeMatches`) as a
// cross-language SSOT regression matrix (#4365). The Rust dataplane
// (userspace-dp/src/policy.rs `GlobalZoneScope::matches`) is the only forwarding
// path and the Go simulator here backs `show security match-policies`; the two
// MUST agree or the operator's test output permits/denies differently than the
// wire. These vectors are the Go half of that lock — the Rust side mirrors them
// in `global_policy_zone_scope_tier_ordering` (F2). Each case asserts the FULL
// verdict contract the runtime stamps: Matched, Global, Action, PolicyName, the
// #3331 FromZone/ToZone SCOPE (empty == "any" for a global), and the stable
// PolicyID drawn from the shared RuntimePolicyIDs namespace — a global policy's
// runtime set is the one that immediately follows the last zone-pair set
// (policySetID == len(cfg.Security.Policies)).
//
// The behaviors pinned are exactly the #4365 gap: (a) a scoped global matches
// only when BOTH the from-zone and to-zone scope match; (b) a non-matching
// scope falls through to the configured default; (c) an empty/`any` scope
// applies to every zone; (d) tier precedence — a matching zone-pair policy AND a
// matching both-any wildcard each OUTRANK a matching scoped global (Tier 1 and
// Tier 3 before Tier 4), so `Global` is false and the scoped global never fires.
func TestSharedMatcherGlobalScopeRegressionMatrix(t *testing.T) {
	tests := []struct {
		name        string
		cfg         *config.Config
		q           Query
		wantMatched bool
		wantGlobal  bool
		wantDefault bool
		wantAction  config.PolicyAction
		wantName    string // "" => default (no policy matched)
		wantFrom    string // expected Result.FromZone scope (only checked when matched)
		wantTo      string // expected Result.ToZone scope (only checked when matched)
		// wantContentRejected: the helper refuses the WHOLE snapshot for this
		// config (#9410), so this matrix's remaining columns describe nothing and
		// only the absence of an attributed verdict is asserted.
		wantContentRejected bool
		// idSet/idSlice are the [policySetID, sliceIndex] RuntimePolicyIDs
		// coordinate of the matched rule. For a global match idSet is IGNORED and
		// the runtime set index is derived as len(cfg.Security.Policies); for a
		// zone-pair match idSet is the zone-pair set index. Unused when not matched.
		idSet   int
		idSlice int
	}{
		{
			// (a) BOTH from-zone and to-zone scope match -> the scoped global
			// fires. Result carries Global=true and the scope as FromZone/ToZone.
			name: "scoped global matches when both from and to scope match",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyDeny,
				GlobalPolicies: []*config.Policy{
					permit("g-scoped", config.PolicyMatch{FromZones: []string{"trust"}, ToZones: []string{"untrust"}}),
				},
			}, config.ApplicationsConfig{}),
			q:           Query{FromZone: "trust", ToZone: "untrust"},
			wantMatched: true, wantGlobal: true, wantAction: config.PolicyPermit,
			wantName: "g-scoped", wantFrom: "trust", wantTo: "untrust",
			idSlice: 0, // global set (len(Policies)==0), first global rule
		},
		{
			// (a') Same scoped global, but a preceding UNRELATED zone-pair set
			// exists so the global's runtime set index is len(Policies)==1 and its
			// PolicyID is provably nonzero — this locks that the global-set index
			// tracks len(cfg.Security.Policies), not a fixed 0.
			name: "scoped global runtime id tracks len(policies)",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyDeny,
				Policies: []*config.ZonePairPolicies{
					// Never matches a trust->untrust query; only shifts indices.
					zonePair("dmz", "wan", permit("unrelated", config.PolicyMatch{})),
				},
				GlobalPolicies: []*config.Policy{
					permit("g-scoped", config.PolicyMatch{FromZones: []string{"trust"}, ToZones: []string{"untrust"}}),
				},
			}, config.ApplicationsConfig{}),
			q:           Query{FromZone: "trust", ToZone: "untrust"},
			wantMatched: true, wantGlobal: true, wantAction: config.PolicyPermit,
			wantName: "g-scoped", wantFrom: "trust", wantTo: "untrust",
			idSlice: 0, // global set == len(Policies)==1
		},
		{
			// (b) from-zone scope does NOT match (scope trust, flow dmz) -> the
			// global is skipped and the verdict is the configured default.
			name: "scoped global from-zone mismatch falls through to default",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyPermit,
				GlobalPolicies: []*config.Policy{
					deny("g-trust-only", config.PolicyMatch{FromZones: []string{"trust"}}),
				},
			}, config.ApplicationsConfig{}),
			q:           Query{FromZone: "dmz", ToZone: "untrust"},
			wantMatched: false, wantDefault: true, wantAction: config.PolicyPermit,
		},
		{
			// (b') to-zone scope does NOT match (scope untrust, flow dmz) -> default.
			name: "scoped global to-zone mismatch falls through to default",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyPermit,
				GlobalPolicies: []*config.Policy{
					deny("g-to-untrust", config.PolicyMatch{ToZones: []string{"untrust"}}),
				},
			}, config.ApplicationsConfig{}),
			q:           Query{FromZone: "trust", ToZone: "dmz"},
			wantMatched: false, wantDefault: true, wantAction: config.PolicyPermit,
		},
		{
			// (b'') An undefined/typo'd scope must match nothing and must never
			// silently widen to all-zones.
			//
			// #9410 RE-ANCHORED THIS ROW, and it is the row that made this matrix's
			// headline claim false.
			//
			// This matrix is cited in docs/userspace-dataplane-architecture.md as a
			// cross-language SSOT whose two halves "assert the same matrix
			// case-for-case ... so the operator's test output can never permit/deny
			// differently than the wire", with ONE named exception: a typo'd scope
			// "fails closed to the default in the Go simulator ... but fails the
			// whole snapshot closed at build in Rust (#3402); a typo can never
			// commit, so neither path ever serves it."
			//
			// Both halves of that excuse are false, and the second is the serious
			// one. A typo CAN be served: CompileConfigLenient downgrades the zone
			// gate to a warning and Store.Load / Store.SyncApply / cmd/xpfd/upgrade
			// all use it. And what this row asserted — fall through to a default
			// PERMIT — is precisely the fail-OPEN the Rust side eliminated in #3402.
			// policy_tests.rs unknown_zone_pair_fails_closed says so in as many
			// words: "under `default-policy permit-all` a stale `deny` became an
			// ALLOW (fail-OPEN) ... Rejecting the snapshot keeps the previous good
			// state." So the Go half of the SSOT matrix was pinning, on the
			// operator-facing `show` surface, the behaviour the dataplane had
			// already been fixed not to have.
			//
			// With #9410's zone arm the two halves agree here with NO exception, so
			// the doc's "one deliberate divergence" sentence is removed rather than
			// reworded — the divergence is gone, not mis-described.
			//
			// The row is KEPT because its subject is still load-bearing: an
			// undefined global scope must not match and must not yield a fabricated
			// verdict. Only the FORM of "no verdict" moved, from "the default" to
			// "the snapshot is refused".
			name: "undefined global scope is CONTENT-REJECTED (was: fails closed to default)",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyPermit,
				GlobalPolicies: []*config.Policy{
					deny("g-typo", config.PolicyMatch{FromZones: []string{"trsut"}}), // typo
				},
			}, config.ApplicationsConfig{}),
			q:           Query{FromZone: "trust", ToZone: "untrust"},
			wantMatched: false, wantDefault: false, wantAction: config.PolicyDeny,
			wantContentRejected: true,
		},
		{
			// (c) An empty (unset) scope applies to EVERY zone. FromZone/ToZone in
			// the Result stay "" (callers render "" as "any" for a global).
			name: "empty scope global applies to any zone pair",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyPermit,
				GlobalPolicies: []*config.Policy{
					deny("g-any", config.PolicyMatch{}),
				},
			}, config.ApplicationsConfig{}),
			q:           Query{FromZone: "dmz", ToZone: "wan"},
			wantMatched: true, wantGlobal: true, wantAction: config.PolicyDeny,
			wantName: "g-any", wantFrom: "", wantTo: "",
			idSlice: 0,
		},
		{
			// (c') An explicit `any`/`any` scope ALSO applies everywhere, and the
			// literal "any" is preserved in the reported scope (distinct from the
			// empty-string case above).
			name: "explicit any scope global applies and preserves any in scope",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyPermit,
				GlobalPolicies: []*config.Policy{
					deny("g-anyany", config.PolicyMatch{FromZones: []string{"any"}, ToZones: []string{"any"}}),
				},
			}, config.ApplicationsConfig{}),
			q:           Query{FromZone: "dmz", ToZone: "wan"},
			wantMatched: true, wantGlobal: true, wantAction: config.PolicyDeny,
			wantName: "g-anyany", wantFrom: "any", wantTo: "any",
			idSlice: 0,
		},
		{
			// (c'') Partial scope: from-zone constrained, to-zone empty (== any).
			// A matching from-zone with ANY to-zone fires.
			name: "partial scope from-zone-only matches any to-zone",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyDeny,
				GlobalPolicies: []*config.Policy{
					permit("g-from-trust", config.PolicyMatch{FromZones: []string{"trust"}}),
				},
			}, config.ApplicationsConfig{}),
			q:           Query{FromZone: "trust", ToZone: "wan"},
			wantMatched: true, wantGlobal: true, wantAction: config.PolicyPermit,
			wantName: "g-from-trust", wantFrom: "trust", wantTo: "",
			idSlice: 0,
		},
		{
			// (c''') Same partial-scope global, non-matching from-zone -> default.
			name: "partial scope from-zone-only rejects non-matching from-zone",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyDeny,
				GlobalPolicies: []*config.Policy{
					permit("g-from-trust", config.PolicyMatch{FromZones: []string{"trust"}}),
				},
			}, config.ApplicationsConfig{}),
			q:           Query{FromZone: "dmz", ToZone: "wan"},
			wantMatched: false, wantDefault: true, wantAction: config.PolicyDeny,
		},
		{
			// (d) TIER PRECEDENCE: a matching exact zone-pair policy (Tier 1)
			// OUTRANKS a scoped global (Tier 4) that ALSO matches the same tuple.
			// The zone-pair permit wins; Global is false and the global-deny never
			// fires. Result scope is the zone-pair stanza, PolicyID the zone-pair
			// set coordinate [0,0].
			name: "exact zone-pair outranks matching scoped global",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyDeny,
				Policies: []*config.ZonePairPolicies{
					zonePair("trust", "untrust", permit("zp-allow", config.PolicyMatch{})),
				},
				GlobalPolicies: []*config.Policy{
					deny("g-scoped-deny", config.PolicyMatch{FromZones: []string{"trust"}, ToZones: []string{"untrust"}}),
				},
			}, config.ApplicationsConfig{}),
			q:           Query{FromZone: "trust", ToZone: "untrust"},
			wantMatched: true, wantGlobal: false, wantAction: config.PolicyPermit,
			wantName: "zp-allow", wantFrom: "trust", wantTo: "untrust",
			idSet: 0, idSlice: 0,
		},
		{
			// (d') TIER PRECEDENCE after the both-any wildcard: a matching both-any
			// (`from-zone any to-zone any`) zone-pair rule (Tier 3) OUTRANKS a
			// matching unscoped global (Tier 4). The both-any deny wins; the global
			// permit never fires. This is the "tier precedence after both-any
			// wildcard" lock (#4365) — the global tier is consulted ONLY after the
			// both-any wildcard tier.
			name: "both-any wildcard outranks matching global",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyPermit,
				Policies: []*config.ZonePairPolicies{
					zonePair("any", "any", deny("wild-deny", config.PolicyMatch{})),
				},
				GlobalPolicies: []*config.Policy{
					permit("g-allow", config.PolicyMatch{}),
				},
			}, config.ApplicationsConfig{}),
			q:           Query{FromZone: "trust", ToZone: "untrust"},
			wantMatched: true, wantGlobal: false, wantAction: config.PolicyDeny,
			wantName: "wild-deny", wantFrom: "any", wantTo: "any",
			idSet: 0, idSlice: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := Match(tt.cfg, tt.q)
			if res.ContentRejected != tt.wantContentRejected {
				t.Fatalf("ContentRejected = %v, want %v (reasons %v)",
					res.ContentRejected, tt.wantContentRejected, res.ContentRejectionReasons)
			}
			if res.Matched != tt.wantMatched {
				t.Fatalf("Matched = %v, want %v (res=%+v)", res.Matched, tt.wantMatched, res)
			}
			if res.DefaultUsed != tt.wantDefault {
				t.Fatalf("DefaultUsed = %v, want %v (res=%+v)", res.DefaultUsed, tt.wantDefault, res)
			}
			if res.Action != tt.wantAction {
				t.Fatalf("Action = %v, want %v (res=%+v)", res.Action, tt.wantAction, res)
			}
			if res.Global != tt.wantGlobal {
				t.Fatalf("Global = %v, want %v (res=%+v)", res.Global, tt.wantGlobal, res)
			}
			if !tt.wantMatched {
				// A default verdict must not leak a policy identity or scope.
				if res.PolicyName != "" {
					t.Fatalf("default verdict leaked PolicyName %q", res.PolicyName)
				}
				return
			}
			if res.PolicyName != tt.wantName {
				t.Fatalf("PolicyName = %q, want %q", res.PolicyName, tt.wantName)
			}
			if res.FromZone != tt.wantFrom || res.ToZone != tt.wantTo {
				t.Fatalf("scope = %q->%q, want %q->%q", res.FromZone, res.ToZone, tt.wantFrom, tt.wantTo)
			}
			// Lock the PolicyID against the shared RuntimePolicyIDs SSOT at the
			// matched rule's coordinate — the exact key the dataplane write side
			// and `show policies` Index column use, so a Go/Rust divergence in the
			// global-set index (len(Policies)) or slice ordering is caught here.
			ids := dpuserspace.RuntimePolicyIDs(tt.cfg)
			setIdx := tt.idSet
			if tt.wantGlobal {
				setIdx = len(tt.cfg.Security.Policies)
			}
			wantID := ids[[2]uint32{uint32(setIdx), uint32(tt.idSlice)}]
			if res.PolicyID != wantID {
				t.Fatalf("PolicyID = %d, want %d (SSOT coord [%d,%d])", res.PolicyID, wantID, setIdx, tt.idSlice)
			}
		})
	}

	// Reinforce the a' vector's intent: with a preceding zone-pair set the scoped
	// global's runtime PolicyID is provably NONZERO, proving the global-set index
	// is derived from len(Policies) rather than a hard-coded 0.
	t.Run("global runtime id is nonzero after a preceding zone-pair set", func(t *testing.T) {
		cfg := cfgWith(config.SecurityConfig{
			DefaultPolicy: config.PolicyDeny,
			Policies: []*config.ZonePairPolicies{
				zonePair("dmz", "wan", permit("unrelated", config.PolicyMatch{})),
			},
			GlobalPolicies: []*config.Policy{
				permit("g-scoped", config.PolicyMatch{FromZones: []string{"trust"}, ToZones: []string{"untrust"}}),
			},
		}, config.ApplicationsConfig{})
		res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust"})
		if !res.Matched || !res.Global || res.PolicyID == 0 {
			t.Fatalf("expected nonzero-ID global match, got Matched=%v Global=%v PolicyID=%d",
				res.Matched, res.Global, res.PolicyID)
		}
	})
}
