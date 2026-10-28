package policymatch

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #3727 — the policy simulator (backing `show security match-policies` /
// `test policy` and the REST/gRPC MatchPolicies RPCs) used to SILENTLY SKIP a
// policy application-set whose expansion errors (matchApp's old `continue`) and
// fall through to a later rule / configured default-policy. The runtime instead
// fails the WHOLE snapshot closed on the same malformed set — pkg/appid
// BuildCatalog returns an ExpandApplicationSet error so buildSnapshot itself
// errors (apply retains prior state, #3438), and pkg/dataplane/userspace
// expandUserspacePolicyApplications poisons the rule with the __unsupported__
// sentinel that the helper integrity preflight rejects (#3261) — so the
// dataplane retains its previous-good snapshot or fresh-boots default-deny and
// enforces NONE of the config. Under a default-PERMIT the simulator therefore
// reported PERMIT for a config the dataplane fail-closes (a dangerous operator
// lie). These tests pin the fail-closed-parity fix: a malformed application-set
// makes Match report the first-class ContentRejected verdict, not a fabricated
// permit/deny/default. They go RED on revert of the Match content-rejection gate
// (the config falls through to the default-policy / a positive match again).

// badSetApps constructs an ApplicationsConfig whose application-set "bad-set"
// references a member that does not resolve, so config.ExpandApplicationSet
// returns an error — the exact input the runtime fails closed on.
func badSetApps() config.ApplicationsConfig {
	return config.ApplicationsConfig{
		ApplicationSets: map[string]*config.ApplicationSet{
			"bad-set": {Name: "bad-set", Applications: []string{"nonexistent-app"}},
		},
	}
}

func denyPol(name string, m config.PolicyMatch) *config.Policy {
	return &config.Policy{Name: name, Match: m, Action: config.PolicyDeny}
}

// TestAppSetExpansionFailsClosedUnderDefaultPermit is the H01 anchor: a deny
// rule referencing a malformed application-set under a default-PERMIT. Pre-#3727
// matchApp skipped the bad set, the rule did not match, and Match fell through
// to default-permit -> the simulator reported PERMIT while the dataplane
// fail-closes. The fix reports ContentRejected instead.
func TestAppSetExpansionFailsClosedUnderDefaultPermit(t *testing.T) {
	// Sanity: the shared config primitive both the runtime and the simulator use
	// really does reject this set — the parity reference for the whole fix.
	if _, err := config.ExpandApplicationSet("bad-set", &config.ApplicationsConfig{
		ApplicationSets: map[string]*config.ApplicationSet{
			"bad-set": {Name: "bad-set", Applications: []string{"nonexistent-app"}},
		},
	}); err == nil {
		t.Fatal("ExpandApplicationSet(bad-set) returned nil error; test premise broken")
	}

	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyPermit,
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust", denyPol("deny-badset",
				config.PolicyMatch{Applications: []string{"bad-set"}})),
		},
	}, badSetApps())

	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: PortPtr(80)})

	if !res.ContentRejected {
		t.Fatalf("ContentRejected = false, want true: a malformed application-set must fail-close the simulator like the runtime, not fall through to default-permit (Matched=%v DefaultUsed=%v Action=%v)",
			res.Matched, res.DefaultUsed, res.Action)
	}
	if res.Matched || res.DefaultUsed || res.HostInboundUnmatched {
		t.Fatalf("Matched=%v DefaultUsed=%v HostInboundUnmatched=%v, want all false for a ContentRejected verdict",
			res.Matched, res.DefaultUsed, res.HostInboundUnmatched)
	}
	if res.DisplayAction() != ContentRejectedActionString {
		t.Fatalf("DisplayAction() = %q, want ContentRejectedActionString", res.DisplayAction())
	}
	if len(res.ContentRejectionReasons) == 0 {
		t.Fatal("ContentRejectionReasons empty, want the offending policy + application-set named")
	}
	reason := strings.Join(res.ContentRejectionReasons, " | ")
	if !strings.Contains(reason, "trust->untrust/deny-badset") || !strings.Contains(reason, "bad-set") {
		t.Fatalf("reason %q does not name the offending policy scope + application-set", reason)
	}
}

// TestAppSetExpansionBadSetBeforeAny is the M01 shape `[ bad-set any ]`: pre-fix
// matchApp returned true on the `any` token so the rule matched (a confident
// WRONG verdict); the runtime rejects because the bad set is present. Post-fix:
// ContentRejected.
func TestAppSetExpansionBadSetBeforeAny(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust", permit("permit-badset-any",
				config.PolicyMatch{Applications: []string{"bad-set", "any"}})),
		},
	}, badSetApps())

	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: PortPtr(80)})
	if !res.ContentRejected {
		t.Fatalf("ContentRejected = false, want true for `[ bad-set any ]` (Matched=%v Action=%v)", res.Matched, res.Action)
	}
	if res.Matched {
		t.Fatal("Matched = true, want false: the `any` token must not paper over a malformed application-set (M01)")
	}
}

// TestAppSetExpansionAnyBeforeBadSet pins ORDER-INSENSITIVITY: `[ any bad-set ]`
// ALSO fails closed at runtime because pkg/appid BuildCatalog walks every token
// and errors on the bad set regardless of the leading `any` (an `any` token does
// not short-circuit the catalog walk), so buildSnapshot errors and the apply
// path retains prior state. The simulator must match that — not report the
// (naive) match-any verdict.
func TestAppSetExpansionAnyBeforeBadSet(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust", permit("permit-any-badset",
				config.PolicyMatch{Applications: []string{"any", "bad-set"}})),
		},
	}, badSetApps())

	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: PortPtr(80)})
	if !res.ContentRejected {
		t.Fatalf("ContentRejected = false, want true for `[ any bad-set ]`: the runtime BuildCatalog fail-close is order-insensitive (Matched=%v Action=%v)", res.Matched, res.Action)
	}
}

// TestAppSetExpansionUnrelatedPolicyPoisonsWholeConfig pins the whole-snapshot
// semantics: a malformed set in an UNRELATED zone pair fails the config closed
// for EVERY query, including one whose zone pair has a perfectly good rule the
// query would otherwise match. The runtime rejects the WHOLE snapshot, so the
// clean trust->untrust permit is NOT enforced either.
func TestAppSetExpansionUnrelatedPolicyPoisonsWholeConfig(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust", permit("clean-http",
				config.PolicyMatch{Applications: []string{"junos-http"}})),
			zonePair("dmz", "wan", denyPol("deny-badset",
				config.PolicyMatch{Applications: []string{"bad-set"}})),
		},
	}, badSetApps())

	// This query would match the clean trust->untrust permit pre-fix.
	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: PortPtr(80)})
	if !res.ContentRejected {
		t.Fatalf("ContentRejected = false, want true: a malformed set in dmz->wan must fail the WHOLE config closed, so the trust->untrust permit is not certified (Matched=%v PolicyName=%q Action=%v)",
			res.Matched, res.PolicyName, res.Action)
	}
	reason := strings.Join(res.ContentRejectionReasons, " | ")
	if !strings.Contains(reason, "dmz->wan/deny-badset") {
		t.Fatalf("reason %q does not name the offending dmz->wan policy", reason)
	}
}

// TestAppSetExpansionGlobalPolicy covers a malformed set referenced by a GLOBAL
// policy — the reason must carry the scope-qualified global identity.
func TestAppSetExpansionGlobalPolicy(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy:  config.PolicyPermit,
		GlobalPolicies: []*config.Policy{denyPol("g-badset", config.PolicyMatch{Applications: []string{"bad-set"}})},
	}, badSetApps())

	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: PortPtr(80)})
	if !res.ContentRejected {
		t.Fatalf("ContentRejected = false, want true for a malformed set in a global policy (Matched=%v Action=%v)", res.Matched, res.Action)
	}
	reason := strings.Join(res.ContentRejectionReasons, " | ")
	if !strings.Contains(reason, "global/g-badset") {
		t.Fatalf("reason %q does not name the global policy scope", reason)
	}
}

// TestWellFormedAppSetStillMatches is the non-regression guard: a well-formed
// (multi-level) application-set must NOT be flagged as content-rejected and must
// match correctly. Reverting the fix must not turn a healthy nested set into a
// false ContentRejected.
func TestWellFormedAppSetStillMatches(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust", permit("allow-set",
				config.PolicyMatch{Applications: []string{"outer"}})),
		},
	}, config.ApplicationsConfig{
		ApplicationSets: map[string]*config.ApplicationSet{
			"outer": {Name: "outer", Applications: []string{"inner"}},
			"inner": {Name: "inner", Applications: []string{"junos-https"}},
		},
	})

	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: PortPtr(443)})
	if res.ContentRejected {
		t.Fatalf("ContentRejected = true for a well-formed nested application-set; reasons=%v", res.ContentRejectionReasons)
	}
	if !res.Matched || res.Action != config.PolicyPermit || res.PolicyName != "allow-set" {
		t.Fatalf("well-formed app-set did not match: Matched=%v Action=%v Name=%q", res.Matched, res.Action, res.PolicyName)
	}
}

// TestNoAppSetNoRejection confirms a config with no application-sets at all is
// never flagged (the scan is inert for the common case).
func TestNoAppSetNoRejection(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust", permit("allow-http",
				config.PolicyMatch{Applications: []string{"junos-http"}})),
		},
	}, config.ApplicationsConfig{})
	if reasons := policyContentRejectionReasons(cfg, nil); len(reasons) != 0 {
		t.Fatalf("policyContentRejectionReasons = %v, want empty for a config with no application-sets", reasons)
	}
}
