package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #5225: a firewall-filter term that carries an UNRESOLVED positive
// prefix-list ref AND a DEFINED-but-EMPTY `except` ref, with no RESOLVED
// positive scope, must NOT compose to match-ALL on an `accept` term.
//
// The #4338 "any except X" compose (ResolveFilterPrefixListAddrs) fires on
// `hasExcept && !hasPositiveRef && addrsAllMatchAny(positive)` and lowers the
// direction to (exceptPrefixes, except=true, constrained=true) = match-ALL. That
// gate is correct only when the positive side is GENUINELY the match-any
// universe. An UNRESOLVED positive ref leaves `positive` empty WITHOUT the
// operator having written `any` — addrsAllMatchAny then returns a FALSE positive,
// the gate fires, and:
//   - `accept` term  -> match-ALL = ADMIT every packet  = fail-OPEN (the bug),
//   - `discard`/`reject` term -> match-ALL = DROP every packet = fail-CLOSED.
//
// hasPositiveRef is set only for RESOLVED positive refs (pl != nil), so an
// unresolved positive ref never sets it and the gate cannot see the intended
// specific scope. The fix records an UNRESOLVED positive ref separately
// (hasUnresolvedPositiveRef) and, when it is present, lowers the direction fail
// CLOSED BY ACTION: `accept` (and any non-deny action) -> match-NOTHING; only
// `discard`/`reject` keep match-ALL.
//
// This term shape is hard-rejected at strict commit TWICE — undefined prefix-list
// (validateFirewallPrefixListReferencesStrict) and mixed positive+except (#3359)
// — so it only reaches the runtime lowering on the tolerant / peer-sync /
// persisted-invalid load path (#1960 no-brick), same family as #5097/#5223.
//
// FAIL-ON-REVERT: drop the `hasUnresolvedPositiveRef && !firewallFilterActionDenies`
// branch from the compose gate in ResolveFilterPrefixListAddrs (so it always
// `return exceptPrefixes, true, true`) and the accept assertions below go RED —
// the accept term composes back to except=true = admit-ALL.
func TestResolvePrefixListAddrsUnresolvedPositivePlusExceptFailsClosedByAction_5225(t *testing.T) {
	// Positive refs are unresolved; both except lists are defined but empty.
	// This isolates #5225 from #11451's unresolved-except handling.
	cfg := &config.Config{PolicyOptions: config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{
			"empty_exc4": {Name: "empty_exc4"},
			"empty_exc6": {Name: "empty_exc6"},
		},
	}}

	// refs order: positive first, then except (natural config order). The lowering
	// is order-independent, but pin the realistic ordering.
	refs4 := []config.PrefixListRef{
		{Name: "undef_pos4", Except: false},
		{Name: "empty_exc4", Except: true},
	}
	refs6 := []config.PrefixListRef{
		{Name: "undef_pos6", Except: false},
		{Name: "empty_exc6", Except: true},
	}

	acceptCases := []struct {
		name      string
		refs      []config.PrefixListRef
		direction string
		action    string
	}{
		{"accept-source-inet", refs4, "source", "accept"},
		{"accept-dest-inet", refs4, "destination", "accept"},
		{"accept-source-inet6", refs6, "source", "accept"},
		{"accept-dest-inet6", refs6, "destination", "accept"},
		// A modifier-only fall-through (Action == "") and a PBR redirect must ALSO
		// fail closed to match-NOTHING — an unresolvable positive set must never be
		// counted, logged, admitted, or redirected as a match.
		{"fallthrough-source-inet", refs4, "source", ""},
	}
	for _, tc := range acceptCases {
		t.Run(tc.name, func(t *testing.T) {
			addrs, except, constrained := resolvePrefixListAddrs(
				nil, tc.refs, cfg, "f", "t", tc.direction, tc.action,
			)
			if !constrained {
				t.Fatalf("an unresolved positive+except term must stay constrained "+
					"(fail closed), got constrained=false addrs=%v", addrs)
			}
			if except {
				t.Fatalf("#5225 REGRESSION: an unresolved positive prefix-list ref + "+
					"except on a non-deny term (%q) must lower to match-NOTHING "+
					"(except=false), NOT the match-ALL compose (except=true = admit "+
					"every packet = fail-OPEN). got except=true addrs=%v", tc.action, addrs)
			}
			if len(addrs) != 0 {
				t.Fatalf("match-NOTHING contributes NO prefixes, got addrs=%v", addrs)
			}
		})
	}

	// Regression guard: a `discard`/`reject` term with the SAME shape must STAY
	// fail-closed = match-ALL (except=true, empty set). A deny that matched nothing
	// would fall through to a later permit term = fail-OPEN for the deny (#5097).
	denyCases := []struct {
		name   string
		action string
	}{
		{"discard", "discard"},
		{"reject", "reject"},
	}
	for _, tc := range denyCases {
		t.Run("deny-"+tc.name, func(t *testing.T) {
			addrs, except, constrained := resolvePrefixListAddrs(
				nil, refs4, cfg, "f", "t", "source", tc.action,
			)
			if !except || !constrained {
				t.Fatalf("a %q term with unresolved positive+except must stay fail-closed "+
					"= match-ALL (except=true, constrained=true) so the deny drops "+
					"broadly; got except=%v constrained=%v addrs=%v",
					tc.action, except, constrained, addrs)
			}
			// The unresolved except ref contributes no prefixes, so the excepted set
			// is empty; inverted = match ALL.
			if len(addrs) != 0 {
				t.Fatalf("unresolved except contributes NO prefixes, got addrs=%v", addrs)
			}
		})
	}
}

// A RESOLVED positive prefix-list ref alongside an UNRESOLVED `except` ref is
// still fail-closed by action. The missing negative set makes preserving the
// positive match unsafe: non-deny actions match nothing; discard/reject match
// all so traffic cannot fall through to a later permit.
func TestResolvePrefixListAddrsResolvedPositivePlusUnresolvedExceptFailsClosedByAction_11451(t *testing.T) {
	cfg := &config.Config{
		PolicyOptions: config.PolicyOptionsConfig{
			PrefixLists: map[string]*config.PrefixList{
				"good": {Name: "good", Prefixes: []string{"10.0.0.0/8"}},
			},
		},
	}
	refs := []config.PrefixListRef{
		{Name: "good", Except: false},
		{Name: "undef_exc", Except: true},
	}
	for _, tc := range []struct {
		action     string
		wantExcept bool
	}{
		{"accept", false}, {"discard", true}, {"reject", true}, {"", false},
	} {
		t.Run("action="+tc.action, func(t *testing.T) {
			addrs, except, constrained := resolvePrefixListAddrs(
				nil, refs, cfg, "f", "t", "source", tc.action,
			)
			if !constrained {
				t.Fatalf("a resolved positive scope must stay constrained, got constrained=false")
			}
			if except != tc.wantExcept || len(addrs) != 0 {
				t.Fatalf("unresolved except action=%q: got except=%v addrs=%v, want except=%v and no prefixes",
					tc.action, except, addrs, tc.wantExcept)
			}
		})
	}
}

// A match-any positive (`0.0.0.0/0`) with an UNRESOLVED except is fail-closed
// by action: it cannot use the empty complement as match-all for an accept or
// PBR term, while a deny must continue matching all to prevent permit fallthrough.
func TestResolvePrefixListAddrsGenuineMatchAnyPlusUnresolvedExceptFailsClosedByAction_11451(t *testing.T) {
	cfg := &config.Config{}
	for _, tc := range []struct {
		action     string
		wantExcept bool
	}{
		{"accept", false}, {"discard", true}, {"reject", true}, {"", false},
	} {
		t.Run("action="+tc.action, func(t *testing.T) {
			addrs, except, constrained := resolvePrefixListAddrs(
				[]string{"0.0.0.0/0"},
				[]config.PrefixListRef{{Name: "undef_exc", Except: true}},
				cfg, "f", "t", "source", tc.action,
			)
			if !constrained {
				t.Fatalf("match-any + unresolved except must stay constrained, got false")
			}
			if except != tc.wantExcept || len(addrs) != 0 {
				t.Fatalf("match-any + unresolved except action=%q: got except=%v addrs=%v, want except=%v and no prefixes",
					tc.action, except, addrs, tc.wantExcept)
			}
		})
	}
}
