package config

import (
	"strings"
	"testing"
)

// #15259 (A90-02): a group-supplied `then next policy` beside an inline
// `then accept`/`then reject` was silently dropped, while the mirror
// (group accept/reject beside inline next policy) strict-rejected via
// #11780. The asymmetry was a verdict inconsistency for one conflict
// class: `next policy` is a flow-control action that conflicts with a
// terminal exactly as #11780 already judges inline, so both directions
// must produce the same verdict.
//
// Mechanism (measured on origin/master): the failing shape is a group
// term CONTAINER (`term t1 { then next policy; }`) merging into an
// inline term whose `then` is a leaf or container
// (`then accept;` / `then { accept; }`). The container-container merge
// recurses into the inline term and merges the group's `then` node as
// a leaf child: the group `then next policy` leaf (Keys
// [then next policy]) met the inline `then accept` leaf as its
// keyword peer and took the generic inline-wins override, so NextPolicy
// never materialised and validatePolicyNextPolicyActions11780 never
// saw the conflict. Leaf-spelling group `then` nodes already adopted
// beside their peer via the surrounding container path and reached the
// gate; only this leaf-vs-leaf recursion dropped the group side.
//
// FAIL-ON-REVERT: remove the #15259 adoption in mergeNodes (or the
// routingTermThenNextPolicy15259 predicate) and the strict cells below
// go RED — CompileConfig accepts the contradictory term and the inline
// terminal silently wins.

func TestRoutingTermNextPolicyVsTerminalGroupInlineStrict15259(t *testing.T) {
	cases := []struct {
		name string
		src  string
		term string // expected terminal named in the error
	}{
		{
			name: "group-next-container-then-vs-inline-accept-leaf",
			src: `groups { G { policy-options { policy-statement P { term t1 { then next policy; } } } } }
policy-options { policy-statement P { term t1 { then accept; } apply-groups G; } }`,
			term: "accept",
		},
		{
			name: "group-next-container-then-vs-inline-reject-leaf",
			src: `groups { G { policy-options { policy-statement P { term t1 { then next policy; } } } } }
policy-options { policy-statement P { term t1 { then reject; } apply-groups G; } }`,
			term: "reject",
		},
		{
			// Mirror direction: must keep rejecting (already did via the
			// container path); pinning it proves both directions agree.
			name: "group-accept-container-then-vs-inline-next-leaf",
			src: `groups { G { policy-options { policy-statement P { term t1 { then accept; } } } } }
policy-options { policy-statement P { term t1 { then next policy; } apply-groups G; } }`,
			term: "accept",
		},
		{
			name: "group-reject-container-then-vs-inline-next-leaf",
			src: `groups { G { policy-options { policy-statement P { term t1 { then reject; } } } } }
policy-options { policy-statement P { term t1 { then next policy; } apply-groups G; } }`,
			term: "reject",
		},
		{
			// Malformed flow-control (`next term` is not `next policy` in
			// routing) supplied by a group beside an inline terminal must
			// also materialise so the #11780 malformed gate sees it, instead
			// of being dropped to a clean accept. Its diagnostic names the
			// malformed value, not the surviving terminal.
			name: "group-malformed-next-container-then-vs-inline-accept-leaf",
			src: `groups { G { policy-options { policy-statement P { term t1 { then next term; } } } } }
policy-options { policy-statement P { term t1 { then accept; } apply-groups G; } }`,
			term: "term",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(hierTree(t, tc.src))
			if err == nil {
				t.Fatalf("group next-policy/terminal conflict compiled clean; inline %s would silently win", tc.term)
			}
			if !strings.Contains(err.Error(), "next") || !strings.Contains(err.Error(), tc.term) {
				t.Fatalf("error %q must name next-policy and %s", err, tc.term)
			}
			if !strings.Contains(err.Error(), "P") || !strings.Contains(err.Error(), "t1") {
				t.Fatalf("error %q must name policy-statement P and term t1", err)
			}
		})
	}
}

func TestRoutingTermNextPolicyVsTerminalGroupLenient15259(t *testing.T) {
	src := `groups { G { policy-options { policy-statement P { term t1 { then next policy; } } } } }
policy-options { policy-statement P { term t1 { then accept; } apply-groups G; } }`
	cfg, err := CompileConfigLenient(hierTree(t, src))
	if err != nil {
		t.Fatalf("lenient compile must boot: %v", err)
	}
	term := dr16h3Term(t, cfg)
	if !term.NextPolicy {
		t.Fatalf("lenient conflicting term lost NextPolicy (group side dropped): %+v", term)
	}
	if term.Action != "accept" {
		t.Fatalf("lenient conflicting term Action=%q, want retained inline accept per #11780 lenient contract", term.Action)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "t1") && strings.Contains(w, "next policy") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient warnings %v omit next-policy conflict warning for t1", cfg.Warnings)
	}
}

func TestRoutingTermNextPolicyGroupControls15259(t *testing.T) {
	// Group next-policy beside a modifier-only inline term: no terminal,
	// so no conflict — next policy must survive with the modifier.
	modifierOnly := `groups { G { policy-options { policy-statement P { term t1 { then next policy; } } } } }
policy-options { policy-statement P { term t1 { then local-preference 200; } apply-groups G; } }`
	cfg, err := CompileConfig(hierTree(t, modifierOnly))
	if err != nil {
		t.Fatalf("group next-policy beside modifier-only term rejected: %v", err)
	}
	term := dr16h3Term(t, cfg)
	if !term.NextPolicy || term.Action != "" || !term.HasLocalPreference || term.LocalPreference != 200 {
		t.Fatalf("modifier+next term = %+v, want NextPolicy with local-preference 200 and no terminal", term)
	}

	// Group next-policy beside an inline next-policy: identical repeat
	// stays legal.
	sameNext := `groups { G { policy-options { policy-statement P { term t1 { then next policy; } } } } }
policy-options { policy-statement P { term t1 { then next policy; } apply-groups G; } }`
	cfg, err = CompileConfig(hierTree(t, sameNext))
	if err != nil {
		t.Fatalf("same next-policy merged term rejected: %v", err)
	}
	if term := dr16h3Term(t, cfg); !term.NextPolicy || term.Action != "" {
		t.Fatalf("same-next term = %+v, want NextPolicy and no terminal", term)
	}

	// Group accept beside an inline accept (same terminal): the #14425
	// control must stay legal and must not gain a next-policy conflict.
	sameAccept := `groups { G { policy-options { policy-statement P { term t1 { then accept; } } } } }
policy-options { policy-statement P { term t1 { then accept; } apply-groups G; } }`
	cfg, err = CompileConfig(hierTree(t, sameAccept))
	if err != nil {
		t.Fatalf("same-accept merged term rejected: %v", err)
	}
	if term := dr16h3Term(t, cfg); term.Action != "accept" || term.NextPolicy {
		t.Fatalf("same-accept term = %+v, want accept without NextPolicy", term)
	}
}
