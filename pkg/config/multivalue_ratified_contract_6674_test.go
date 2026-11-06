package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// #6674 — the two `multi: true` leaves whose extra values are not representable
// are RATIFIED as accepting one value, not implemented as lists.
//
// WHAT #6673 ALREADY DID, so this is not re-litigated: both leaves now
// accumulate every authored value into a plural field, so nothing escapes
// validation, and a multi-valued list is hard-REJECTED at commit / commit-check
// and warned on the tolerant load / peer-sync path. The fail-open half is gone.
// What remained was a TYPE-SHAPE limit and six source sites telling the reader a
// follow-up was coming.
//
// THE TWO ARMS RATIFY FOR DIFFERENT REASONS, and conflating them is how a wrong
// decision gets made for the pair:
//
//   - `security nat static rule-set <rs> rule <r> match destination-address`:
//     Junos takes ONE prefix here. A static-NAT rule is a 1:1 mapping — one
//     `match destination-address` against one `then static-nat prefix` — so N
//     external prefixes against one internal prefix names no target. `rule R1` /
//     `rule R2` already expresses the intent. The schema's `multi: true` is an
//     xpf OVER-ADVERTISEMENT of the grammar, not a promise.
//   - `routing-options forwarding-table export`: Junos genuinely takes a policy
//     CHAIN, so "the schema over-advertises" is NOT available as an argument
//     here, and neither is "a chain is equivalent to its first policy" — that
//     equivalence is measured FALSE in
//     pkg/frr/forwarding_export_chain_6674_test.go. It ratifies because
//     resolveECMP derives FRR's GLOBAL `maximum-paths`, which has no per-route
//     form, while Junos evaluates the chain per route and stops at the first
//     terminating action. The cheap composition is not Junos and the faithful
//     one is not expressible.
//
// This file pins the OPERATOR-FACING half of that decision. A source comment
// that rots is bad; a warning message that promises a feature which is never
// coming is worse, because the operator acts on it — they leave the list in
// place and wait.

// warningsFor6674 compiles a config on the TOLERANT path (load / peer-sync) and
// returns the warnings, which is where the operator-facing text for these two
// gates lives. The strict path returns the same text as an error.
func warningsFor6674(t *testing.T, cmds ...string) []string {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile failed: %v", err)
	}
	return cfg.Warnings
}

func warningMatching6674(t *testing.T, warnings []string, needle string) string {
	t.Helper()
	for _, w := range warnings {
		if strings.Contains(w, needle) {
			return w
		}
	}
	t.Fatalf("no warning containing %q; got %d warnings:\n%s",
		needle, len(warnings), strings.Join(warnings, "\n"))
	return ""
}

// TestRatifiedGatesDoNotPromiseAFollowUp_6674 is the behavioural guard, and it
// asserts on the text the OPERATOR reads rather than on the source.
//
// Both halves are required. The negative half alone would pass on a gate that
// stopped warning entirely; the positive half alone would pass on a gate that
// says both "this is permanent" and "support is tracked in #6674".
func TestRatifiedGatesDoNotPromiseAFollowUp_6674(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
		// needle identifies the gate's own warning among the others, so the
		// assertion cannot be satisfied by an unrelated warning.
		needle string
		// wantReason is a phrase that states WHY the limit is permanent. Keyed
		// to the reason, not to a fix: a rewording that keeps the reason keeps
		// this green, and a rewording that drops it does not.
		wantReason string
	}{
		{
			name: "forwarding-table-export",
			cmds: []string{
				"set policy-options policy-statement p1 then accept",
				"set policy-options policy-statement p2 then accept",
				"set routing-options forwarding-table export [ p1 p2 ]",
			},
			needle:     "forwarding-table export LIST FORM IS NOT SUPPORTED",
			wantReason: "GLOBAL ECMP toggle",
		},
		{
			name: "static-nat-match-destination-address",
			cmds: []string{
				"set security nat static rule-set rs from zone untrust",
				"set security nat static rule-set rs rule r1 match destination-address [ 10.6.0.1/32 10.6.0.2/32 ]",
				"set security nat static rule-set rs rule r1 then static-nat prefix 10.0.1.1/32",
			},
			needle:     "static NAT `match destination-address` LIST FORM IS NOT SUPPORTED",
			wantReason: "1:1 mapping",
		},
	}

	// Wording that tells the operator a follow-up is coming. Normalized for
	// line wrapping first — these strings are built from concatenated source
	// literals, and a claim that breaks across two of them is invisible to a
	// literal search.
	promises := []string{
		"tracked in #6674",
		"tracked as #6674",
		"support for the list form is tracked",
		"support for the junos export policy chain is tracked",
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			w := warningMatching6674(t, warningsFor6674(t, tc.cmds...), tc.needle)
			flat := strings.ToLower(strings.Join(strings.Fields(w), " "))
			for _, p := range promises {
				if strings.Contains(flat, strings.ToLower(p)) {
					t.Errorf("the warning still promises a follow-up (%q), which #6674 "+
						"decided is not coming — the operator leaves the list in place "+
						"and waits:\n%s", p, w)
				}
			}
			if !strings.Contains(w, tc.wantReason) {
				t.Errorf("the warning does not say WHY the limit is permanent "+
					"(want a mention of %q):\n%s", tc.wantReason, w)
			}
		})
	}
}

// ratifiedFollowUpClaim matches source text that presents #6674 as a pending
// follow-up. It is applied to WHITESPACE-NORMALIZED file text so a claim broken
// across two comment lines is still caught — the failure mode a literal grep
// has on exactly this kind of wrapped prose.
var ratifiedFollowUpClaim = regexp.MustCompile(
	`(?i)(tracked (as|in) #6674|separate (semantic change|renderer change)[^.]{0,40}#6674|#6674[^.]{0,40}(is a separate|not this fix))`)

// flattenSourceFor6674 normalizes source text so a claim WRAPPED across comment
// lines is visible to the regex.
//
// Collapsing whitespace alone is not enough, and that is the trap: a claim that
// breaks mid-phrase leaves the `//` marker of the next line embedded in the
// flattened text ("tracked as // #6674"), which no adjacency regex matches. The
// comment markers have to go too. TestSweepNormalizationSeesAWrappedClaim_6674
// is the positive control for exactly this — without it the normalization is an
// untested claim, and a sweep that cannot see a wrapped promise reports a clean
// tree it never actually searched.
func flattenSourceFor6674(text string) string {
	r := strings.NewReplacer("//", " ", "/*", " ", "*/", " ")
	return strings.Join(strings.Fields(r.Replace(text)), " ")
}

// TestSweepNormalizationSeesAWrappedClaim_6674 is the positive control for the
// sweep below. It asserts BOTH directions on one synthetic sample: the raw text
// must NOT match (or the control proves nothing about normalization) and the
// normalized text MUST match.
func TestSweepNormalizationSeesAWrappedClaim_6674(t *testing.T) {
	// The claim breaks between "tracked as" and "#6674", which is the shape a
	// literal grep and a whitespace-only normalization both miss: the `//` of
	// the continuation line lands between the two halves.
	const wrapped = "\t// Widening static NAT to fan a rule across several\n" +
		"\t// external prefixes is a change tracked as\n" +
		"\t// #6674 and is out of scope here.\n"

	if m := ratifiedFollowUpClaim.FindString(wrapped); m != "" {
		t.Fatalf("the RAW sample already matches (%q), so this control cannot show "+
			"that normalization is doing anything", m)
	}
	if m := ratifiedFollowUpClaim.FindString(flattenSourceFor6674(wrapped)); m == "" {
		t.Fatalf("a claim wrapped across comment lines is INVISIBLE to the sweep; "+
			"normalized text was %q", flattenSourceFor6674(wrapped))
	}
}

// TestNoSourceStillCallsThisAPendingFollowUp_6674 sweeps the tree for the six
// breadcrumbs, so a future edit cannot reinstate the promise in a comment while
// the warning text stays correct.
//
// It is a source sweep because that IS the artifact — the claim lives only in
// comments, and there is no runtime observation of a comment.
func TestNoSourceStillCallsThisAPendingFollowUp_6674(t *testing.T) {
	root := ".."
	var offenders []string
	checked := 0
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		text := string(b)
		if !strings.Contains(text, "6674") {
			return nil
		}
		checked++
		flat := flattenSourceFor6674(text)
		if m := ratifiedFollowUpClaim.FindString(flat); m != "" {
			offenders = append(offenders, path+": "+m)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if checked == 0 {
		t.Fatalf("no non-test source file mentions 6674 at all — the sweep found " +
			"nothing to search, so a green here says nothing about the claim")
	}
	if len(offenders) > 0 {
		t.Errorf("source still presents #6674 as a pending follow-up; it was RATIFIED "+
			"(neither arm is being implemented):\n  %s", strings.Join(offenders, "\n  "))
	}
	t.Logf("swept %d non-test source files mentioning 6674", checked)
}

// TestRatifiedGatesStillRejectOnCommit_6674 is the green control for the pair.
// A ratification must not weaken the gate: the list is still a hard REJECT on
// the strict commit path, and a single value still commits. Without both halves
// the tests above would pass on a change that simply stopped gating.
func TestRatifiedGatesStillRejectOnCommit_6674(t *testing.T) {
	build := func(cmds ...string) *ConfigTree {
		tree := &ConfigTree{}
		for _, cmd := range cmds {
			path, err := ParseSetCommand(cmd)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", cmd, err)
			}
		}
		return tree
	}

	t.Run("forwarding-table export list rejected", func(t *testing.T) {
		_, err := CompileConfig(build(
			"set policy-options policy-statement p1 then accept",
			"set policy-options policy-statement p2 then accept",
			"set routing-options forwarding-table export [ p1 p2 ]",
		))
		if err == nil {
			t.Fatal("a two-policy export list committed clean")
		}
		if !strings.Contains(err.Error(), "forwarding-table export declares 2 policies") {
			t.Fatalf("rejected by a different gate: %v", err)
		}
	})

	t.Run("forwarding-table export single still commits", func(t *testing.T) {
		cfg, err := CompileConfig(build(
			"set policy-options policy-statement p1 then accept",
			"set routing-options forwarding-table export p1",
		))
		if err != nil {
			t.Fatalf("a single export policy no longer commits: %v", err)
		}
		if cfg.RoutingOptions.ForwardingTableExport != "p1" {
			t.Errorf("selected export policy = %q, want p1", cfg.RoutingOptions.ForwardingTableExport)
		}
	})

	t.Run("static NAT match list rejected", func(t *testing.T) {
		_, err := CompileConfig(build(
			"set security zones security-zone untrust",
			"set security nat static rule-set rs from zone untrust",
			"set security nat static rule-set rs rule r1 match destination-address [ 10.6.0.1/32 10.6.0.2/32 ]",
			"set security nat static rule-set rs rule r1 then static-nat prefix 10.0.1.1/32",
		))
		if err == nil {
			t.Fatal("a two-prefix static NAT match committed clean")
		}
	})

	t.Run("static NAT single prefix still commits", func(t *testing.T) {
		cfg, err := CompileConfig(build(
			"set security zones security-zone untrust",
			"set security nat static rule-set rs from zone untrust",
			"set security nat static rule-set rs rule r1 match destination-address 10.6.0.1/32",
			"set security nat static rule-set rs rule r1 then static-nat prefix 10.0.1.1/32",
		))
		if err != nil {
			t.Fatalf("a single static NAT prefix no longer commits: %v", err)
		}
		var found bool
		for _, rs := range cfg.Security.NAT.Static {
			for _, r := range rs.Rules {
				if r.Match == "10.6.0.1/32" {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("the single external prefix did not reach the compiled rule")
		}
	})
}
