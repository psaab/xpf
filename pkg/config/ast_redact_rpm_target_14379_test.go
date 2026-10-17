package config

import (
	"strings"
	"testing"
)

// #14379 (DR4-H7 + DR4-H7-ext). urlLeafIndices had no `target` case, so the
// RPM probe target's bare spelling (`target <url>`) and `target address
// <url>` spelling — neither of which contains a `url` token — rendered a
// credential-bearing URL verbatim through RedactedClone on every AST
// display surface, while `target url <url>` (which does) and the typed
// route (RPMTest.MarshalJSON) redacted the same value. The fixture below
// plants the credential in each installed spelling, renders through
// RedactedClone in every format, and asserts the sentinel is gone and the
// host remains. It fails on the pre-fix code for the bare and `address`
// spellings and passes after the rpm-gated `target` case.

const rpmTargetSecret14379 = "SECRET14379TOKEN"

func rpmTargetTree14379(t *testing.T, lines []string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, line := range lines {
		toks, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(toks); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	return tree
}

func rpmTargetHierTree14379(t *testing.T, text string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("NewParser: %v", errs)
	}
	return tree
}

// TestRPMTargetBareAndAddressSpellingsRedacted14379 is the decisive
// regression: bare, address (flat / block / grandchild) and url spellings
// of the RPM probe target, each across every RedactedClone format.
func TestRPMTargetBareAndAddressSpellingsRedacted14379(t *testing.T) {
	planted := "https://user:" + rpmTargetSecret14379 + "@host.example.com/base?token=" + rpmTargetSecret14379

	cases := []struct {
		name string
		tree func(t *testing.T) *ConfigTree
	}{
		{"bare target flat-set", func(t *testing.T) *ConfigTree {
			return rpmTargetTree14379(t, []string{
				`set services rpm probe P test t target "` + planted + `"`,
			})
		}},
		{"target address flat-set", func(t *testing.T) *ConfigTree {
			return rpmTargetTree14379(t, []string{
				`set services rpm probe p1 test t1 probe-type http-get`,
				`set services rpm probe p1 test t1 target address "` + planted + `"`,
			})
		}},
		{"target address block", func(t *testing.T) *ConfigTree {
			return rpmTargetHierTree14379(t, `services { rpm { probe p1 { test t1 { probe-type http-get; target { address "`+planted+`"; } } } } }`)
		}},
		{"target address grandchild", func(t *testing.T) *ConfigTree {
			return rpmTargetHierTree14379(t, `services { rpm { probe p1 { test t1 { probe-type http-get; target { address { "`+planted+`"; } } } } } }`)
		}},
		{"target url flat-set (pre-existing control)", func(t *testing.T) *ConfigTree {
			return rpmTargetTree14379(t, []string{
				`set services rpm probe p1 test t1 target url "` + planted + `"`,
			})
		}},
		{"target url block (pre-existing control)", func(t *testing.T) *ConfigTree {
			return rpmTargetHierTree14379(t, `services { rpm { probe p1 { test t1 { probe-type http-get; target { url "`+planted+`"; } } } } }`)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := tc.tree(t)
			red := tree.RedactedClone()
			renders := map[string]string{
				"Format":            red.Format(),
				"FormatSet":         red.FormatSet(),
				"FormatJSON":        red.FormatJSON(),
				"FormatXML":         red.FormatXML(),
				"FormatInheritance": red.FormatInheritance(),
			}
			for format, out := range renders {
				if strings.Contains(out, rpmTargetSecret14379) {
					t.Errorf("%s: %s leaked the planted RPM target credential:\n%s", tc.name, format, out)
				}
				if strings.Contains(out, "user:") {
					t.Errorf("%s: %s leaked the RPM target userinfo:\n%s", tc.name, format, out)
				}
				if !strings.Contains(out, "host.example.com") {
					t.Errorf("%s: %s lost the diagnostic host (over-redaction):\n%s", tc.name, format, out)
				}
			}
			// FormatCompare routes through FormatCompareRedacted, which
			// shares urlLeafIndices via fingerprintRedactedClone.
			diff := FormatCompareRedacted(&ConfigTree{}, tree)
			if strings.Contains(diff, rpmTargetSecret14379) || strings.Contains(diff, "user:") {
				t.Errorf("%s: FormatCompareRedacted leaked the planted credential:\n%s", tc.name, diff)
			}
			if !strings.Contains(diff, "host.example.com") {
				t.Errorf("%s: FormatCompareRedacted lost the diagnostic host:\n%s", tc.name, diff)
			}
			// The live tree is never mutated — RedactedClone is display-only.
			if !strings.Contains(tree.FormatSet()+tree.Format(), rpmTargetSecret14379) {
				t.Errorf("%s: RedactedClone mutated the live tree", tc.name)
			}
		})
	}
}

// TestRPMTargetNonCredentialAndNonRPMControls14379 pins the two halves the
// rpm gate must not break: a credential-free RPM target renders unchanged,
// and a `target` leaf outside an rpm ancestor is not claimed at all.
func TestRPMTargetNonCredentialAndNonRPMControls14379(t *testing.T) {
	tree := rpmTargetTree14379(t, []string{
		`set services rpm probe p1 test t1 target address 10.0.0.1`,
		`set services rpm probe p2 test t2 target 192.0.2.1`,
	})
	out := tree.RedactedClone().FormatSet()
	for _, want := range []string{"10.0.0.1", "192.0.2.1"} {
		if !strings.Contains(out, want) {
			t.Errorf("credential-free RPM target %q must render unchanged:\n%s", want, out)
		}
	}
	if strings.Contains(out, SecretRedacted) || strings.Contains(out, SecretDataPlaceholder) {
		t.Errorf("credential-free RPM target must not be redacted:\n%s", out)
	}

	// Direct gate check: RedactURL is a no-op on a bare host, so a
	// render-level test cannot discriminate an ungated `target` case —
	// pin urlLeafIndices itself, mirroring TestURLLeafIndicesGatesGenericKeywords_6703.
	for _, tc := range []struct {
		name string
		path []string
		want []int
	}{
		{"rpm bare target is a url leaf",
			[]string{"services", "rpm", "probe", "P", "test", "t", "target", "VALUE"}, []int{7}},
		{"rpm target address claims keyword and value",
			[]string{"services", "rpm", "probe", "P", "test", "t", "target", "address", "VALUE"}, []int{7, 8}},
		{"non-rpm target is NOT a url leaf",
			[]string{"services", "other", "target", "VALUE"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := urlLeafIndices(tc.path)
			if len(got) != len(tc.want) {
				t.Fatalf("urlLeafIndices(%v) = %v, want %v", tc.path, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("urlLeafIndices(%v) = %v, want %v", tc.path, got, tc.want)
				}
			}
		})
	}
}

// TestRPMTargetRedactedIngestRefused14379 pins the symmetric ingest guard:
// findRedactedURL shares urlLeafIndices, so a re-committed redacted RPM
// target (bare or address spelling) is refused, while a cleartext one
// ingests cleanly.
func TestRPMTargetRedactedIngestRefused14379(t *testing.T) {
	for _, line := range []string{
		`set services rpm probe P test t target "https://<redacted>@host.example.com/base"`,
		`set services rpm probe P test t target address "https://<redacted>@host.example.com/base"`,
		`set services rpm probe P test t target "https://host.example.com/base?<redacted>"`,
	} {
		tree := rpmTargetTree14379(t, []string{line})
		err := checkRedactionPlaceholder(tree)
		if err == nil {
			t.Errorf("a redacted RPM target must be refused on commit-ingest (%s)", line)
		} else if !strings.Contains(err.Error(), "redacted URL") {
			t.Errorf("error must identify the cause, got %v", err)
		}
	}

	clean := rpmTargetTree14379(t, []string{
		`set services rpm probe P test t target "https://host.example.com/base"`,
	})
	if err := checkRedactionPlaceholder(clean); err != nil {
		t.Errorf("a cleartext RPM target must ingest cleanly, got %v", err)
	}
}
