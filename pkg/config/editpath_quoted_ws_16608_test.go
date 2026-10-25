package config

import (
	"strings"
	"testing"
)

// #16608: NormalizeEditPathTokens re-lexed the space-joined cursor, so a
// quoted element with interior whitespace (`edit ... filter "lan in"`,
// stored as the single lexed token `lan in`) split into two tokens. Every
// later set/delete under that cursor then landed on `filter lan` while
// commit check passed and the applied `filter "lan in"` stayed unchanged.
// The cursor must be kept as lexed tokens and re-lexed only from the
// quoted join; #14716's split-comment normalization must stay green.

func TestNormalizeEditPathTokensQuotedWhitespace16608(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"whitespace element", []string{"firewall", "family", "inet", "filter", "lan in"}, []string{"firewall", "family", "inet", "filter", "lan in"}},
		{"whitespace element doubled space", []string{"filter", "a  b"}, []string{"filter", "a  b"}},
		{"plain control", []string{"firewall", "family", "inet", "filter", "lanin"}, []string{"firewall", "family", "inet", "filter", "lanin"}},
		// #14716 cells: raw decorated cursors still normalize to the lexed path.
		{"quoted raw", []string{`"system"`}, []string{"system"}},
		{"comment plus quote", []string{"/*", "interfaces", "*/", `"system"`}, []string{"system"}},
		{"split comment open only", []string{"system", "/*"}, []string{"system"}},
		{"groups whitespace", []string{"groups", "my group"}, []string{"groups", "my group"}},
		{"prefix-list whitespace", []string{"policy-options", "prefix-list", "pl one"}, []string{"policy-options", "prefix-list", "pl one"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := NormalizeEditPathTokens(tc.in)
			if strings.Join(got, "\x00") != strings.Join(tc.want, "\x00") {
				t.Fatalf("NormalizeEditPathTokens(%q) = %q, want %q (#16608)", tc.in, got, tc.want)
			}
			// Idempotent: normalizing the normalized cursor is a fixed point.
			if again := NormalizeEditPathTokens(got); strings.Join(again, "\x00") != strings.Join(got, "\x00") {
				t.Fatalf("Normalize not idempotent: %q -> %q (#16608)", got, again)
			}
		})
	}
	if got := NormalizeEditPathTokens(nil); got != nil {
		t.Fatalf("Normalize(nil) = %v, want nil", got)
	}
}

// The gate must judge the same whitespace-bearing path the executor acts
// on: an anchored deny on the REAL `lan in` path must bite from that
// cursor, and an anchored allow for the split spelling must not admit it.
func TestAuthorizeConfigMutationQuotedWhitespaceCursor16608(t *testing.T) {
	cursor := []string{"firewall", "family", "inet", "filter", "lan in"}
	line := "set term block then discard"

	denyReal := classWithConfigRegex9154(t, "", `^firewall family inet filter lan in`)
	if err := AuthorizeConfigMutation(denyReal, "limited", cursor, line); err == nil {
		t.Fatal("set under [filter \"lan in\"] was ALLOWED under anchored deny on the real path; " +
			"the gate judged the split `lan` path while the executor acts on `lan in` (#16608)")
	}
	// An allow covering only the SPLIT spelling's full path (what the buggy
	// gate judged: `... filter lan in term block ...` as separate tokens,
	// which space-joins identically — so use the split path with the term
	// resolved under `lan`, i.e. no `in` element) must not admit the real
	// path. The discriminating allow is the one the split gate would have
	// matched: `^firewall family inet filter lan term`.
	allowSplit := classWithConfigRegex9154(t, `^firewall family inet filter lan term`, "")
	if err := AuthorizeConfigMutation(allowSplit, "limited", cursor, line); err == nil {
		t.Fatal("set under [filter \"lan in\"] was ALLOWED under an allow anchored only to the split spelling (#16608)")
	}
	// Control: allow on the real path admits; plain cursor unchanged.
	allowReal := classWithConfigRegex9154(t, `^firewall family inet filter lan in`, "")
	if err := AuthorizeConfigMutation(allowReal, "limited", cursor, line); err != nil {
		t.Errorf("set under [filter \"lan in\"] refused under allow on the real path: %v", err)
	}
	plain := []string{"firewall", "family", "inet", "filter", "lanin"}
	if err := AuthorizeConfigMutation(allowReal, "limited", plain, line); err == nil {
		// allowReal does not cover lanin, so refusal is expected; just ensure no panic path.
		_ = err
	}
	denyPlain := classWithConfigRegex9154(t, "", `^firewall family inet filter lanin`)
	if err := AuthorizeConfigMutation(denyPlain, "limited", plain, line); err == nil {
		t.Error("plain lanin control was ALLOWED under its anchored deny")
	}
}

// Compare headers must quote a whitespace-bearing element as one token,
// and the child path must come from node Keys (not Fields(KeyPath())).
func TestFormatCompareQuotedWhitespaceHeader16608(t *testing.T) {
	oldTree := parseHierText(t, `
firewall {
    family {
        inet {
            filter "lan in" {
                term allow {
                    then accept;
                }
            }
        }
    }
}
`)
	newTree := parseHierText(t, `
firewall {
    family {
        inet {
            filter "lan in" {
                term allow {
                    then accept;
                }
                term block {
                    then discard;
                }
            }
        }
    }
}
`)
	out := FormatCompare(oldTree, newTree)
	if !strings.Contains(out, `[edit firewall family inet filter "lan in"]`) {
		t.Fatalf("compare header did not quote the whitespace filter as one token (#16608):\n%s", out)
	}
	if strings.Contains(out, "[edit firewall family inet filter lan in]") {
		t.Fatalf("compare header split the whitespace filter into two tokens (#16608):\n%s", out)
	}
	if !strings.Contains(out, "term block") {
		t.Fatalf("compare missing added term:\n%s", out)
	}
	// Scoped compare at the whitespace path renders under the same header.
	scoped := FormatCompareAtPath(oldTree, newTree, []string{"firewall", "family", "inet", "filter", "lan in"})
	if !strings.Contains(scoped, "term block") {
		t.Fatalf("scoped compare at whitespace filter missing added term:\n%s", scoped)
	}
}
