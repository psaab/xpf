package config

import (
	"strings"
	"testing"
)

// #16784: deny-configuration priced only the path a mutation NAMES.
// delete/deactivate/rename of an ANCESTOR destroys or relocates a
// denied descendant, copy overwrites-clones it, and the commit gate
// (AuthorizeExpandedCandidate) priced only candidate − active lines
// for group-bearing trees, so removal through any of those — and
// removal of an apply-groups linker (folded R3-F04-01) — committed
// with every gate returning nil.
//
// Fixture: class `limited` denies ^security policies policy guard
// (deny spelling) or is allowlisted to ^security policies policy other
// (allow spelling). The protected policy `guard` sits under ancestors
// `security` and `security policies`.

const candidate16784Text = `
security {
    policies {
        policy guard {
            then { deny; }
        }
        policy other {
            then { permit; }
        }
    }
    zones {
        security-zone trust {
            description ok16784;
        }
    }
}
system {
    host-name fw16784;
    login {
        class limited {
            permissions [ configure view ];
        }
    }
}
`

func cfg16784(t *testing.T, allow, deny string) *Config {
	t.Helper()
	var b strings.Builder
	b.WriteString("system { login { class limited { permissions [ configure view ]; ")
	if allow != "" {
		b.WriteString("allow-configuration \"" + allow + "\"; ")
	}
	if deny != "" {
		b.WriteString("deny-configuration \"" + deny + "\"; ")
	}
	b.WriteString("} } }")
	root, perrs := NewParser(b.String()).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := CompileConfig(&ConfigTree{Children: root.Children})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if _, restricted, err := ConfigurationLoginRegexesFor(cfg, "limited"); err != nil || !restricted {
		t.Fatalf("fixture class not regex-restricted (restricted=%v err=%v)", restricted, err)
	}
	return cfg
}

func candidate16784(t *testing.T) *ConfigTree {
	t.Helper()
	return parseHierText(t, candidate16784Text)
}

// Premise: the denied descendant is really in the candidate subtree,
// and a direct mutation of it is refused — otherwise every refusal
// below is vacuous.
func TestSubtreePremise16784(t *testing.T) {
	cfg := cfg16784(t, "", "^security policies policy guard")
	cand := candidate16784(t)
	if out := cand.FormatPathSet([]string{"security"}); !strings.Contains(out, "security policies policy guard") {
		t.Fatalf("premise broken: candidate subtree carries no guard policy:\n%s", out)
	}
	if err := AuthorizeConfigMutation(cfg, "limited", nil, "delete security policies policy guard"); err == nil {
		t.Fatal("premise failed: direct denied delete allowed")
	}
	if err := AuthorizeConfigMutation(cfg, "limited", nil, "set security zones security-zone trust description x"); err != nil {
		t.Fatalf("control failed: allowed set refused: %v", err)
	}
}

// The five defect rows, both spellings: ancestor delete, deactivate,
// rename (source), copy (source), and activate — each must refuse for
// `limited` because the subtree contains the denied descendant.
func TestAncestorSubtreeVerbsRefused16784(t *testing.T) {
	spellings := map[string]*Config{
		"deny":  cfg16784(t, "", "^security policies policy guard"),
		"allow": cfg16784(t, "^security policies policy other", ""),
	}
	lines := map[string]string{
		"delete ancestor":     "delete security",
		"delete mid ancestor": "delete security policies",
		"deactivate ancestor": "deactivate security",
		"activate ancestor":   "activate security policies",
		"rename ancestor":     "rename security to security2",
		"rename mid ancestor": "rename security policies to security policies2",
		"copy ancestor":       "copy security to security2",
		"copy mid ancestor":   "copy security policies to security policies2",
	}
	for sname, cfg := range spellings {
		for lname, line := range lines {
			if err := AuthorizeConfigMutationOnCandidate(cfg, "limited", nil, line, candidate16784(t)); err == nil {
				t.Errorf("%s spelling: %q ALLOWED though its subtree contains the denied descendant (#16784)", sname, lname)
			}
		}
	}
}

// Positive controls: the same ancestor mutations succeed once the
// denied descendant is absent (block-all removed), an allowed subtree
// is untouched, and unrestricted/empty classes are unaffected.
func TestAncestorSubtreeControls16784(t *testing.T) {
	cfg := cfg16784(t, "", "^security policies policy guard")
	noGuard := parseHierText(t, `
security {
    policies {
        policy other {
            then { permit; }
        }
    }
    zones {
        security-zone trust {
            description ok16784;
        }
    }
}
`)
	for _, line := range []string{
		"delete security",
		"deactivate security",
		"rename security to security2",
		"copy security to security2",
	} {
		if err := AuthorizeConfigMutationOnCandidate(cfg, "limited", nil, line, noGuard); err != nil {
			t.Errorf("%q refused though the denied descendant is absent: %v", line, err)
		}
	}
	// Allowed subtree of the real candidate stays allowed.
	for _, line := range []string{
		"delete security zones",
		"deactivate security zones security-zone trust",
		"rename security zones to security zones2",
	} {
		if err := AuthorizeConfigMutationOnCandidate(cfg, "limited", nil, line, candidate16784(t)); err != nil {
			t.Errorf("%q on an allowed subtree refused: %v", line, err)
		}
	}
	// Nil candidate keeps the legacy per-line verdict (commit backstop).
	if err := AuthorizeConfigMutationOnCandidate(cfg, "limited", nil, "delete security", nil); err != nil {
		t.Errorf("nil-candidate ancestor delete changed the per-line verdict: %v", err)
	}
	// No-regex and empty classes unaffected even with a candidate.
	unrestricted := classWithConfigRegex9154(t, "", "")
	if err := AuthorizeConfigMutationOnCandidate(unrestricted, "limited", nil, "delete security", candidate16784(t)); err != nil {
		t.Errorf("no-regex class refused an ancestor delete: %v", err)
	}
	if err := AuthorizeConfigMutationOnCandidate(cfg, "", nil, "delete security", candidate16784(t)); err != nil {
		t.Errorf("empty class refused an ancestor delete: %v", err)
	}
}

// Copy/rename INTO an existing denied node: the executor refuses the
// collision, so there is no overwrite to price — the destination must
// not be subtree-priced as destroyed. (Its per-line verdict applies.)
func TestCopyRenameDestinationNotSubtreePriced16784(t *testing.T) {
	cfg := cfg16784(t, "", "^security policies policy guard")
	// Copy an allowed policy onto the denied one's identity-adjacent
	// destination parent: destination `security policies` itself is
	// allowed per-line; only the source subtree matters.
	if err := AuthorizeConfigMutationOnCandidate(cfg, "limited", nil,
		"copy security zones to security zones2", candidate16784(t)); err != nil {
		t.Errorf("allowed copy refused: %v", err)
	}
}

// Edit-path resolution: the subtree is priced at the RESOLVED path.
func TestAncestorSubtreeEditPath16784(t *testing.T) {
	cfg := cfg16784(t, "", "^security policies policy guard")
	if err := AuthorizeConfigMutationOnCandidate(cfg, "limited", []string{"security"}, "delete policies", candidate16784(t)); err == nil {
		t.Error("edit security + delete policies ALLOWED though it destroys the denied descendant (#16784)")
	}
	if err := AuthorizeConfigMutationOnCandidate(cfg, "limited", []string{"security"}, "delete zones", candidate16784(t)); err != nil {
		t.Errorf("edit security + delete zones (allowed) refused: %v", err)
	}
}

// Commit gate: removal of the denied descendant — directly, through
// an ancestor, and through an apply-groups linker (R3-F04-01) — is
// refused for every tree, not only group-bearing ones.
func TestCommitRemovalPriced16784(t *testing.T) {
	cfg := cfg16784(t, "", "^security policies policy guard")
	active := candidate16784(t)

	removedDirect := parseHierText(t, `
security {
    policies {
        policy other {
            then { permit; }
        }
    }
}
system { host-name fw16784; }
`)
	if err := AuthorizeExpandedCandidate(cfg, "limited", removedDirect, active); err == nil {
		t.Error("commit removing the denied policy directly was ALLOWED (#16784)")
	}

	removedAncestor := parseHierText(t, `system { host-name fw16784; }`)
	if err := AuthorizeExpandedCandidate(cfg, "limited", removedAncestor, active); err == nil {
		t.Error("commit removing the whole security ancestor was ALLOWED (#16784)")
	}

	// R3-F04-01 leg: the denied leaf exists only through apply-groups;
	// deleting the linker removes it without naming it.
	groupActive := parseHierText(t, `
groups {
    G {
        security {
            policies {
                policy guard {
                    then { deny; }
                }
            }
        }
    }
}
apply-groups G;
security {
    zones {
        security-zone trust {
            description ok16784;
        }
    }
}
`)
	groupCandidate := parseHierText(t, `
groups {
    G {
        security {
            policies {
                policy guard {
                    then { deny; }
                }
            }
        }
    }
}
security {
    zones {
        security-zone trust {
            description ok16784;
        }
    }
}
`)
	if err := AuthorizeExpandedCandidate(cfg, "limited", groupCandidate, groupActive); err == nil {
		t.Error("commit deleting the apply-groups linker for a denied leaf was ALLOWED (#16784/R3-F04-01)")
	}

	// Controls: an unchanged candidate, and a candidate that removes
	// only allowed config, both commit.
	if err := AuthorizeExpandedCandidate(cfg, "limited", candidate16784(t), active); err != nil {
		t.Errorf("unchanged candidate refused at commit: %v", err)
	}
	removedAllowed := parseHierText(t, `
security {
    policies {
        policy guard {
            then { deny; }
        }
        policy other {
            then { permit; }
        }
    }
}
system { host-name fw16784; }
`)
	if err := AuthorizeExpandedCandidate(cfg, "limited", removedAllowed, active); err != nil {
		t.Errorf("commit removing only the allowed zones subtree refused: %v", err)
	}
}

// Allow-spelling commit removal: a candidate that drops a descendant
// the allowlist does not cover is refused; dropping covered config is not.
func TestCommitRemovalAllowlist16784(t *testing.T) {
	cfg := cfg16784(t, "^security policies policy other", "")
	active := candidate16784(t)
	cand := parseHierText(t, `
security {
    policies {
        policy other {
            then { permit; }
        }
    }
}
`)
	if err := AuthorizeExpandedCandidate(cfg, "limited", cand, active); err == nil {
		t.Error("allowlist commit removing the uncovered guard policy was ALLOWED (#16784)")
	}
}

// #17830: subtree/commit descendants must be adjudicated on CANONICAL
// LEXED tokens (quotes consumed), not display-set text. A quoted
// identity (`policy "guard"`) renders with quotes in FormatSet, so
// evaluating the raw display line never matches a deny authored
// against the lexed path `security policies policy guard`; a
// whitespace-bearing identity additionally broke the strings.Fields
// subtree navigation, finding no subtree at all.
func TestQuotedDescendantCanonicalAuthz17830(t *testing.T) {
	cfg := cfg16784(t, "", "^security policies policy guard")
	cand := parseHierText(t, `
security {
    policies {
        policy "guard" {
            then { deny; }
        }
        policy other {
            then { permit; }
        }
    }
}
`)
	// Premise: display text really carries the quotes, direct lexed
	// mutation is denied, and a quoted direct form is denied too.
	if out := cand.FormatPathSet([]string{"security"}); !strings.Contains(out, `policy "guard"`) {
		t.Fatalf("premise broken: display set lost authored quotes:\n%s", out)
	}
	if err := AuthorizeConfigMutation(cfg, "limited", nil, `delete security policies policy guard`); err == nil {
		t.Fatal("premise failed: direct denied delete allowed")
	}
	if err := AuthorizeConfigMutation(cfg, "limited", nil, `delete security policies policy "guard"`); err == nil {
		t.Fatal("premise failed: quoted direct denied delete allowed")
	}
	// Defect rows: ancestor mutation + commit removal of the quoted
	// descendant must refuse (canonical lexed descendant).
	if err := AuthorizeConfigMutationOnCandidate(cfg, "limited", nil, "delete security", cand); err == nil {
		t.Error("ancestor delete of quoted denied descendant ALLOWED (#17830)")
	}
	if err := AuthorizeConfigMutationOnCandidate(cfg, "limited", nil, "delete security policies", cand); err == nil {
		t.Error("mid-ancestor delete of quoted denied descendant ALLOWED (#17830)")
	}
	if err := AuthorizeConfigMutationOnCandidate(cfg, "limited", nil, "deactivate security", cand); err == nil {
		t.Error("ancestor deactivate of quoted denied descendant ALLOWED (#17830)")
	}
	removed := parseHierText(t, `
security {
    policies {
        policy other {
            then { permit; }
        }
    }
}
`)
	if err := AuthorizeExpandedCandidate(cfg, "limited", removed, cand); err == nil {
		t.Error("commit removing quoted denied descendant ALLOWED (#17830)")
	}
	// Positive controls: same mutations allowed when the denied
	// quoted descendant is absent, and allowed subtrees untouched.
	noGuard := parseHierText(t, `
security {
    policies {
        policy other {
            then { permit; }
        }
    }
}
`)
	if err := AuthorizeConfigMutationOnCandidate(cfg, "limited", nil, "delete security", noGuard); err != nil {
		t.Errorf("ancestor delete without denied quoted descendant refused: %v", err)
	}
	if err := AuthorizeExpandedCandidate(cfg, "limited", noGuard, noGuard); err != nil {
		t.Errorf("unchanged commit refused: %v", err)
	}
	if err := AuthorizeConfigMutationOnCandidate(cfg, "limited", nil, `delete security policies policy other`, cand); err != nil {
		t.Errorf("allowed quoted-adjacent policy delete refused: %v", err)
	}
	// Quoted allowed identities must also keep the positive verdict:
	// the ordinary gate allows their canonical spelling, and the subtree
	// and commit checks must not deny them because display output quotes it.
	allowQuoted := cfg16784(t, "^security policies policy guard", "")
	if err := AuthorizeConfigMutationOnCandidate(allowQuoted, "limited", nil, `delete security policies policy "guard"`, cand); err != nil {
		t.Errorf("allowed quoted policy subtree delete refused: %v", err)
	}
	if err := AuthorizeExpandedCandidate(allowQuoted, "limited", noGuard, cand); err != nil {
		t.Errorf("commit removing allowed quoted policy refused: %v", err)
	}
}

// #17830 whitespace leg: a whitespace-bearing identity is ONE lexed
// token. Root reconstruction must preserve token boundaries when
// navigating to that identity, and descendants must be authorized on
// their unquoted canonical lexed path.
func TestWhitespaceDescendantCanonicalAuthz17830(t *testing.T) {
	cfg := cfg16784(t, "", "^security policies policy guard name then deny")
	cand := parseHierText(t, `
security {
    policies {
        policy "guard name" {
            then { deny; }
        }
        policy other {
            then { permit; }
        }
    }
}
`)
	if out := cand.FormatPathSet([]string{"security", "policies"}); !strings.Contains(out, `policy "guard name" then deny`) {
		t.Fatalf("premise broken: quoted identity missing from display path:\n%s", out)
	}
	// The ancestor mutation is allowed by its own path, but its subtree
	// contains a descendant covered by the deny.
	if err := AuthorizeConfigMutationOnCandidate(cfg, "limited", nil, "delete security", cand); err == nil {
		t.Error("ancestor delete of whitespace-bearing denied descendant ALLOWED (#17830)")
	}
	// This targets the whitespace-bearing node itself. The typed root is
	// lexed as four tokens; strings.Fields over its joined spelling splits
	// the final identity and used to find no subtree.
	if err := AuthorizeConfigMutationOnCandidate(cfg, "limited", []string{"security", "policies"}, `delete policy "guard name"`, cand); err == nil {
		t.Error("delete of whitespace-bearing denied subtree ALLOWED (#17830)")
	}
	removed := parseHierText(t, `
security {
    policies {
        policy other {
            then { permit; }
        }
    }
}
`)
	if err := AuthorizeExpandedCandidate(cfg, "limited", removed, cand); err == nil {
		t.Error("commit removing whitespace-bearing denied descendant ALLOWED (#17830)")
	}
	// Same roots remain permitted when the denied descendant is absent;
	// a neighboring policy is outside the deny.
	if err := AuthorizeConfigMutationOnCandidate(cfg, "limited", nil, "delete security", removed); err != nil {
		t.Errorf("ancestor delete without denied whitespace-bearing descendant refused: %v", err)
	}
	if err := AuthorizeConfigMutationOnCandidate(cfg, "limited", []string{"security", "policies"}, "delete policy other", cand); err != nil {
		t.Errorf("allowed neighboring policy delete refused: %v", err)
	}
	if err := AuthorizeExpandedCandidate(cfg, "limited", removed, removed); err != nil {
		t.Errorf("unchanged commit refused: %v", err)
	}
}
