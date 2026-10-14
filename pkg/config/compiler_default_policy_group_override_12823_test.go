package config

import (
	"strconv"
	"strings"
	"testing"
)

// #12823: a group default-policy merged recursively into an inline
// default-policy produced a 2-child block [inline, group], which #11367
// (and #12821) rejected even though the inline value is a valid
// higher-precedence override of the group value. Inline must win.

func groupDefaultPolicyConfig12823(groupAction, inline string) string {
	return "groups {\n    G12823 {\n        security {\n            policies {\n                default-policy {\n                    " + groupAction + ";\n                }\n            }\n        }\n    }\n}\napply-groups G12823;\nsecurity {\n    policies {\n        " + inline + "\n    }\n}\n"
}

func TestGroupDefaultPolicyInlineOverride12823(t *testing.T) {
	cases := []struct {
		name   string
		group  string
		inline string
		want   PolicyAction
	}{
		{"block override deny over permit", "permit-all", "default-policy {\n            deny-all;\n        }", PolicyDeny},
		{"block override permit over deny", "deny-all", "default-policy {\n            permit-all;\n        }", PolicyPermit},
		{"block override reject over permit", "permit-all", "default-policy {\n            reject-all;\n        }", PolicyReject},
		{"flat override deny over permit", "permit-all", "default-policy deny-all;", PolicyDeny},
		{"flat override permit over deny", "deny-all", "default-policy permit-all;", PolicyPermit},
		{"equal block value", "deny-all", "default-policy {\n            deny-all;\n        }", PolicyDeny},
		{"equal flat value", "permit-all", "default-policy permit-all;", PolicyPermit},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text := groupDefaultPolicyConfig12823(tc.group, tc.inline)
			tree := defaultPolicyTree11821(t, text)
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("strict compile rejected valid inline override of group default-policy: %v\n%s", err, text)
			}
			if cfg.Security.DefaultPolicy != tc.want {
				t.Fatalf("default-policy = %v, want inline value %v", cfg.Security.DefaultPolicy, tc.want)
			}
			// SchemaValidate runs on the authored (pre-expansion) tree in
			// some callers and on expanded trees in others; the authored
			// tree must validate.
			if err := SchemaValidate(defaultPolicyTree11821(t, text), nil); err != nil {
				t.Fatalf("SchemaValidate rejected valid override config: %v", err)
			}
			// Lenient must also yield inline value without ambiguity warning.
			cfg2, err := CompileConfigLenient(defaultPolicyTree11821(t, text))
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			if cfg2.Security.DefaultPolicy != tc.want {
				t.Fatalf("lenient default-policy = %v, want %v", cfg2.Security.DefaultPolicy, tc.want)
			}
			for _, w := range cfg2.Warnings {
				if strings.Contains(w, "default-policy") && (strings.Contains(w, "#11367") || strings.Contains(w, "#12821")) {
					t.Fatalf("lenient compile warned about resolved override: %q", w)
				}
			}
		})
	}
}

// Group value alone (no inline) must still be inherited.
func TestGroupDefaultPolicyInheritedWithoutInline12823(t *testing.T) {
	text := "groups {\n    G12823 {\n        security {\n            policies {\n                default-policy {\n                    permit-all;\n                }\n            }\n        }\n    }\n}\napply-groups G12823;\nsecurity {\n    policies {\n    }\n}\n"
	cfg, err := CompileConfig(defaultPolicyTree11821(t, text))
	if err != nil {
		t.Fatalf("strict compile rejected group-only default-policy: %v", err)
	}
	if cfg.Security.DefaultPolicy != PolicyPermit {
		t.Fatalf("group-only default-policy = %v, want permit", cfg.Security.DefaultPolicy)
	}
}

// Same-tier ambiguity must still reject: an inline block with two children
// remains a #11367 ambiguity, and repeated inline stanzas remain a #11821
// conflict even when a group choice is also present.
func TestGroupDefaultPolicySameTierAmbiguityStillRejects12823(t *testing.T) {
	// Inline-authored two-child block alongside a group value.
	text := groupDefaultPolicyConfig12823("permit-all", "default-policy {\n            deny-all;\n            reject-all;\n        }")
	if _, err := CompileConfig(defaultPolicyTree11821(t, text)); err == nil {
		t.Fatal("strict compile accepted inline-authored two-child default-policy block")
	} else if !strings.Contains(err.Error(), "default-policy") {
		t.Fatalf("error %q does not name default-policy", err)
	}
	cfg, err := CompileConfigLenient(defaultPolicyTree11821(t, text))
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	if cfg.Security.DefaultPolicy != PolicyDeny {
		t.Fatalf("lenient ambiguous default-policy = %v, want deny (fail-closed)", cfg.Security.DefaultPolicy)
	}
	// The group's block is suppressed by the first inline value, but a
	// distinct second inline value remains a duplicate-stanza conflict.
	duplicates := groupDefaultPolicyConfig12823(
		"permit-all",
		"default-policy deny-all;\n        default-policy reject-all;",
	)
	if _, err := CompileConfig(defaultPolicyTree11821(t, duplicates)); err == nil ||
		!strings.Contains(err.Error(), "#11821") {
		t.Fatalf("strict compile error = %v, want #11821 duplicate-stanza rejection", err)
	}
	cfg, err = CompileConfigLenient(defaultPolicyTree11821(t, duplicates))
	if err != nil {
		t.Fatalf("lenient duplicate-stanza compile: %v", err)
	}
	if cfg.Security.DefaultPolicy != PolicyDeny {
		t.Fatalf("lenient duplicate stanzas = %v, want deny (fail-closed)", cfg.Security.DefaultPolicy)
	}
}

// The synthetic per-root compilation isolates the sibling application views;
// it does not claim that conflicting top-level security roots are accepted.
func TestGroupDefaultPolicyInlineOverrideDoesNotLeak12823(t *testing.T) {
	text := `groups {
    G12823 {
        security {
            policies {
                default-policy {
                    permit-all;
                }
            }
        }
    }
}
security {
    policies {
        apply-groups G12823;
        default-policy {
            deny-all;
        }
    }
}
security {
    policies {
        apply-groups G12823;
    }
}`
	tree := defaultPolicyTree11821(t, text)
	if err := tree.ExpandGroups(); err != nil {
		t.Fatalf("ExpandGroups: %v", err)
	}
	var got []PolicyAction
	for _, security := range tree.FindChildren("security") {
		if len(security.FindChildren("policies")) == 0 {
			t.Fatal("missing policies block")
		}
		cfg, err := CompileConfig(&ConfigTree{Children: []*Node{security}})
		if err != nil {
			t.Fatalf("compile sibling policies: %v", err)
		}
		got = append(got, cfg.Security.DefaultPolicy)
	}
	if len(got) != 2 || got[0] != PolicyDeny || got[1] != PolicyPermit {
		t.Fatalf("sibling default-policy values = %v, want [deny permit]", got)
	}
}

// Conflicting group values (two groups) with no inline override must
// still reject / fail closed; with an inline override it must resolve.
func TestConflictingGroupsDefaultPolicy12823(t *testing.T) {
	base := "groups {\n    GA {\n        security { policies { default-policy { permit-all; } } }\n    }\n    GB {\n        security { policies { default-policy { deny-all; } } }\n    }\n}\napply-groups [ GA GB ];\n"
	noInline := base + "security { policies { } }\n"
	if _, err := CompileConfig(defaultPolicyTree11821(t, noInline)); err == nil {
		t.Fatal("strict compile accepted conflicting group default-policy values with no inline override")
	}
	cfg, err := CompileConfigLenient(defaultPolicyTree11821(t, noInline))
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	if cfg.Security.DefaultPolicy != PolicyDeny {
		t.Fatalf("lenient conflicting groups = %v, want deny (fail-closed)", cfg.Security.DefaultPolicy)
	}
	withInline := base + "security { policies { default-policy { reject-all; } } }\n"
	cfg2, err := CompileConfig(defaultPolicyTree11821(t, withInline))
	if err != nil {
		t.Fatalf("strict compile rejected inline override over conflicting groups: %v", err)
	}
	if cfg2.Security.DefaultPolicy != PolicyReject {
		t.Fatalf("inline override over conflicting groups = %v, want reject", cfg2.Security.DefaultPolicy)
	}
}

// B1 nested groups: OUTER permit-all applies INNER deny-all. The nested
// expansion merges INNER's block into OUTER's block before OUTER applies
// at root; the merged destination is group-adopted, not authored inline,
// so it must remain a group-group conflict (strict reject / deny in
// tolerant mode), never a silent permit.
func nestedGroupDefaultPolicyConfig12823(innerAction, outerAction string, withExcept bool) string {
	except := ""
	if withExcept {
		except = "\n        apply-groups-except UNRELATED12823;"
	}
	return `groups {
    INNER12823 {
        security {
            policies {
                default-policy {
                    ` + innerAction + `;
                }
            }
        }
    }
    OUTER12823 {
        apply-groups INNER12823;
        security {
            policies {
                default-policy {
                    ` + outerAction + `;
                }
            }
        }
    }
    UNRELATED12823 {
        system {
            host-name unrelated-12823;
        }
    }
}
apply-groups OUTER12823;
security {
    policies {` + except + `
    }
}
`
}

func TestNestedGroupsDefaultPolicyConflict12823(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
	}{
		{"nested conflict", nestedGroupDefaultPolicyConfig12823("deny-all", "permit-all", false)},
		{"nested conflict with apply-groups-except", nestedGroupDefaultPolicyConfig12823("deny-all", "permit-all", true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CompileConfig(defaultPolicyTree11821(t, tc.text)); err == nil {
				t.Fatal("strict compile accepted nested group default-policy conflict (permit-all over deny-all)")
			} else if !strings.Contains(err.Error(), "default-policy") {
				t.Fatalf("error %q does not name default-policy", err)
			}
			cfg, err := CompileConfigLenient(defaultPolicyTree11821(t, tc.text))
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			if cfg.Security.DefaultPolicy != PolicyDeny {
				t.Fatalf("lenient nested conflict = %v, want deny (fail-closed)", cfg.Security.DefaultPolicy)
			}
		})
	}
}

func TestNestedGroupsDefaultPolicySameAction12823(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
		want PolicyAction
	}{
		{"nested same action permit", nestedGroupDefaultPolicyConfig12823("permit-all", "permit-all", false), PolicyPermit},
		{"nested same action deny", nestedGroupDefaultPolicyConfig12823("deny-all", "deny-all", false), PolicyDeny},
		{"nested same action with apply-groups-except", nestedGroupDefaultPolicyConfig12823("deny-all", "deny-all", true), PolicyDeny},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := tc.want
			cfg, err := CompileConfig(defaultPolicyTree11821(t, tc.text))
			if err != nil {
				t.Fatalf("strict compile rejected nested same-action default-policy: %v", err)
			}
			if cfg.Security.DefaultPolicy != want {
				t.Fatalf("nested same-action default-policy = %v, want %v", cfg.Security.DefaultPolicy, want)
			}
			// apply-groups-except presence must not flip the outcome.
			cfg2, err := CompileConfigLenient(defaultPolicyTree11821(t, tc.text))
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			if cfg2.Security.DefaultPolicy != want {
				t.Fatalf("lenient nested same-action = %v, want %v", cfg2.Security.DefaultPolicy, want)
			}
		})
	}
}

func TestGroupDefaultPolicyMarkerHandlesDeepGroupBody12823(t *testing.T) {
	tree := &ConfigTree{}
	path := []string{"groups", "DEEP12823", "system", "host-name", "flat-set"}
	if err := tree.SetPathQuotedGrouped(path, nil, nil); err != nil {
		t.Fatalf("build flat-set group: %v", err)
	}
	groups := tree.FindChild("groups")
	group := groups.FindChild("DEEP12823")
	group.Children = append(group.Children, &Node{
		Keys: []string{"security"},
		Children: []*Node{{
			Keys: []string{"policies"},
			Children: []*Node{{
				Keys:     []string{"default-policy"},
				Children: []*Node{{Keys: []string{"permit-all"}, IsLeaf: true}},
			}},
		}},
	})
	// SetPathQuotedGrouped creates flat-set configuration incrementally and
	// accepts tree shapes deeper than the hierarchical parser's depth cap.
	// Retain such a deep opaque subtree beside the policy so group provenance
	// traversal must grow its context path rather than assume maxParseDepth.
	deep := &Node{Keys: []string{"opaque-0", "instance"}}
	cursor := deep
	for i := 1; i < maxParseDepth+64; i++ {
		child := &Node{Keys: []string{"opaque-" + strconv.Itoa(i), "instance"}}
		cursor.Children = []*Node{child}
		cursor = child
	}
	group.Children = append(group.Children, deep)
	tree.Children = append(tree.Children, &Node{Keys: []string{"apply-groups", "DEEP12823"}, IsLeaf: true})

	if err := tree.ExpandGroups(); err != nil {
		t.Fatalf("ExpandGroups on deep flat-set group tree: %v", err)
	}
}
