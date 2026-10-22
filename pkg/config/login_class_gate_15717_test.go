package config

import (
	"strings"
	"testing"
)

// #15717 (V44-04): `collectSchemaRefs` collected login-class definitions
// from un-applied `groups` bodies (the #1319 PR 3 permissive union), so a
// `system login user <n> class <c>` whose class existed ONLY in an
// un-applied group passed schema validation — then ExpandGroups discarded
// the group and the compiled config carried a user whose class does not
// exist. No post-compile gate checked `cfg.System.Login.Users[*].Class`,
// and CompileConfig never ran SchemaValidate at all, so even a plainly
// undefined class compiled clean. At runtime the unknown class resolves
// to no permissions (fail-closed), making this a silent lockout, not a
// privilege gain — Junos rejects the shape at commit.
//
// The fix is validateLoginUserClassReferencesStrict, wired dead-last in
// runUniformGates with the lenientLoginUserClassRef tolerant downgrade,
// plus sibling-aware (`FindChildren`) definition collection in
// collectSchemaRefs so a class defined in a second sibling `system` /
// `class-of-service` block of an applied group is actually seen.

const loginClassGateSrcA15717 = `groups {
    staged-rbac {
        system {
            login {
                class ops-admin {
                    permissions [ all ];
                }
            }
        }
    }
}
system {
    login {
        user alice {
            class ops-admin;
        }
    }
}
`

// Case B (report §V44-04): a directly compiled undefined class must be
// rejected by CompileConfig. RED on pre-fix code (err was nil).
func TestLoginUserUndefinedClassRejectedStrict15717(t *testing.T) {
	tree := buildTree4303(t, []string{
		"set system login user bob class totally-undefined-class",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted user bob with undefined class (fail-open regression)")
	}
	if !strings.Contains(err.Error(), "bob") || !strings.Contains(err.Error(), "totally-undefined-class") {
		t.Fatalf("error %q does not name the user and class", err)
	}
}

// Case A: class defined only in an un-applied group. The schema gate may
// keep passing (permissive peer-node union), but the post-compile gate
// sees the effective config — ExpandGroups discarded the group — and
// rejects. RED on pre-fix code.
func TestLoginUserUnappliedGroupClassRejectedStrict15717(t *testing.T) {
	tree := parseHierText(t, loginClassGateSrcA15717)
	cfg, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted alice with class ops-admin defined only in un-applied group; cfg=%+v", cfg)
	}
	if !strings.Contains(err.Error(), "ops-admin") {
		t.Fatalf("error %q does not name ops-admin", err)
	}
}

// The tolerant load / peer-sync path must still boot (#1960): the same
// shapes compile with a warning naming the class, and the user stanza is
// retained (runtime already denies the unknown class).
func TestLoginUserUndefinedClassLenientWarns15717(t *testing.T) {
	tree := buildTree4303(t, []string{
		"set system login user bob class totally-undefined-class",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "totally-undefined-class") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a lenient warning naming totally-undefined-class; warnings=%v", cfg.Warnings)
	}
	if cfg.System.Login == nil || len(cfg.System.Login.Users) != 1 {
		t.Fatalf("lenient compile dropped the user stanza: %+v", cfg.System.Login)
	}
}

func TestLoginUserUnappliedGroupClassLenientWarns15717(t *testing.T) {
	tree := parseHierText(t, loginClassGateSrcA15717)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "ops-admin") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a lenient warning naming ops-admin; warnings=%v", cfg.Warnings)
	}
}

// Positive controls: built-in classes, custom classes defined at top
// level, and custom classes inherited from an APPLIED group all compile
// clean on the strict path — the gate resolves against the effective
// config, so it must not reject what Junos accepts.
func TestLoginUserValidClassesAccepted15717(t *testing.T) {
	cases := map[string][]string{
		"built-in": {
			"set system login user bob class super-user",
		},
		"custom top-level": {
			"set system login class noc-admin permissions all",
			"set system login user bob class noc-admin",
		},
	}
	for name, cmds := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := CompileConfig(buildTree4303(t, cmds)); err != nil {
				t.Fatalf("CompileConfig rejected valid class: %v", err)
			}
		})
	}
	t.Run("custom in applied group", func(t *testing.T) {
		src := `groups {
    g1 {
        system {
            login {
                class ops-admin {
                    permissions [ view ];
                }
            }
        }
    }
}
apply-groups g1;
system {
    login {
        user alice {
            class ops-admin;
        }
    }
}
`
		if _, err := CompileConfig(parseHierText(t, src)); err != nil {
			t.Fatalf("CompileConfig rejected class inherited from applied group: %v", err)
		}
	})
	// A user with no class leaf is untouched by the gate.
	t.Run("no class", func(t *testing.T) {
		tree := buildTree4303(t, []string{
			"set system login user bob uid 2001",
		})
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("CompileConfig rejected classless user: %v", err)
		}
	})
}

// Case C: a group carrying TWO sibling `system` blocks, the class in the
// second. collectSchemaRefs used singular FindChild("system") and missed
// it, falsely rejecting the reference at schema-validate time. RED on
// pre-fix code (loginClasses was empty).
func TestCollectSchemaRefsSecondSystemBlock15717(t *testing.T) {
	src := `groups {
    g1 {
        system {
            host-name fw1;
        }
        system {
            login {
                class second-sys-class {
                    permissions [ view ];
                }
            }
        }
    }
}
apply-groups g1;
system {
    login {
        user carol {
            class second-sys-class;
        }
    }
}
`
	tree := parseHierText(t, src)
	if _, ok := collectSchemaRefs(tree).loginClasses["second-sys-class"]; !ok {
		t.Fatalf("collectSchemaRefs missed class in second sibling system block of group g1")
	}
	// And the full compile of the applied-group config is accepted.
	if _, err := CompileConfig(parseHierText(t, src)); err != nil {
		t.Fatalf("CompileConfig rejected second-system-block class: %v", err)
	}
}

// Sibling class-of-service blocks: same singular-FindChild defect on the
// forwarding-class leg.
func TestCollectSchemaRefsSecondCoSBlock15717(t *testing.T) {
	src := `groups {
    g1 {
        class-of-service {
            forwarding-classes {
                queue 0 first-fc;
            }
        }
        class-of-service {
            forwarding-classes {
                queue 1 second-fc;
            }
        }
    }
}
`
	tree := parseHierText(t, src)
	refs := collectSchemaRefs(tree)
	if _, ok := refs.forwardingClasses["first-fc"]; !ok {
		t.Fatalf("collectSchemaRefs missed first-fc")
	}
	if _, ok := refs.forwardingClasses["second-fc"]; !ok {
		t.Fatalf("collectSchemaRefs missed forwarding class in second sibling class-of-service block")
	}
}
