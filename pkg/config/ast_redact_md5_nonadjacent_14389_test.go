package config

import (
	"strings"
	"testing"
)

// #14389 (DR6-H5): the AST redactor's `key` gate used an exact-position
// window (authentication at i-3, md5 at i-2), so the hierarchical spelling
// `md5 1 2 { key SECRET; }` — flattened [..., authentication, md5, 1, 2,
// key, SECRET] — leaked the live OSPF MD5 key on every redacted display
// surface, while the compiler still installs it (key-id stays 1).
const md5NonAdjacentSecret14389 = "LIVE-OSPF-MD5-SECRET-14389"

func parseMD5Tree14389(t *testing.T, text string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(text).Parse()
	if len(errs) != 0 {
		t.Fatalf("NewParser: %v", errs)
	}
	return tree
}

func hierarchicalMD5Tree14389(t *testing.T, secret string) *ConfigTree {
	t.Helper()
	return parseMD5Tree14389(t, `protocols {
    ospf {
        area 0.0.0.0 {
            interface ge-0/0/0 {
                authentication {
                    md5 1 2 {
                        key "`+secret+`";
                    }
                }
            }
        }
    }
}`)
}

// The hierarchical non-adjacent spelling must be masked on Format,
// FormatSet and FormatCompareRedacted, and the key must be live after
// compilation (key-id 1, AuthKey == secret) so the fixture cannot pass
// vacuously on a dead/dormant spelling.
func TestRedactedCloneMasksNonAdjacentMD5Key14389(t *testing.T) {
	tree := hierarchicalMD5Tree14389(t, md5NonAdjacentSecret14389)

	// Liveness premise: the compiler installs this key.
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig(hierarchical md5 1 2): %v", err)
	}
	if cfg == nil || cfg.Protocols.OSPF == nil {
		t.Fatalf("compiled config has no OSPF: %+v", cfg)
	}
	found := false
	for _, area := range cfg.Protocols.OSPF.Areas {
		for _, iface := range area.Interfaces {
			if iface.AuthType == "md5" && iface.AuthKeyID == 1 &&
				string(iface.AuthKey) == md5NonAdjacentSecret14389 {
				found = true
			}
			for _, k := range iface.AuthMD5Keys {
				if k.ID == 1 && string(k.Key) == md5NonAdjacentSecret14389 {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatalf("premise broken: hierarchical md5 1 2 key was not installed live (want AuthKeyID=1, AuthKey=%q): %+v",
			md5NonAdjacentSecret14389, cfg.Protocols.OSPF)
	}

	red := tree.RedactedClone()
	renders := map[string]string{
		"Format":    red.Format(),
		"FormatSet": red.FormatSet(),
	}
	for name, out := range renders {
		if strings.Contains(out, md5NonAdjacentSecret14389) {
			t.Errorf("%s leaked non-adjacent OSPF MD5 key in cleartext:\n%s", name, out)
		}
		if !strings.Contains(out, SecretDataPlaceholder) {
			t.Errorf("%s did not mask non-adjacent OSPF MD5 key with %s:\n%s", name, SecretDataPlaceholder, out)
		}
		if !strings.Contains(out, "md5 1 2") {
			t.Errorf("%s lost the non-secret `md5 1 2` prefix (over-masking):\n%s", name, out)
		}
	}

	const oldSecret = "OLD-OSPF-MD5-SECRET-14389"
	oldTree := hierarchicalMD5Tree14389(t, oldSecret)
	diff := FormatCompareRedacted(oldTree, tree)
	for _, secret := range []string{oldSecret, md5NonAdjacentSecret14389} {
		if strings.Contains(diff, secret) {
			t.Errorf("FormatCompareRedacted leaked secret %q:\n%s", secret, diff)
		}
	}
	if diff == "" || diff == "[no changes]\n" {
		t.Errorf("FormatCompareRedacted collapsed a secret-only change to no-changes:\n%q", diff)
	}
	if !strings.Contains(diff, SecretDataPlaceholder) {
		t.Errorf("FormatCompareRedacted did not emit the %s placeholder:\n%s", SecretDataPlaceholder, diff)
	}

	if out := tree.Format() + tree.FormatSet(); !strings.Contains(out, md5NonAdjacentSecret14389) {
		t.Errorf("RedactedClone mutated the source tree:\n%s", out)
	}
}

// Controls that must stay exactly as before: canonical adjacent spelling
// still masked, set-form dormant `md5 1 2 key` also masked, the already-
// covered `md5 1 key { key SECRET; }` still masked, and non-secret `key`
// values (GRE tunnel, NTP, api-auth identity, chassis device-map) visible.
func TestRedactedCloneMD5KeyControls14389(t *testing.T) {
	t.Run("canonical md5 1 key still masked", func(t *testing.T) {
		tree := parseMD5Tree14389(t, `protocols {
    ospf {
        area 0.0.0.0 {
            interface ge-0/0/0 {
                authentication {
                    md5 1 {
                        key "`+md5NonAdjacentSecret14389+`";
                    }
                }
            }
        }
    }
}`)
		out := tree.RedactedClone().Format() + tree.RedactedClone().FormatSet()
		if strings.Contains(out, md5NonAdjacentSecret14389) {
			t.Errorf("canonical md5 1 key leaked:\n%s", out)
		}
		if !strings.Contains(out, SecretDataPlaceholder) {
			t.Errorf("canonical md5 1 key not masked:\n%s", out)
		}
	})

	t.Run("md5 1 key with nested key still masked", func(t *testing.T) {
		tree := parseMD5Tree14389(t, `protocols {
    ospf {
        area 0.0.0.0 {
            interface ge-0/0/0 {
                authentication md5 1 key {
                    key "`+md5NonAdjacentSecret14389+`";
                }
            }
        }
    }
}`)
		out := tree.RedactedClone().Format() + tree.RedactedClone().FormatSet()
		if strings.Contains(out, md5NonAdjacentSecret14389) {
			t.Errorf("md5 1 key { key ... } leaked:\n%s", out)
		}
	})

	t.Run("set-form dormant md5 1 2 key also masked", func(t *testing.T) {
		tree := buildRedactTree(t, []string{
			"set protocols ospf area 0.0.0.0 interface ge-0/0/0 authentication md5 1 2 key " + md5NonAdjacentSecret14389,
		})
		out := tree.RedactedClone().FormatSet() + tree.RedactedClone().Format()
		if strings.Contains(out, md5NonAdjacentSecret14389) {
			t.Errorf("set-form md5 1 2 key leaked:\n%s", out)
		}
		if !strings.Contains(out, SecretDataPlaceholder) {
			t.Errorf("set-form md5 1 2 key not masked:\n%s", out)
		}
	})

	t.Run("non-secret key values stay visible", func(t *testing.T) {
		tree := buildRedactTree(t, []string{
			"set interfaces gr-0/0/0 unit 0 tunnel key 100",
			"set system ntp server 192.0.2.1 key 42",
			"set system services web-management api-auth key automation secret LEAK-API-NAMED-KEY-SECRET-14389",
		})
		out := tree.RedactedClone().FormatSet()
		for _, want := range []string{"100", "42", "automation"} {
			if !strings.Contains(out, want) {
				t.Errorf("non-secret key value %q was masked (over-redaction):\n%s", want, out)
			}
		}
		if strings.Contains(out, "LEAK-API-NAMED-KEY-SECRET-14389") {
			t.Errorf("api-auth named-key secret leaked:\n%s", out)
		}
	})
}

// The ingest guard shares secretIndices with the masker, so a redacted
// export of the non-adjacent spelling must now be rejected instead of
// silently committing the placeholder as the literal MD5 key.
func TestRedactionPlaceholderIngestNonAdjacentMD5Key14389(t *testing.T) {
	redacted := hierarchicalMD5Tree14389(t, md5NonAdjacentSecret14389).RedactedClone()
	if !strings.Contains(redacted.FormatSet(), SecretDataPlaceholder) {
		t.Fatalf("premise broken: redacted export carries no placeholder:\n%s", redacted.FormatSet())
	}
	if err := checkRedactionPlaceholder(redacted); err == nil {
		t.Fatalf("guard missed the redacted non-adjacent MD5 key:\n%s", redacted.FormatSet())
	}
	if err := checkRedactionPlaceholder(hierarchicalMD5Tree14389(t, md5NonAdjacentSecret14389)); err != nil {
		t.Fatalf("guard rejected a real cleartext MD5 key: %v", err)
	}
}
