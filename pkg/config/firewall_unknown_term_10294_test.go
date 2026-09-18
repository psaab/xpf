package config

import (
	"strings"
	"testing"
)

func TestFirewallTermUnknownChildRejected10294(t *testing.T) {
	flat := flatTreeFromSets(t,
		"set firewall family inet filter f1 term t1 from protocol tcp",
		"set firewall family inet filter f1 term t1 then accept",
		"set firewall family inet filter f1 term t1 foo bar",
	)
	_, err := CompileConfig(flat)
	if err == nil {
		t.Fatal("unknown TERM child committed cleanly and was dropped")
	}
	if !strings.Contains(err.Error(), "#10294") ||
		!strings.Contains(err.Error(), "foo") ||
		!strings.Contains(err.Error(), "term") {
		t.Fatalf("error = %q, want #10294 TERM diagnostic naming foo", err)
	}

	hier := hierTree(t, `firewall {
    family inet {
        filter f1 {
            term t1 {
                from { protocol tcp; }
                then { accept; }
                typo-term {
                    value;
                }
            }
        }
    }
}`)
	_, err = CompileConfig(hier)
	if err == nil {
		t.Fatal("hierarchical unknown TERM child committed cleanly and was dropped")
	}

	if !strings.Contains(err.Error(), "#10294") || !strings.Contains(err.Error(), "typo-term") {
		t.Fatalf("error = %q, want #10294 diagnostic naming typo-term", err)
	}
}
func TestFirewallTermPackedKnownChildStillCommits10294(t *testing.T) {
	tree := hierTree(t, `firewall {
    family inet {
        filter f1 {
            term t1 then discard;
        }
    }
}`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("packed `term t1 then discard` was rejected: %v", err)
	}
	term := cfg.Firewall.FiltersInet["f1"].Terms[0]
	if len(term.unknownChildren) != 0 {
		t.Fatalf("packed known term tail recorded as unknown: %v", term.unknownChildren)
	}
	if term.Action != "discard" {
		t.Fatalf("packed known term tail lost action: %q", term.Action)
	}
}

func TestFirewallTermUnknownChildLenientWarns10294(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set firewall family inet filter f1 term t1 from protocol tcp",
		"set firewall family inet filter f1 term t1 then accept",
		"set firewall family inet filter f1 term t1 foo bar",
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must boot: %v", err)
	}
	term := cfg.Firewall.FiltersInet["f1"].Terms[0]
	if len(term.unknownChildren) != 1 || term.unknownChildren[0] != "foo" {
		t.Fatalf("unknownChildren = %v, want [foo]", term.unknownChildren)
	}
	warnings := strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(warnings, "#10294") || !strings.Contains(warnings, "foo") {
		t.Fatalf("warnings = %q, want #10294 naming foo", warnings)
	}
}

func sourceNATUnknownLines10294(action []string) []string {
	lines := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/8",
	}
	return append(lines, action...)
}

func TestSourceNATThenUnknownChildRejected10294(t *testing.T) {
	flat := flatTreeFromSets(t, sourceNATUnknownLines10294([]string{
		"set security nat source rule-set rs1 rule r1 then source-nat interface",
		"set security nat source rule-set rs1 rule r1 then source-nat typo",
	})...)
	_, err := CompileConfig(flat)
	if err == nil {
		t.Fatal("unknown source-NAT action committed cleanly and was dropped")
	}
	if !strings.Contains(err.Error(), "#10294") ||
		!strings.Contains(err.Error(), "typo") ||
		!strings.Contains(err.Error(), "source-nat") {
		t.Fatalf("error = %q, want #10294 source-nat diagnostic naming typo", err)
	}

	hier := hierTree(t, `security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    nat {
        source {
            rule-set rs1 {
                from { zone trust; }
                to { zone untrust; }
                rule r1 {
                    match { source-address 10.0.0.0/8; }
                    then {
                        source-nat {
                            interface;
                            typo-action;
                        }
                    }
                }
            }
        }
    }
}`)
	_, err = CompileConfig(hier)
	if err == nil {
		t.Fatal("hierarchical unknown source-NAT child committed cleanly")
	}
	if !strings.Contains(err.Error(), "#10294") || !strings.Contains(err.Error(), "typo-action") {
		t.Fatalf("error = %q, want #10294 diagnostic naming typo-action", err)
	}
}

func TestSourceNATUnknownContainerWithValidModeRejected10294(t *testing.T) {
	hier := hierTree(t, `security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    nat {
        source {
            rule-set rs1 {
                from { zone trust; }
                to { zone untrust; }
                rule r1 {
                    match { source-address 10.0.0.0/8; }
                    then {
                        source-nat {
                            interface;
                            frobnicate { off; }
                        }
                    }
                }
            }
        }
    }
}`)
	_, err := CompileConfig(hier)
	if err == nil {
		t.Fatal("unknown source-NAT container committed cleanly")
	}
	if !strings.Contains(err.Error(), "#10294") ||
		!strings.Contains(err.Error(), "frobnicate") {
		t.Fatalf("error = %q, want #10294 diagnostic naming frobnicate", err)
	}
}

func TestSourceNATThenUnknownChildLenientWarns10294(t *testing.T) {
	tree := flatTreeFromSets(t, sourceNATUnknownLines10294([]string{
		"set security nat source rule-set rs1 rule r1 then source-nat interface",
		"set security nat source rule-set rs1 rule r1 then source-nat typo",
	})...)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient source-NAT compile must boot: %v", err)
	}
	r := sourceRule9877(t, cfg, "rs1", "r1")
	if len(r.unknownThenLeaves) != 1 || r.unknownThenLeaves[0] != "typo" {
		t.Fatalf("unknownThenLeaves = %v, want [typo]", r.unknownThenLeaves)
	}
	warnings := strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(warnings, "#10294") || !strings.Contains(warnings, "typo") {
		t.Fatalf("warnings = %q, want #10294 naming typo", warnings)
	}
}

func TestSourceNATPersistentTailStillCommits10294(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security nat source pool p1 address 198.51.100.1/32",
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set rs1 rule r1 then source-nat pool p1 persistent-nat permit target-host-port",
	)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("valid #10078 persistent-nat tail rejected by #10294: %v", err)
	}
}
func TestSourceNATKnownPackedModesStay7033Owned10294(t *testing.T) {
	for _, tc := range []struct {
		name    string
		action  string
		wantErr bool
	}{
		{name: "repeated off", action: "off off"},
		{name: "interface versus off", action: "interface off", wantErr: true},
		{name: "interface versus pool", action: "interface pool p1", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines := sourceNATUnknownLines10294([]string{
				"set security nat source pool p1 address 198.51.100.1/32",
				"set security nat source rule-set rs1 rule r1 then source-nat " + tc.action,
			})
			_, err := CompileConfig(flatTreeFromSets(t, lines...))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("known contradictory modes %q committed cleanly", tc.action)
				}
				if strings.Contains(err.Error(), "#10294") {
					t.Fatalf("known contradictory modes %q were misclassified as #10294: %v", tc.action, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("repeated known mode %q was rejected: %v", tc.action, err)
			}
		})
	}
}
