package config

import (
	"strings"
	"testing"
)

// #14626: rule-level `then source-nat pool P persistent-nat ...` used to pass
// strict commit while doing nothing — recordSourceNATUnknownThen returned on
// `pool <name>` and skipped the tail, and the pool parser (the only writer of
// PersistentNAT) never saw it. The snapshot therefore carried
// persistent_nat=false with no warning. These tests pin the fix: the tail is
// compiled per-rule (conflicting tails reject), or rejected at strict commit.
// RED on revert: the effective-config assertions fail (PersistentNAT stays
// nil) and the conflict/invalid rows commit cleanly.

func rulePNATLines14626(poolExtra []string, thenAction string) []string {
	lines := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security nat source pool p1 address 198.51.100.1/32",
	}
	lines = append(lines, poolExtra...)
	lines = append(lines,
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set rs1 rule r1 then "+thenAction,
	)
	return lines
}

func rulePNATRule14626(t *testing.T, cfg *Config) *NATRule {
	t.Helper()
	for _, rs := range cfg.Security.NAT.Source {
		for _, r := range rs.Rules {
			if r.Name == "r1" {
				return r
			}
		}
	}
	t.Fatalf("rule r1 not found in %+v", cfg.Security.NAT.Source)
	return nil
}

// permit/timeout authored only at rule level must take effect.
func TestRuleLevelPersistentNATCompiles14626(t *testing.T) {
	for _, tc := range []struct {
		name       string
		thenAction string
		wantPermit PersistentNATPermit
		wantTO     int
	}{
		{"permit-only", "source-nat pool p1 persistent-nat permit any-remote-host", PersistentNATPermitAnyRemoteHost, 300},
		{"timeout-only", "source-nat pool p1 persistent-nat inactivity-timeout 900", PersistentNATPermitTargetHostPort, 900},
		{"both", "source-nat pool p1 persistent-nat permit target-host inactivity-timeout 600", PersistentNATPermitTargetHost, 600},
		{"bare-persistent-nat", "source-nat pool p1 persistent-nat", PersistentNATPermitTargetHostPort, 300},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(buildTree(t, rulePNATLines14626(nil, tc.thenAction)))
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			r := rulePNATRule14626(t, cfg)
			eff, ok := r.EffectivePersistentNAT(cfg)
			if !ok || eff == nil {
				t.Fatalf("rule-level persistent-nat did not compile: effective=%v ok=%v warnings=%v", eff, ok, cfg.Warnings)
			}
			if eff.Permit != tc.wantPermit || eff.InactivityTimeout != tc.wantTO {
				t.Fatalf("effective = %+v, want permit=%q timeout=%d", eff, tc.wantPermit, tc.wantTO)
			}
			if pool := cfg.Security.NAT.SourcePools["p1"]; pool.PersistentNAT != nil {
				t.Fatalf("pool PersistentNAT mutated to %+v; rule-level tail must stay per-rule", pool.PersistentNAT)
			}
		})
	}
}

// Hierarchical spellings must compile identically.
func TestRuleLevelPersistentNATHierarchical14626(t *testing.T) {
	txt := `security {
    zones { security-zone trust; security-zone untrust; }
    nat { source {
        pool p1 { address 198.51.100.1/32; }
        rule-set rs1 {
            from { zone trust; }
            to { zone untrust; }
            rule r1 {
                match { source-address 10.0.0.0/8; }
                then { source-nat { pool P; persistent-nat { permit any-remote-host; inactivity-timeout 900; } } }
            }
        }
    } }
}`
	// pool name in hier fixture is P; use p1 spelling instead for consistency:
	txt = strings.ReplaceAll(txt, "pool P;", "pool p1;")
	tree, perr := NewParser(txt).Parse()
	if len(perr) != 0 {
		t.Fatalf("parse: %v", perr)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig(hier): %v", err)
	}
	r := rulePNATRule14626(t, cfg)
	eff, ok := r.EffectivePersistentNAT(cfg)
	if !ok || eff.Permit != PersistentNATPermitAnyRemoteHost || eff.InactivityTimeout != 900 {
		t.Fatalf("hier effective = %+v ok=%v, want any-remote-host/900", eff, ok)
	}

	// Pool-nested spelling: pool { p1; persistent-nat { ... } }
	txt2 := `security {
    zones { security-zone trust; security-zone untrust; }
    nat { source {
        pool p1 { address 198.51.100.1/32; }
        rule-set rs1 {
            from { zone trust; }
            to { zone untrust; }
            rule r1 {
                match { source-address 10.0.0.0/8; }
                then { source-nat { pool { p1; persistent-nat { permit target-host; } } } }
            }
        }
    } }
}`
	tree2, perr2 := NewParser(txt2).Parse()
	if len(perr2) != 0 {
		t.Fatalf("parse2: %v", perr2)
	}
	cfg2, err := CompileConfig(tree2)
	if err != nil {
		t.Fatalf("CompileConfig(hier pool-nested): %v", err)
	}
	r2 := rulePNATRule14626(t, cfg2)
	eff2, ok2 := r2.EffectivePersistentNAT(cfg2)
	if !ok2 || eff2.Permit != PersistentNATPermitTargetHost || eff2.InactivityTimeout != 300 {
		t.Fatalf("pool-nested effective = %+v ok=%v, want target-host/300", eff2, ok2)
	}
}

// Pool-level control must stay unchanged, and a rule tail that AGREES with
// the pool definition commits.
func TestRuleLevelPersistentNATPoolControl14626(t *testing.T) {
	poolExtra := []string{"set security nat source pool p1 persistent-nat permit any-remote-host inactivity-timeout 300"}
	// Control: no rule tail.
	cfg, err := CompileConfig(buildTree(t, rulePNATLines14626(poolExtra, "source-nat pool p1")))
	if err != nil {
		t.Fatalf("control CompileConfig: %v", err)
	}
	pool := cfg.Security.NAT.SourcePools["p1"]
	if pool.PersistentNAT == nil || pool.PersistentNAT.Permit != PersistentNATPermitAnyRemoteHost || pool.PersistentNAT.InactivityTimeout != 300 {
		t.Fatalf("pool control changed: %+v", pool.PersistentNAT)
	}
	r := rulePNATRule14626(t, cfg)
	eff, ok := r.EffectivePersistentNAT(cfg)
	if !ok || eff.Permit != PersistentNATPermitAnyRemoteHost || eff.InactivityTimeout != 300 {
		t.Fatalf("control effective = %+v ok=%v", eff, ok)
	}
	// Agreeing tail.
	cfg2, err := CompileConfig(buildTree(t, rulePNATLines14626(poolExtra,
		"source-nat pool p1 persistent-nat permit any-remote-host")))
	if err != nil {
		t.Fatalf("agreeing tail rejected: %v", err)
	}
	_ = cfg2
	// A second rule on a different pool sharing the same pool with the SAME tail commits.
	cfg3, err := CompileConfig(buildTree(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security nat source pool p1 address 198.51.100.1/32",
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set rs1 rule r1 then source-nat pool p1 persistent-nat permit any-remote-host",
		"set security nat source rule-set rs1 rule r2 match source-address 10.1.0.0/16",
		"set security nat source rule-set rs1 rule r2 then source-nat pool p1 persistent-nat permit any-remote-host",
	}))
	if err != nil {
		t.Fatalf("identical tails on shared pool rejected: %v", err)
	}
	_ = cfg3
}

// Disagreeing tails (vs pool, or rule-vs-rule on a shared pool) and malformed
// tails must reject at strict commit.
func TestRuleLevelPersistentNATConflictsRejected14626(t *testing.T) {
	poolExtra := []string{"set security nat source pool p1 persistent-nat permit any-remote-host"}
	for _, tc := range []struct {
		name       string
		poolExtra  []string
		thenAction string
		wantSub    string
	}{
		{"vs-pool-permit", poolExtra, "source-nat pool p1 persistent-nat permit target-host", "conflicts"},
		{"vs-pool-timeout", []string{"set security nat source pool p1 persistent-nat inactivity-timeout 300"}, "source-nat pool p1 persistent-nat inactivity-timeout 900", "conflicts"},
		{"bad-permit", nil, "source-nat pool p1 persistent-nat permit bogus", "persistent-nat"},
		{"bad-timeout-zero", nil, "source-nat pool p1 persistent-nat inactivity-timeout 0", "persistent-nat"},
		{"bad-timeout-alpha", nil, "source-nat pool p1 persistent-nat inactivity-timeout abc", "persistent-nat"},
		{"unknown-subkey", nil, "source-nat pool p1 persistent-nat frobnicate x", "persistent-nat"},
		{"interface-tail", nil, "source-nat interface persistent-nat permit any-remote-host", "persistent-nat"},
		{"deterministic-pool", []string{"set security nat source pool p1 port range low 1024 high 65535", "set security nat source pool p1 port deterministic block-size 2016", "set security nat source pool p1 port deterministic host address 100.64.0.0/27"}, "source-nat pool p1 persistent-nat permit any-remote-host", "deterministic"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree(t, rulePNATLines14626(tc.poolExtra, tc.thenAction)))
			if err == nil {
				t.Fatalf("%s committed cleanly, want strict reject", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error = %q, want substring %q", err, tc.wantSub)
			}
			if !strings.Contains(err.Error(), "#14626") {
				t.Fatalf("error = %q, want #14626 cite", err)
			}
		})
	}
	// Rule-vs-rule disagreement on a shared pool.
	_, err := CompileConfig(buildTree(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security nat source pool p1 address 198.51.100.1/32",
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set rs1 rule r1 then source-nat pool p1 persistent-nat permit any-remote-host",
		"set security nat source rule-set rs1 rule r2 match source-address 10.1.0.0/16",
		"set security nat source rule-set rs1 rule r2 then source-nat pool p1 persistent-nat permit target-host",
	}))
	if err == nil || !strings.Contains(err.Error(), "#14626") {
		t.Fatalf("rule-vs-rule conflict err = %v, want #14626 reject", err)
	}
}

// Tolerant path: a conflicting rule tail warns (#1960) and the snapshot-facing
// effective value falls back to the pool's own config (never the inert tail).
func TestRuleLevelPersistentNATLenient14626(t *testing.T) {
	poolExtra := []string{"set security nat source pool p1 persistent-nat permit any-remote-host"}
	cfg, err := CompileConfigLenient(buildTree(t, rulePNATLines14626(poolExtra,
		"source-nat pool p1 persistent-nat permit target-host")))
	if err != nil {
		t.Fatalf("lenient must boot: %v", err)
	}
	if !strings.Contains(strings.Join(cfg.Warnings, "\n"), "#14626") {
		t.Fatalf("warnings = %v, want #14626", cfg.Warnings)
	}
	r := rulePNATRule14626(t, cfg)
	eff, ok := r.EffectivePersistentNAT(cfg)
	if !ok || eff.Permit != PersistentNATPermitAnyRemoteHost {
		t.Fatalf("lenient effective = %+v ok=%v, want pool fallback any-remote-host", eff, ok)
	}
	// Malformed tail on lenient path: warn + no persistence (not silent).
	cfg2, err := CompileConfigLenient(buildTree(t, rulePNATLines14626(nil,
		"source-nat pool p1 persistent-nat permit bogus")))
	if err != nil {
		t.Fatalf("lenient malformed must boot: %v", err)
	}
	if !strings.Contains(strings.Join(cfg2.Warnings, "\n"), "#14626") {
		t.Fatalf("warnings2 = %v, want #14626", cfg2.Warnings)
	}
	r2 := rulePNATRule14626(t, cfg2)
	if eff2, ok2 := r2.EffectivePersistentNAT(cfg2); ok2 {
		t.Fatalf("malformed tail produced effective %+v, want none", eff2)
	}
}

// SchemaValidate must accept the modeled rule-level tail and reject bad values.
func TestRuleLevelPersistentNATSchema14626(t *testing.T) {
	good := buildTree(t, rulePNATLines14626(nil, "source-nat pool p1 persistent-nat permit any-remote-host"))
	if err := SchemaValidate(good, nil); err != nil {
		t.Fatalf("SchemaValidate(good rule tail) = %v", err)
	}
	bad := buildTree(t, rulePNATLines14626(nil, "source-nat pool p1 persistent-nat permit bogus"))
	if err := SchemaValidate(bad, nil); err == nil {
		t.Fatal("SchemaValidate(bad permit) = nil, want reject")
	} else if !strings.Contains(err.Error(), "bogus") && !strings.Contains(err.Error(), "permit") {
		t.Fatalf("SchemaValidate error = %q, want permit/bogus named", err)
	}
	badTO := buildTree(t, rulePNATLines14626(nil, "source-nat pool p1 persistent-nat inactivity-timeout 99999"))
	if err := SchemaValidate(badTO, nil); err == nil {
		t.Fatal("SchemaValidate(timeout 99999) = nil, want reject")
	}
}
