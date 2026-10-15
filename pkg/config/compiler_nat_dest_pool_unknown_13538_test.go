// #13538: destination-NAT pool compiler had no default arm, so unknown pool
// leaves were silently dropped (dstUnknown==[]) while source pools record
// them (#10291). Symmetric gate: strict rejects, tolerant warns and keeps pool.
// Also: deterministic validation ran inside compileNAT (no opts), so the
// tolerant path hard-failed a correctly modeled but incomplete deterministic
// pool; it is now a uniform gate downgraded to a warning on tolerant path.
package config

import (
	"strings"
	"testing"
)

func destPoolUnknown13538Tree(t *testing.T, leaf string) *ConfigTree {
	t.Helper()
	return buildTree(t, []string{
		"set security nat destination pool P1 address 10.1.0.1",
		"set security nat destination pool P1 " + leaf,
	})
}

func TestDestNATPoolUnsupportedLeavesRejected13538(t *testing.T) {
	cases := []struct{ name, leaf, token string }{
		{"overflow-pool", "overflow-pool interface", "overflow-pool"},
		{"typo", "adress 10.2.0.1", "adress"},
		{"persistent-nat", "persistent-nat permit target-host", "persistent-nat"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := destPoolUnknown13538Tree(t, tc.leaf)
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("unsupported dest-pool leaf %q committed cleanly", tc.token)
			} else if !strings.Contains(err.Error(), tc.token) || !strings.Contains(err.Error(), "#13538") {
				t.Fatalf("strict error = %q, want token %q and #13538", err, tc.token)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("tolerant compile rejected unsupported leaf %q: %v", tc.token, err)
			}
			w := strings.Join(cfg.Warnings, "\n")
			if !strings.Contains(w, tc.token) || !strings.Contains(w, "#13538") {
				t.Fatalf("tolerant warnings = %q, want token %q and #13538", w, tc.token)
			}
			if pool := cfg.Security.NAT.Destination.Pools["P1"]; pool == nil {
				t.Fatal("tolerant compile dropped dest pool P1")
			}
		})
	}
}

func TestDestNATPoolSupportedLeavesCompileUnchanged13538(t *testing.T) {
	tree := buildTree(t, []string{
		"set security nat destination pool P1 address 10.1.0.1",
		"set security nat destination pool P1 routing-instance RI",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("modeled dest-pool leaves must still compile: %v", err)
	}
	pool := cfg.Security.NAT.Destination.Pools["P1"]
	if pool == nil || pool.Address != "10.1.0.1" || pool.RoutingInstance != "RI" || len(pool.UnknownLeaves) != 0 {
		t.Fatalf("dest pool = %+v, want address/RI preserved, no unknown leaves", pool)
	}
}

func TestDeterministicPoolIncompleteTolerant13538(t *testing.T) {
	lines := []string{
		"set security nat source pool CGNAT-POOL address 203.0.113.1/32 to 203.0.113.4/32",
		"set security nat source pool CGNAT-POOL port deterministic host address 100.64.0.0/25",
		"set security nat source pool CGNAT-POOL port range low 1024 high 65535",
	}
	// Strict still hard-fails (missing block-size).
	if _, err := CompileConfig(buildTree(t, lines)); err == nil || !strings.Contains(err.Error(), "block-size") {
		t.Fatalf("strict must reject incomplete deterministic pool, got %v", err)
	}
	// Tolerant warns and keeps pool (modeled but incomplete -> falls back non-det).
	cfg, err := CompileConfigLenient(buildTree(t, lines))
	if err != nil {
		t.Fatalf("tolerant compile hard-failed incomplete deterministic pool: %v", err)
	}
	if !strings.Contains(strings.Join(cfg.Warnings, "\n"), "block-size") {
		t.Fatalf("tolerant warnings = %v, want block-size warning", cfg.Warnings)
	}
	if pool := cfg.Security.NAT.SourcePools["CGNAT-POOL"]; pool == nil {
		t.Fatal("tolerant compile dropped pool")
	}
	// Complete pool strict-clean and deterministic preserved; tolerant no det warning.
	complete := append([]string{}, lines...)
	complete = append(complete, "set security nat source pool CGNAT-POOL port deterministic block-size 2016")
	cfg2, err := CompileConfig(buildTree(t, complete))
	if err != nil {
		t.Fatalf("complete deterministic pool must compile: %v", err)
	}
	if det := cfg2.Security.NAT.SourcePools["CGNAT-POOL"].Deterministic; det == nil || det.BlockSize != 2016 || det.HostAddress != "100.64.0.0/25" {
		t.Fatalf("deterministic = %+v, want 2016/100.64.0.0/25", det)
	}
}

func TestDeterministicValidationSortedFirst13538(t *testing.T) {
	lines := []string{
		"set security nat source pool ZZZ address 203.0.113.1/32",
		"set security nat source pool ZZZ port deterministic host address 100.64.0.0/25",
		"set security nat source pool AAA address 203.0.113.5/32",
		"set security nat source pool AAA port deterministic host address 100.64.0.0/25",
	}
	for range 5 {
		_, err := CompileConfig(buildTree(t, lines))
		if err == nil || !strings.Contains(err.Error(), `"AAA"`) {
			t.Fatalf("error = %v, want first sorted pool AAA", err)
		}
	}
}
