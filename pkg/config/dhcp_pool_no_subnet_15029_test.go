package config

import (
	"strings"
	"testing"
)

// #15029 (A17-02, residual of #14601): a DHCP pool with NO subnet committed
// clean and rendered "subnet": "" into the Kea file. Kea refuses an empty
// subnet, so the whole file is rejected and every pool of the family stops —
// while the #14601 "control: pool with dns-server only (no subnet) commits"
// case pinned the hole as legitimate. Strict commit must refuse the empty
// subnet naming the pool; the tolerant path keeps warning (#1960); a pool
// WITH a subnet (C0) still commits.

func TestDHCPPoolNoSubnetRefusedAtCommit15029(t *testing.T) {
	const v4, v6 = "dhcp-local-server", "dhcpv6-local-server"
	cases := []struct {
		name  string
		lines []string
		want  []string // nil = must commit (C0 control)
	}{
		{
			name:  "C0 control: valid v4 pool with subnet commits",
			lines: dhcpPool14601(v4, "g1", "p1", "10.0.61.0/24", "10.0.61.100", "10.0.61.199", "10.0.61.1", "10.0.61.53"),
		},
		{
			name:  "C0 control: valid v6 pool with subnet commits",
			lines: dhcpPool14601(v6, "g6", "p6", "2001:db8:61::/64", "2001:db8:61::100", "2001:db8:61::199", "", "2001:db8:61::53"),
		},
		{
			name:  "C3 v4 pool with dns-server only (no subnet) refused",
			lines: dhcpPool14601(v4, "g1", "p1", "", "", "", "", "10.0.61.53"),
			want:  []string{v4, `group "g1" pool "p1"`, "subnet"},
		},
		{
			name:  "C3 v4 pool with range only (no subnet) refused",
			lines: dhcpPool14601(v4, "g1", "p1", "", "10.0.61.100", "10.0.61.199", "", ""),
			want:  []string{v4, `group "g1" pool "p1"`, "subnet"},
		},
		{
			name:  "C4 v6 pool with dns-server only (no subnet) refused",
			lines: dhcpPool14601(v6, "g6", "p6", "", "", "", "", "2001:db8:61::53"),
			want:  []string{v6, `group "g6" pool "p6"`, "subnet"},
		},
		{
			name:  "C4 v6 pool with range only (no subnet) refused",
			lines: dhcpPool14601(v6, "g6", "p6", "", "2001:db8:61::100", "2001:db8:61::199", "", ""),
			want:  []string{v6, `group "g6" pool "p6"`, "subnet"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(dupSubnetTree9785(t, tc.lines...))
			if tc.want == nil {
				if err != nil {
					t.Fatalf("CONTROL BROKE: want the config to commit, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("want the subnet-less pool refused at commit, got a clean compile (would render \"subnet\": \"\" and Kea would refuse the whole file)")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("refusal %q does not contain %q", err, w)
				}
			}
		})
	}
}

// The tolerant load / peer-sync paths must warn and keep the pool so a
// persisted config still boots (#1960), while the strict path refuses.
func TestDHCPPoolNoSubnetLenientGate15029(t *testing.T) {
	lines := dhcpPool14601("dhcp-local-server", "g1", "p1", "", "", "", "", "10.0.61.53")
	if _, err := CompileConfig(dupSubnetTree9785(t, lines...)); err == nil {
		t.Fatal("CompileConfig: want the subnet-less pool refused, got a clean compile")
	}
	const warn = "DHCP pool value (downgraded to warning on tolerant path)"
	cfg, err := CompileConfigLenient(dupSubnetTree9785(t, lines...))
	if err != nil {
		t.Fatalf("CompileConfigLenient: want a warning, not an error: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, warn) {
		t.Fatalf("CompileConfigLenient: want %q, got %+v", warn, cfg.Warnings)
	}
	if !strings.Contains(strings.Join(cfg.Warnings, " "), "subnet") {
		t.Fatalf("CompileConfigLenient: warning must name the subnet: %+v", cfg.Warnings)
	}
	cfgN, errN := CompileConfigForNodeLenient(dupSubnetTree9785(t, lines...), 0)
	if errN != nil {
		t.Fatalf("CompileConfigForNodeLenient: want a warning, not an error: %v", errN)
	}
	if !hasWarningContaining(cfgN.Warnings, warn) {
		t.Fatalf("CompileConfigForNodeLenient: want %q, got %+v", warn, cfgN.Warnings)
	}
}
