package config

import (
	"strings"
	"testing"
)

// #10289: a destination-NAT pool address is a single-host wire field. The
// parser must not collapse an address range or another multi-token address to
// its final token. Until destination-NAT ranges have wire support, strict
// validation must reject them with an operator-visible diagnostic, and the
// tolerant path must retain the exclusion so the snapshot builder fails closed.
func TestDNATPoolAddressRangeRejectedAtCommit10289(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want string
	}{
		{
			name: "range",
			cmd:  "set security nat destination pool p1 address 10.1.0.1 to 10.1.0.9",
			want: "address range",
		},
		{
			name: "bracket-list",
			cmd:  "set security nat destination pool p1 address [ 10.1.0.1 10.1.0.9 ]",
			want: "multi-address value",
		},
		{
			name: "unexpected-token",
			cmd:  "set security nat destination pool p1 address 10.1.0.1 bogus 10.1.0.9",
			want: "multi-address value",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := dnatPoolTree(t, tc.cmd)
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("CompileConfig accepted multi-token DNAT address %q", tc.cmd)
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("CompileConfig error %q does not name %s", err, tc.want)
			}

			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("CompileConfigLenient rejected %q: %v", tc.cmd, err)
			}
			if len(cfg.Warnings) == 0 || !strings.Contains(cfg.Warnings[0], tc.want) {
				t.Fatalf("CompileConfigLenient warnings = %v, want named %s diagnostic", cfg.Warnings, tc.want)
			}
			pool := cfg.Security.NAT.Destination.Pools["p1"]
			if pool.AddressInvalidSpec == "" {
				t.Fatalf("AddressInvalidSpec is empty for multi-token address %q", tc.cmd)
			}
			if pool.Address == "10.1.0.9" {
				t.Fatalf("pool.Address collapsed to final token for %q", tc.cmd)
			}
			rule := cfg.Security.NAT.Destination.RuleSets[0].Rules[0]
			if reason := DestinationNATRuleExcludedReason(cfg.Security.NAT.Destination, rule); !strings.Contains(reason, tc.want) {
				t.Fatalf("DestinationNATRuleExcludedReason = %q, want %s exclusion", reason, tc.want)
			}
		})
	}
}

// A single translated host remains valid and retains the existing preserve-port
// behavior. RED-on-revert: a parser that rejects every address or changes the
// host-only path breaks this case.
func TestDNATPoolSingleAddressStillCompiles10289(t *testing.T) {
	tree := dnatPoolTree(t, "set security nat destination pool p1 address 10.1.0.1")
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig rejected single-address DNAT pool: %v", err)
	}
	pool := cfg.Security.NAT.Destination.Pools["p1"]
	if pool.Address != "10.1.0.1" {
		t.Fatalf("pool.Address = %q, want 10.1.0.1", pool.Address)
	}
	if pool.Port != 0 || pool.PortRaw != "" {
		t.Fatalf("single-address pool port state = (%d, %q), want preserve-port default", pool.Port, pool.PortRaw)
	}
}

// A later single-address leaf replaces an earlier multi-token leaf. The
// replacement must clear the old marker; otherwise the effective valid host is
// rejected and the tolerant builder drops it.
func TestDNATPoolAddressOverrideClearsRangeMarker10289(t *testing.T) {
	tree := dnatPoolTree(t,
		"set security nat destination pool p1 address 10.1.0.1 to 10.1.0.9",
		"set security nat destination pool p1 address 10.2.0.1",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("range followed by a valid address must compile: %v", err)
	}
	pool := cfg.Security.NAT.Destination.Pools["p1"]
	if pool.Address != "10.2.0.1" || pool.AddressInvalidSpec != "" {
		t.Fatalf("effective pool = (%q, %q), want valid host with no stale marker",
			pool.Address, pool.AddressInvalidSpec)
	}

	// A port-only leaf carries no address information and must not clear an
	// earlier invalid address marker.
	tree = dnatPoolTree(t,
		"set security nat destination pool p1 address 10.1.0.1 to 10.1.0.9",
		"set security nat destination pool p1 address port 80",
	)
	if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "address range") {
		t.Fatalf("range followed by port-only address should retain rejection, got %v", err)
	}
}

// Repeated hierarchical pool blocks merge into one named pool. A later valid
// address must replace both the effective address and the earlier marker.
func TestDNATPoolRepeatedBlockMergeClearsRangeMarker10289(t *testing.T) {
	const cfgText = `
security {
    nat {
        destination {
            pool P1 {
                address 10.1.0.1 to 10.1.0.9;
            }
            pool P1 {
                address 10.2.0.1;
            }
        }
    }
}
`
	nat := natNodeFromText(t, cfgText)
	sec := &SecurityConfig{}
	if err := compileNAT(nat, sec); err != nil {
		t.Fatalf("compileNAT: %v", err)
	}
	pool := sec.NAT.Destination.Pools["P1"]
	if pool == nil {
		t.Fatal("merged destination pool P1 missing")
	}
	if pool.Address != "10.2.0.1" || pool.AddressInvalidSpec != "" {
		t.Fatalf("merged pool = (%q, %q), want valid host with no stale marker",
			pool.Address, pool.AddressInvalidSpec)
	}
}
