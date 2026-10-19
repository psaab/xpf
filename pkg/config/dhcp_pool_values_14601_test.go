package config

import (
	"strings"
	"testing"
)

// #14601: DHCP pool subnet, address-range, router and dns-server family were
// not validated at commit. The compiler copied the raw tokens and the Kea
// renderer emitted them verbatim, so one typo committed clean and Kea then
// refused the whole rendered config — every pool of that family stopped,
// healthy pools included (the #9785 mechanism through four more leaves).

// dhcpPool14601 returns the set lines declaring one fully-specified pool.
// Empty leaves are omitted so a case can leave a leaf unset.
func dhcpPool14601(server, group, pool, subnet, low, high, router string, dns ...string) []string {
	p := "set system services " + server + " group " + group
	lines := []string{p + " interface ge-0-0-1"}
	if subnet != "" {
		lines = append(lines, p+" pool "+pool+" subnet "+subnet)
	}
	if low != "" || high != "" {
		lines = append(lines, p+" pool "+pool+" address-range low "+low+" high "+high)
	}
	if router != "" {
		lines = append(lines, p+" pool "+pool+" router "+router)
	}
	for _, d := range dns {
		lines = append(lines, p+" pool "+pool+" dns-server "+d)
	}
	return lines
}

func TestDHCPPoolValuesRefusedAtCommit14601(t *testing.T) {
	const v4, v6 = "dhcp-local-server", "dhcpv6-local-server"
	cases := []struct {
		name  string
		lines []string
		want  []string // substrings of the refusal; nil means the config must commit
	}{
		// Controls.
		{
			name:  "control: valid v4 pool commits",
			lines: dhcpPool14601(v4, "g1", "p1", "10.0.61.0/24", "10.0.61.100", "10.0.61.199", "10.0.61.1", "10.0.61.53", "10.0.61.54"),
		},
		{
			name:  "control: valid v6 pool commits",
			lines: dhcpPool14601(v6, "g6", "p6", "2001:db8:61::/64", "2001:db8:61::100", "2001:db8:61::199", "", "2001:db8:61::53", "2001:db8:61::54"),
		},
		{
			// Flipped by #15029: a subnet-less pool renders "subnet": ""
			// and Kea refuses the whole file; it is no longer a control.
			// Exercised in dhcp_pool_no_subnet_15029_test.go (C3/C4).
			name:  "pool with dns-server only (no subnet) refused (#15029)",
			lines: dhcpPool14601(v4, "g1", "p1", "", "", "", "", "10.0.61.53"),
			want:  []string{v4, `group "g1" pool "p1"`, "subnet"},
		},
		{
			name:  "control: pool with subnet only (no range) commits",
			lines: dhcpPool14601(v4, "g1", "p1", "10.0.61.0/24", "", "", "", ""),
		},
		// Subnet.
		{
			name:  "v4 subnet without prefix length",
			lines: dhcpPool14601(v4, "g1", "p1", "10.0.61.0", "10.0.61.100", "10.0.61.199", "", ""),
			want:  []string{v4, `group "g1" pool "p1"`, "subnet", `"10.0.61.0"`},
		},
		{
			name:  "v6 subnet without prefix length",
			lines: dhcpPool14601(v6, "g6", "p6", "2001:db8:61::", "2001:db8:61::100", "2001:db8:61::199", "", ""),
			want:  []string{v6, "subnet", `"2001:db8:61::"`},
		},
		{
			name:  "v4 subnet is a v6 prefix",
			lines: dhcpPool14601(v4, "g1", "p1", "2001:db8:61::/64", "10.0.61.100", "10.0.61.199", "", ""),
			want:  []string{v4, "subnet", `"2001:db8:61::/64"`, "IPv4"},
		},
		{
			name:  "v6 subnet is a v4 prefix",
			lines: dhcpPool14601(v6, "g6", "p6", "10.0.61.0/24", "2001:db8:61::100", "2001:db8:61::199", "", ""),
			want:  []string{v6, "subnet", `"10.0.61.0/24"`, "IPv6"},
		},
		{
			name:  "v4 subnet unparseable",
			lines: dhcpPool14601(v4, "g1", "p1", "bogus", "10.0.61.100", "10.0.61.199", "", ""),
			want:  []string{"subnet", `"bogus"`},
		},
		// Address range.
		{
			name:  "v4 range outside subnet",
			lines: dhcpPool14601(v4, "g1", "p1", "10.0.61.0/24", "10.0.99.100", "10.0.99.199", "", ""),
			want:  []string{"address-range low", `"10.0.99.100"`, "outside", "10.0.61.0/24"},
		},
		{
			name:  "v4 range high outside subnet",
			lines: dhcpPool14601(v4, "g1", "p1", "10.0.61.0/24", "10.0.61.100", "10.0.99.199", "", ""),
			want:  []string{"address-range high", `"10.0.99.199"`, "outside"},
		},
		{
			name:  "v6 range outside subnet",
			lines: dhcpPool14601(v6, "g6", "p6", "2001:db8:61::/64", "2001:db8:99::100", "2001:db8:99::199", "", ""),
			want:  []string{"address-range low", "outside", "2001:db8:61::/64"},
		},
		{
			name:  "v4 range low greater than high",
			lines: dhcpPool14601(v4, "g1", "p1", "10.0.61.0/24", "10.0.61.199", "10.0.61.100", "", ""),
			want:  []string{"address-range low", `"10.0.61.199"`, "address-range high", `"10.0.61.100"`},
		},
		{
			name:  "v6 range low greater than high",
			lines: dhcpPool14601(v6, "g6", "p6", "2001:db8:61::/64", "2001:db8:61::199", "2001:db8:61::100", "", ""),
			want:  []string{"address-range low", "address-range high"},
		},
		{
			name:  "v4 range low unparseable",
			lines: dhcpPool14601(v4, "g1", "p1", "10.0.61.0/24", "bogus", "10.0.61.199", "", ""),
			want:  []string{"address-range low", `"bogus"`},
		},
		{
			name:  "v4 range is v6",
			lines: dhcpPool14601(v4, "g1", "p1", "10.0.61.0/24", "2001:db8::100", "2001:db8::199", "", ""),
			want:  []string{"address-range low", `"2001:db8::100"`, "IPv4"},
		},
		{
			name:  "v6 range is v4",
			lines: dhcpPool14601(v6, "g6", "p6", "2001:db8:61::/64", "10.0.61.100", "10.0.61.199", "", ""),
			want:  []string{"address-range low", `"10.0.61.100"`, "IPv6"},
		},
		// Router (v4 only: the v6 renderer emits no routers option).
		{
			name:  "v4 router is v6",
			lines: dhcpPool14601(v4, "g1", "p1", "10.0.61.0/24", "10.0.61.100", "10.0.61.199", "2001:db8::1"),
			want:  []string{"router", `"2001:db8::1"`, "IPv4"},
		},
		{
			name:  "v4 router unparseable",
			lines: dhcpPool14601(v4, "g1", "p1", "10.0.61.0/24", "10.0.61.100", "10.0.61.199", "bogus"),
			want:  []string{"router", `"bogus"`},
		},
		// DNS servers (every element, both families).
		{
			name:  "v4 dns-server is v6",
			lines: dhcpPool14601(v4, "g1", "p1", "10.0.61.0/24", "10.0.61.100", "10.0.61.199", "", "2001:db8::53"),
			want:  []string{"dns-server", `"2001:db8::53"`, "IPv4"},
		},
		{
			name:  "v4 second dns-server is v6",
			lines: dhcpPool14601(v4, "g1", "p1", "10.0.61.0/24", "10.0.61.100", "10.0.61.199", "", "10.0.61.53", "2001:db8::53"),
			want:  []string{"dns-server", `"2001:db8::53"`},
		},
		{
			name:  "v6 dns-server is v4",
			lines: dhcpPool14601(v6, "g6", "p6", "2001:db8:61::/64", "2001:db8:61::100", "2001:db8:61::199", "", "192.0.2.53"),
			want:  []string{"dns-server", `"192.0.2.53"`, "IPv6"},
		},
		{
			name:  "v6 second dns-server is v4",
			lines: dhcpPool14601(v6, "g6", "p6", "2001:db8:61::/64", "2001:db8:61::100", "2001:db8:61::199", "", "2001:db8:61::53", "192.0.2.53"),
			want:  []string{"dns-server", `"192.0.2.53"`},
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
				t.Fatal("want the bad pool value refused at commit, got a clean compile")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("refusal %q does not contain %q", err, w)
				}
			}
		})
	}
}

// TestDHCPPoolValuesLenientGate14601 binds the tolerant side: load and
// peer-sync must warn and keep the pool so a persisted config still boots
// (#1960), while the strict path refuses the same lines.
func TestDHCPPoolValuesLenientGate14601(t *testing.T) {
	lines := dhcpPool14601("dhcp-local-server", "g1", "p1", "10.0.61.0/24", "10.0.99.100", "10.0.99.50", "2001:db8::1", "2001:db8::53")
	if _, err := CompileConfig(dupSubnetTree9785(t, lines...)); err == nil {
		t.Fatal("CompileConfig: want the out-of-subnet range refused, got a clean compile")
	}
	const warn = "DHCP pool value (downgraded to warning on tolerant path)"
	cfg, err := CompileConfigLenient(dupSubnetTree9785(t, lines...))
	if err != nil {
		t.Fatalf("CompileConfigLenient: want a warning, not an error: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, warn) {
		t.Fatalf("CompileConfigLenient: want %q, got %+v", warn, cfg.Warnings)
	}
	cfgN, errN := CompileConfigForNodeLenient(dupSubnetTree9785(t, lines...), 0)
	if errN != nil {
		t.Fatalf("CompileConfigForNodeLenient: want a warning, not an error: %v", errN)
	}
	if !hasWarningContaining(cfgN.Warnings, warn) {
		t.Fatalf("CompileConfigForNodeLenient: want %q, got %+v", warn, cfgN.Warnings)
	}
}
