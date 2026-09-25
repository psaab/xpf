package config

import "testing"

// #7000: source-NAT pool capacity was re-derived per consumer as
// `len(pool.Addresses)`, which is wrong in THREE directions at once. These pin
// the single source all six operator surfaces now call.

func mkPool(t *testing.T, addr string, addrs ...string) *NATPool {
	t.Helper()
	return &NATPool{Address: addr, Addresses: addrs}
}

// Direction 2 + 3: a prefix member EXPANDS, and the singular `address` field
// counts. `len(pool.Addresses)` sees neither.
func TestSourceNATPoolReportableAddressesExpandsAndIncludesSingular7000(t *testing.T) {
	cases := []struct {
		name    string
		pool    *NATPool
		want    int
		wantLen int // what the old len(pool.Addresses) derivation produced
	}{
		{"single host", mkPool(t, "", "203.0.113.1"), 1, 1},
		{"host with /32", mkPool(t, "", "203.0.113.1/32"), 1, 1},
		{"a /24 expands to 256", mkPool(t, "", "203.0.113.0/24"), 256, 1},
		{"a /16 expands to 65536", mkPool(t, "", "10.0.0.0/16"), 65536, 1},
		{"two members sum", mkPool(t, "", "203.0.113.0/24", "198.51.100.1"), 257, 2},
		{"SINGULAR address only", mkPool(t, "203.0.113.7"), 1, 0},
		{"singular + list", mkPool(t, "203.0.113.7", "198.51.100.0/24"), 257, 1},
		{"v6 /128", mkPool(t, "", "2001:db8::1/128"), 1, 1},
		{"v6 /120 expands to 256", mkPool(t, "", "2001:db8::/120"), 256, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := SourceNATPoolReportableAddresses(tc.pool, "p", nil)
			if reason != "" {
				t.Fatalf("healthy pool reported unusable: %q", reason)
			}
			if got != tc.want {
				t.Fatalf("addresses = %d, want %d (the old len(pool.Addresses) "+
					"derivation gave %d — the dataplane installs %d, so every "+
					"capacity surface was off by that factor)", got, tc.want, tc.wantLen, tc.want)
			}
			// The point of the fix: the old expression really did differ.
			if tc.want != tc.wantLen {
				t.Logf("old derivation %d -> correct %d", tc.wantLen, tc.want)
			}
		})
	}
}

// #10700: the Rust pool expander keeps the first occurrence of an address
// across all configured members. Capacity and utilization denominators must
// count that same unique expanded set, not sum each overlapping member.
func TestSourceNATPoolReportableAddressesDeduplicatesExpandedMembers10700(t *testing.T) {
	for _, tc := range []struct {
		name string
		pool *NATPool
		want int
	}{
		{"duplicate host spellings", mkPool(t, "", "203.0.113.7", "203.0.113.7/32"), 1},
		{"v4 prefix contains host", mkPool(t, "", "203.0.113.0/31", "203.0.113.1/32"), 2},
		{"v4 partial overlap", mkPool(t, "", "203.0.113.0/30", "203.0.113.2/31"), 4},
		{"singular address overlaps list", mkPool(t, "203.0.113.7", "203.0.113.0/24"), 256},
		{"v6 prefix contains host", mkPool(t, "", "2001:db8::/127", "2001:db8::1/128"), 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := SourceNATPoolReportableAddresses(tc.pool, "p", nil)
			if reason != "" || got != tc.want {
				t.Fatalf("unique addresses = (%d, %q), want (%d, \"\")", got, reason, tc.want)
			}
		})
	}
}

// Direction 1: a pool the dataplane REFUSED reports ZERO, not a fabricated
// figure derived from members it never installed.
func TestSourceNATPoolReportableAddressesIsZeroForRefusedPools7000(t *testing.T) {
	cases := []struct {
		name       string
		pool       *NATPool
		poolName   string
		overBudget map[string]bool
		wantReason string
	}{
		// The issue's own measured case: a malformed prefix makes the WHOLE
		// pool invalid, so no allocator is installed.
		{"malformed prefix", mkPool(t, "", "10.0.0.0/016"), "p", nil, "invalid_pool"},
		{"over-capacity prefix", mkPool(t, "", "10.0.0.0/15"), "p", nil, "invalid_pool"},
		{"unparseable member", mkPool(t, "", "not-an-address"), "p", nil, "invalid_pool"},
		{"empty pool", &NATPool{}, "p", nil, "empty_pool"},
		{"missing pool", nil, "p", nil, "missing_pool"},
		// #6812's aggregate budget is part of "can this pool allocate", so a
		// pool refused there reports zero too.
		{"aggregate over budget", mkPool(t, "", "203.0.113.0/24"), "p",
			map[string]bool{"p": true}, "aggregate_over_budget"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := SourceNATPoolReportableAddresses(tc.pool, tc.poolName, tc.overBudget)
			if got != 0 {
				t.Fatalf("addresses = %d for a pool the dataplane refuses, want 0. "+
					"Any non-zero figure here is confidently wrong — it becomes the "+
					"denominator of a utilisation alert for a pool that can allocate "+
					"nothing (#7000)", got)
			}
			if reason != tc.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tc.wantReason)
			}
		})
	}
}

// THREE STATES (really five), NOT ONE. A capacity of 0 is ambiguous on its own,
// and the five ways to reach it have DIFFERENT operator remedies: define the
// pool, add members, fix the malformed member, or split the config / raise the
// budget. A surface that sees only the number cannot tell them apart, which is
// why the reason is returned WITH it.
//
// This is the same discrimination #6982 built for the NAT64 budget, one layer
// out — and the reason a test asserting only `capacity == 0` would pass against
// every one of these.
func TestSourceNATPoolZeroCapacityReasonsAreDistinct7000(t *testing.T) {
	seen := map[string]string{}
	for _, tc := range []struct {
		label      string
		pool       *NATPool
		overBudget map[string]bool
	}{
		{"missing", nil, nil},
		{"empty", &NATPool{}, nil},
		{"invalid", mkPool(t, "", "10.0.0.0/016"), nil},
		{"overbudget", mkPool(t, "", "203.0.113.1"), map[string]bool{"p": true}},
	} {
		got, reason := SourceNATPoolReportableAddresses(tc.pool, "p", tc.overBudget)
		if got != 0 {
			t.Fatalf("%s: expected a zero-capacity case, got %d", tc.label, got)
		}
		if prev, dup := seen[reason]; dup {
			t.Fatalf("%s and %s both report capacity 0 with the SAME reason %q — the two "+
				"states are indistinguishable at the consumption point, and their remedies "+
				"differ (#7000)", tc.label, prev, reason)
		}
		seen[reason] = tc.label
	}
	if len(seen) != 4 {
		t.Fatalf("expected 4 distinct zero reasons, got %d: %v", len(seen), seen)
	}
	// ...and a HEALTHY pool is distinguishable from all four by a non-zero
	// count with an empty reason. Without this the test could pass on a helper
	// that returned 0 for everything.
	got, reason := SourceNATPoolReportableAddresses(mkPool(t, "", "203.0.113.0/24"), "p", nil)
	if got != 256 || reason != "" {
		t.Fatalf("healthy pool = (%d, %q), want (256, \"\")", got, reason)
	}
}

// The port form multiplies the corrected cardinality through the shared
// arithmetic, and returns 0 for a refused pool WITHOUT consulting the port
// range at all.
func TestSourceNATPoolReportablePorts7000(t *testing.T) {
	ports, reason := SourceNATPoolReportablePorts(mkPool(t, "", "203.0.113.0/24"), "p", 1024, 65535, nil)
	if reason != "" || ports != 256*64512 {
		t.Fatalf("healthy /24 = (%d, %q), want (%d, \"\")", ports, reason, 256*64512)
	}
	ports, reason = SourceNATPoolReportablePorts(
		mkPool(t, "", "203.0.113.0/31", "203.0.113.1/32"), "p", 20000, 20001, nil)
	if reason != "" || ports != 4 {
		t.Fatalf("overlapping members = (%d, %q), want (4, \"\")", ports, reason)
	}
	ports, reason = SourceNATPoolReportablePorts(mkPool(t, "", "10.0.0.0/016"), "p", 1024, 65535, nil)
	if ports != 0 || reason != "invalid_pool" {
		t.Fatalf("refused pool = (%d, %q), want (0, \"invalid_pool\")", ports, reason)
	}
}

// The member expansion must mirror the Rust `expand_pool_address` exactly: it
// pushes EVERY address in the range, network and broadcast included. Counting
// usable hosts instead (254 for a /24) would under-report by two on every
// prefix and disagree with the allocator's own indexing.
func TestSourceNATPoolMemberHostsMirrorsTheExpander7000(t *testing.T) {
	for _, tc := range []struct {
		addr string
		want int
	}{
		{"203.0.113.1", 1},
		{"203.0.113.1/32", 1},
		{"203.0.113.0/31", 2},
		{"203.0.113.0/24", 256},
		{"10.0.0.0/16", 65536},
		{"10.0.0.0/15", 0}, // over MaxSourceNATPoolPrefixHosts — expander refuses
		{"2001:db8::1/128", 1},
		{"2001:db8::/112", 65536},
		{"2001:db8::/111", 0}, // over the cap
		{"garbage", 0},
	} {
		if got := sourceNATPoolMemberHosts(tc.addr); got != tc.want {
			t.Errorf("sourceNATPoolMemberHosts(%q) = %d, want %d", tc.addr, got, tc.want)
		}
	}
}
