package config

import (
	"strings"
	"testing"
)

// #16875 (R3-B09-03): static-NAT and destination-NAT match/target
// literals in IPv4-mapped (::ffff:a.b.c.d) or IPv4-compatible
// (::a.b.c.d, excluding :: and ::1) form commit clean but a match in
// that form can never match: the userspace helper drops every native
// IPv6 frame whose src or dst is v4-mapped/compatible at ingress
// before NAT (#10686/#11669, ipv6_addr_is_v4_mapped_or_compat in
// userspace-dp/src/afxdp/frame/inspect.rs), and an IPv4 packet keys
// V4, missing the V6-keyed entry. A mapped TARGET/pool identity can
// be allocated outbound (the SNAT allocator keeps it in the V6 pool
// for any native-IPv6 source) but its return traffic is
// ingress-dropped, so it cannot carry bidirectional forwarding. The
// strict gates now reject such literals (warn on lenient),
// mirroring that predicate. Note the mapped 127/8 range
// (::ffff:127.x.x.x) is NOT exempt: Rust excludes only the exact
// ::1, and Go's netip IsLoopback would wrongly fold the mapped
// range out of the rejection (review fold on #17697).

func mappedStaticSet16875(match, prefix string) []string {
	return staticNATSet(match, prefix)
}

func TestMappedCompatStaticNATRejected16875(t *testing.T) {
	for _, tc := range []struct{ name, match, prefix string }{
		{"mapped match+target", "::ffff:203.0.113.5/128", "::ffff:10.0.0.5/128"},
		{"compat match+target", "::203.0.113.5/128", "::10.0.0.5/128"},
		{"mapped match only", "::ffff:203.0.113.5/128", "2001:db8::5/128"},
		{"compat target only", "2001:db8::1/128", "::10.0.0.5/128"},
		{"mapped bare match", "::ffff:203.0.113.5", "::ffff:10.0.0.5"},
		{"mapped loopback match", "::ffff:127.0.0.1/128", "2001:db8::5/128"},
		{"mapped loopback range match", "::ffff:127.0.0.2/128", "2001:db8::5/128"},
		{"mapped loopback hex match", "::ffff:7f00:2/128", "2001:db8::5/128"},
		{"mapped loopback target", "2001:db8::1/128", "::ffff:127.0.0.1/128"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree(t, mappedStaticSet16875(tc.match, tc.prefix)))
			if err == nil {
				t.Fatalf("mapped/compat static-NAT %s -> %s must be rejected at commit", tc.match, tc.prefix)
			}
			if !strings.Contains(err.Error(), "IPv4-mapped or IPv4-compatible") {
				t.Fatalf("error must name the mapped/compat cause, got: %v", err)
			}
		})
	}
}

func TestMappedCompatStaticNATControls16875(t *testing.T) {
	for _, tc := range []struct{ name, match, prefix string }{
		{"native v6", "2001:db8::5/128", "2001:db8:1::5/128"},
		{"native v4", "203.0.113.5/32", "10.0.0.5/32"},
		{"unspecified v6", "::/128", "::/128"},
		{"loopback v6", "::1/128", "::1/128"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CompileConfig(buildTree(t, mappedStaticSet16875(tc.match, tc.prefix))); err != nil {
				t.Fatalf("control %s -> %s must compile, got: %v", tc.match, tc.prefix, err)
			}
		})
	}
}

func TestMappedCompatStaticNATLenientWarns16875(t *testing.T) {
	cfg, err := CompileConfigLenient(buildTree(t, mappedStaticSet16875(
		"::ffff:203.0.113.5/128", "::ffff:10.0.0.5/128")))
	if err != nil {
		t.Fatalf("lenient load must not fail: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, "IPv4-mapped or IPv4-compatible") {
		t.Fatalf("lenient load must warn about the mapped/compat literal, got: %v", cfg.Warnings)
	}
}

func TestMappedCompatMappedLoopbackLenientWarns16875(t *testing.T) {
	// The mapped 127/8 range must warn on the tolerant path too — it
	// is inside the mapped rejection, not inside the ::1 exemption.
	cfg, err := CompileConfigLenient(buildTree(t, mappedStaticSet16875(
		"::ffff:127.0.0.1/128", "2001:db8::5/128")))
	if err != nil {
		t.Fatalf("lenient load must not fail: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, "IPv4-mapped or IPv4-compatible") {
		t.Fatalf("lenient load must warn about the mapped loopback literal, got: %v", cfg.Warnings)
	}
	cfg, err = CompileConfigLenient(buildTree(t, snatFamilySet16600(
		"source-address 2001:db8:1::/64", "::ffff:127.0.0.1")))
	if err != nil {
		t.Fatalf("lenient SNAT load must not fail: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, "IPv4-mapped or IPv4-compatible") {
		t.Fatalf("lenient load must warn about the mapped loopback pool member, got: %v", cfg.Warnings)
	}
}

func TestMappedCompatDNATRejected16875(t *testing.T) {
	for _, tc := range []struct{ name, match, pool string }{
		{"mapped match + mapped pool", "::ffff:203.0.113.5/128", "::ffff:10.0.0.5"},
		{"compat match + compat pool", "::203.0.113.5/128", "::10.0.0.5"},
		{"mapped match native pool", "::ffff:203.0.113.5/128", "2001:db8::5"},
		{"native match mapped pool", "2001:db8::1/128", "::ffff:10.0.0.5"},
		{"mapped prefix match", "::ffff:203.0.113.0/120", "::ffff:10.0.0.5"},
		{"mapped loopback match native pool", "::ffff:127.0.0.1/128", "2001:db8::5"},
		{"native match mapped loopback pool", "2001:db8::1/128", "::ffff:127.0.0.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines := []string{
				"set security zones security-zone untrust",
				"set security nat destination pool dp address " + tc.pool,
				"set security nat destination rule-set rs1 from zone untrust",
				"set security nat destination rule-set rs1 rule r1 match destination-address " + tc.match,
				"set security nat destination rule-set rs1 rule r1 then destination-nat pool dp",
			}
			_, err := CompileConfig(buildTree(t, lines))
			if err == nil {
				t.Fatalf("mapped/compat DNAT match %q pool %q must be rejected", tc.match, tc.pool)
			}
			if !strings.Contains(err.Error(), "IPv4-mapped or IPv4-compatible") {
				t.Fatalf("error must name the mapped/compat cause, got: %v", err)
			}
		})
	}
}

func TestMappedCompatDNATControls16875(t *testing.T) {
	for _, tc := range []struct{ name, match, pool string }{
		{"native v6", "2001:db8::5/128", "2001:db8:1::5"},
		{"native v4", "203.0.113.5/32", "10.0.0.5"},
		{"loopback match", "::1/128", "::1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines := []string{
				"set security zones security-zone untrust",
				"set security nat destination pool dp address " + tc.pool,
				"set security nat destination rule-set rs1 from zone untrust",
				"set security nat destination rule-set rs1 rule r1 match destination-address " + tc.match,
				"set security nat destination rule-set rs1 rule r1 then destination-nat pool dp",
			}
			if _, err := CompileConfig(buildTree(t, lines)); err != nil {
				t.Fatalf("control DNAT %q pool %q must compile, got: %v", tc.match, tc.pool, err)
			}
		})
	}
}

func TestMappedCompatDNATLenientWarns16875(t *testing.T) {
	lines := []string{
		"set security zones security-zone untrust",
		"set security nat destination pool dp address ::ffff:10.0.0.5",
		"set security nat destination rule-set rs1 from zone untrust",
		"set security nat destination rule-set rs1 rule r1 match destination-address ::ffff:203.0.113.5/128",
		"set security nat destination rule-set rs1 rule r1 then destination-nat pool dp",
	}
	cfg, err := CompileConfigLenient(buildTree(t, lines))
	if err != nil {
		t.Fatalf("lenient load must not fail: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, "IPv4-mapped or IPv4-compatible") {
		t.Fatalf("lenient load must warn about the mapped/compat literal, got: %v", cfg.Warnings)
	}
}

func TestMappedCompatSNATPoolRejected16875(t *testing.T) {
	for _, tc := range []struct{ name, pool string }{
		{"mapped pool member", "::ffff:192.0.2.1"},
		{"compat pool member", "::192.0.2.1"},
		{"mapped pool prefix", "::ffff:192.0.2.0/120"},
		{"mapped loopback pool member", "::ffff:127.0.0.1"},
		{"mapped loopback pool prefix", "::ffff:127.0.0.0/120"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree(t, snatFamilySet16600(
				"source-address 2001:db8:1::/64", tc.pool)))
			if err == nil {
				t.Fatalf("mapped/compat SNAT pool member %q must be rejected", tc.pool)
			}
			if !strings.Contains(err.Error(), "IPv4-mapped or IPv4-compatible") {
				t.Fatalf("error must name the mapped/compat cause, got: %v", err)
			}
		})
	}
}

func TestMappedCompatSNATPoolControls16875(t *testing.T) {
	for _, tc := range []struct{ name, src, pool string }{
		{"native v6 pool", "source-address 2001:db8:1::/64", "2001:db8::5"},
		{"native v4 pool", "source-address 10.0.0.0/24", "192.0.2.5"},
		{"loopback v6 pool", "source-address 2001:db8:1::/64", "::1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CompileConfig(buildTree(t, snatFamilySet16600(tc.src, tc.pool))); err != nil {
				t.Fatalf("control SNAT pool %q must compile, got: %v", tc.pool, err)
			}
		})
	}
}

func TestMappedCompatSNATPoolLenientWarns16875(t *testing.T) {
	cfg, err := CompileConfigLenient(buildTree(t, snatFamilySet16600(
		"source-address 2001:db8:1::/64", "::ffff:192.0.2.1")))
	if err != nil {
		t.Fatalf("lenient load must not fail: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, "IPv4-mapped or IPv4-compatible") {
		t.Fatalf("lenient load must warn about the mapped/compat pool member, got: %v", cfg.Warnings)
	}
}

func TestMappedCompatPredicate16875(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"::ffff:203.0.113.5", true},
		{"::ffff:203.0.113.5/128", true},
		{"::ffff:203.0.113.0/120", true},
		{"::ffff:0:0", true}, // hex spelling of the mapped form
		{"::203.0.113.5", true},
		{"::203.0.113.5/128", true},
		// Mapped 127/8: Rust excludes only the exact ::1, so the whole
		// mapped loopback range is mapped (ingress-dropped). Go's
		// netip IsLoopback Unmaps and would exempt these — the
		// predicate must not use it (#17697 review fold).
		{"::ffff:127.0.0.1", true},
		{"::ffff:127.0.0.1/128", true},
		{"::ffff:127.0.0.2", true},
		{"::ffff:127.255.255.254/128", true},
		{"::ffff:7f00:1", true}, // hex spelling of ::ffff:127.0.0.1
		{"::127.0.0.1", true},   // compat loopback-range spelling
		{"::", false},           // unspecified excluded (Rust predicate)
		{"::1", false},          // loopback excluded
		{"::/0", false},
		{"::1/128", false},
		{"2001:db8::5", false},
		{"2001:db8::5/128", false},
		{"203.0.113.5", false},
		{"203.0.113.5/32", false},
		{"0.0.0.0/0", false},
		{"not-an-ip", false},
		{"", false},
		{"web-server", false},
	} {
		if got := natAddrIsV4MappedOrCompat(tc.in); got != tc.want {
			t.Errorf("natAddrIsV4MappedOrCompat(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
