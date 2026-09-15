package nftables

import (
	"strings"
	"testing"
)

// #9903 — STEP-0 repro: two netlink-builder gates fail permissive.
// F-126 (ifname16 truncation) and F-127 (pfxAddrMatch silent skip).
// Each cell is RED on the base and GREEN post-fix.

// --- F-126: overlong interface names -------------------------------

func buildIifnamePlan9903(t *testing.T, names []string) *nlPlan {
	t.Helper()
	p := newBuildPlan(t, "xpf_test_9903", lo0FilterPriority)
	p.rule().iifname(names).emit(verdictDrop()...)
	return p
}

func TestOverlongIfnameFailsClosed9903(t *testing.T) {
	for _, tc := range []struct{ name, why string }{
		{"1234567890123456", "16 bytes fill the field with no NUL; the compare key can never match a kernel interface"},
		{"12345678901234567890", "longer names truncate identically"},
		{"", "empty renders 16 zero bytes: a jump that matches nothing, silently"},
		{"a\x00b", "an embedded NUL passes a length check while truncating the kernel comparison"},
	} {
		p := buildIifnamePlan9903(t, []string{tc.name})
		if p.err == nil {
			t.Fatalf("a %d-byte ifname must fail the plan, not render a never-matching predicate: %s", len(tc.name), tc.why)
		}
		if !strings.Contains(p.err.Error(), "representable interface name") {
			t.Errorf("the diagnostic must classify the refusal, got %v", p.err)
		}
		if strings.IndexByte(tc.name, 0) < 0 && tc.name != "" && !strings.Contains(p.err.Error(), tc.name) {
			t.Errorf("the diagnostic must name the overlong interface, got %v", p.err)
		}
	}
}

func TestMixedIfnameSetFailsClosed9903(t *testing.T) {
	p := buildIifnamePlan9903(t, []string{"ge-0/0/0", "1234567890123456"})
	if p.err == nil {
		t.Fatal("one overlong member must fail the whole set build, not install the surviving subset")
	}
}

func TestBoundaryIfnameStillRenders9903(t *testing.T) {
	p := buildIifnamePlan9903(t, []string{"123456789012345"})
	if p.err != nil {
		t.Fatalf("a 15-byte ifname is exactly representable (15+NUL) and must render, got %v", p.err)
	}
	if len(p.rules) != 1 {
		t.Fatalf("want 1 rule emitted, got %d", len(p.rules))
	}
}

// --- F-127: unparseable / wrong-family address tokens --------------

func buildDaddrPlan9903(t *testing.T, f nlFamily, addrs []string, except bool) (p *nlPlan, panicked any) {
	t.Helper()
	p = newBuildPlan(t, "xpf_test_9903", lo0FilterPriority)
	defer func() { panicked = recover() }()
	p.rule().daddr(f, addrs, except).emit(verdictAccept()...)
	return p, nil
}

func TestGarbageAddrFailsClosed9903(t *testing.T) {
	for _, tc := range []struct {
		name   string
		f      nlFamily
		addrs  []string
		except bool
		bad    string
	}{
		{"all_garbage_positive", famV4, []string{"garbage"}, false, "garbage"},
		{"partial_garbage_positive", famV4, []string{"10.0.0.0/8", "garbage"}, false, "garbage"},
		{"all_garbage_except", famV4, []string{"garbage"}, true, "garbage"},
		{"partial_garbage_except", famV4, []string{"10.0.0.0/8", "garbage"}, true, "garbage"},
		{"all_garbage_v6", famV6, []string{"garbage"}, false, "garbage"},
		{"bad_bits", famV4, []string{"10.0.0.0/33"}, false, "10.0.0.0/33"},
		{"whitespace", famV4, []string{"  "}, false, "malformed address"},
		{"not_an_address", famV4, []string{"not-an-address"}, true, "not-an-address"},
	} {
		p, panicked := buildDaddrPlan9903(t, tc.f, tc.addrs, tc.except)
		if panicked != nil {
			t.Fatalf("%s: build panicked (%v) — a fail-closed error was owed, not a crash", tc.name, panicked)
		}
		if p.err == nil {
			t.Fatalf("%s: build MUST fail closed on an unparseable token (pre-fix: nil predicate, unconstrained direction)", tc.name)
		}
		if !strings.Contains(p.err.Error(), tc.bad) {
			t.Errorf("%s: the diagnostic must name the token, got %v", tc.name, p.err)
		}
	}
}

func TestWrongFamilyAddrFailsClosed9903(t *testing.T) {
	for _, tc := range []struct {
		name  string
		f     nlFamily
		addrs []string
	}{
		// v6 token in a v4 rule: pre-fix As4() PANICS in the build path.
		{"v6_prefix_in_v4", famV4, []string{"2001:db8::/32"}},
		{"v6_host_in_v4", famV4, []string{"2001:db8::1"}},
		// v4 token in a v6 rule: pre-fix As16 silently compares ::a.b.c.d (never-match).
		{"v4_prefix_in_v6", famV6, []string{"10.0.0.0/8"}},
		{"v4_host_in_v6", famV6, []string{"10.0.0.1"}},
		{"mixed_families_v4", famV4, []string{"10.0.0.0/8", "2001:db8::/32"}},
	} {
		p, panicked := buildDaddrPlan9903(t, tc.f, tc.addrs, false)
		if panicked != nil {
			t.Fatalf("%s: build panicked (%v) — a fail-closed error was owed, not a crash", tc.name, panicked)
		}
		if p.err == nil {
			t.Fatalf("%s: build MUST fail closed on a wrong-family token", tc.name)
		}
	}
}

func TestWellFormedAddrsStillLower9903(t *testing.T) {
	p, panicked := buildDaddrPlan9903(t, famV4, []string{"10.0.0.0/8", "192.0.2.1"}, false)
	if panicked != nil {
		t.Fatalf("clean build panicked: %v", panicked)
	}
	if p.err != nil {
		t.Fatalf("a clean address list must lower without error, got %v", p.err)
	}
	if len(p.rules) != 1 {
		t.Fatalf("want 1 rule emitted, got %d", len(p.rules))
	}
}

// TestEmptyAnyTokensAreStrippedNotFailed9903 (M3): "" and "any" are
// established no-constraint placeholders (lo0 parity) — stripped without
// error, never a whole-install refusal.
func TestEmptyAnyTokensAreStrippedNotFailed9903(t *testing.T) {
	for _, tok := range []string{"", "any"} {
		p, panicked := buildDaddrPlan9903(t, famV4, []string{tok}, false)
		if panicked != nil {
			t.Fatalf("%q: build panicked: %v", tok, panicked)
		}
		if p.err != nil {
			t.Fatalf("%q must strip without failing the plan, got %v", tok, p.err)
		}
	}
}

// TestZonedAddrFailsClosed9903 (M4): a zone scope has no payload-compare
// representation — As16 would drop it and un-scope a link-local to every
// interface. Refuse rather than un-scope. (Prefixes cannot carry zones:
// netip.ParsePrefix rejects them, so only the addr path is gated.)
func TestZonedAddrFailsClosed9903(t *testing.T) {
	p, panicked := buildDaddrPlan9903(t, famV6, []string{"fe80::1%eth0"}, false)
	if panicked != nil {
		t.Fatalf("zoned build panicked (%v) — a fail-closed error was owed", panicked)
	}
	if p.err == nil {
		t.Fatal("a zoned address must fail the plan, not silently un-scope")
	}
	if !strings.Contains(p.err.Error(), "fe80::1%eth0") {
		t.Errorf("the diagnostic must name the token, got %v", p.err)
	}
}

// TestMappedV4InV6ClassifiesAsV69903 (M4): ::ffff:a.b.c.d Is6()==true, so
// it renders in v6 rules (As16 carries the full 16 bytes) and fails in v4
// rules — identically to lo0's filterFamilyAddrs predicate.
func TestMappedV4InV6ClassifiesAsV69903(t *testing.T) {
	p, panicked := buildDaddrPlan9903(t, famV6, []string{"::ffff:10.0.0.1"}, false)
	if panicked != nil {
		t.Fatalf("mapped build panicked: %v", panicked)
	}
	if p.err != nil {
		t.Fatalf("a 4-in-6 literal must render in a v6 rule, got %v", p.err)
	}
	if len(p.rules) != 1 {
		t.Fatalf("want 1 rule emitted, got %d", len(p.rules))
	}
	p2, panicked := buildDaddrPlan9903(t, famV4, []string{"::ffff:10.0.0.1"}, false)
	if panicked != nil {
		t.Fatalf("mapped-in-v4 build panicked (%v) — a fail-closed error was owed", panicked)
	}
	if p2.err == nil {
		t.Fatal("a 4-in-6 literal in a v4 rule must fail the plan (wrong family)")
	}
}
