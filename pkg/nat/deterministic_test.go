package nat

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// v4View builds an applied view with a single mode-1 (IPv4) deterministic
// pool matching the Rust golden vectors in
// userspace-dp/src/nat/tests_pool.rs
// (deterministic_cgnat_v4_fixed_block_per_subscriber_reversible):
// pool 203.0.113.1-4, port range 1024-65535, block-size 512 (=> 126
// blocks/addr), subscriber CIDR 100.64.0.0/22 (=> host_count 1024).
func v4View(gen uint64) AppliedView {
	pool := &config.NATPool{
		Name:      "cgn-pool",
		Addresses: []string{"203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"},
		PortLow:   1024,
		PortHigh:  65535,
		Deterministic: &config.DeterministicNATConfig{
			BlockSize:   512,
			HostAddress: "100.64.0.0/22",
		},
	}
	cfg := &config.Config{}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{"cgn-pool": pool}
	return AppliedView{Config: cfg, Generation: gen, Available: true}
}

// v6View builds an applied view with a single mode-2 (IPv6/NAPT64)
// deterministic pool matching the Rust golden vectors
// (deterministic_napt64_v6_fixed_block_per_subscriber_reversible):
// external pool 198.51.100.1-4, NAT64 port range 1024-65535, block-size 512
// (=> 126 blocks/addr), subscriber prefix 2001:db8::/32 (=> host_count 504).
func v6View(gen uint64) AppliedView {
	pool := &config.NATPool{
		Name:      "napt64-pool",
		Addresses: []string{"198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4"},
		Deterministic: &config.DeterministicNATConfig{
			BlockSize:   512,
			HostAddress: "2001:db8::/32",
		},
	}
	cfg := &config.Config{}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{"napt64-pool": pool}
	cfg.Security.NAT.NAT64 = []*config.NAT64RuleSet{{
		Name:       "v6-to-v4",
		Prefix:     "64:ff9b::/96",
		SourcePool: "napt64-pool",
	}}
	return AppliedView{Config: cfg, Generation: gen, Available: true}
}

// TestDeterministicV4GoldenVectors pins the mode-1 forward + reverse mapping
// to the exact values the Rust allocator test asserts. If the Go arithmetic
// drifts from the enforced dataplane mapping, these fail.
func TestDeterministicV4GoldenVectors(t *testing.T) {
	view := v4View(7)

	// Subscriber A = 100.64.0.5 -> sub_idx 5, ip_idx 0, block_idx 5,
	// block [3584, 4095], external pool[0] = 203.0.113.1.
	fwd, err := LookupForward(view, "cgn-pool", "100.64.0.5")
	if err != nil {
		t.Fatalf("forward A: unexpected error %v", err)
	}
	if fwd.ExternalIP != "203.0.113.1" || fwd.PortLow != 3584 || fwd.PortHigh != 4095 ||
		fwd.BlockIndex != 5 || fwd.BlockSize != 512 || fwd.Mode != ModeV4 || fwd.AppliedGeneration != 7 {
		t.Fatalf("forward A mismatch: %+v", fwd)
	}

	// Subscriber B = 100.64.1.0 -> sub_idx 256, ip_idx 2, block_idx 4,
	// block [3072, 3583], external pool[2] = 203.0.113.3.
	fwd, err = LookupForward(view, "cgn-pool", "100.64.1.0")
	if err != nil {
		t.Fatalf("forward B: unexpected error %v", err)
	}
	if fwd.ExternalIP != "203.0.113.3" || fwd.PortLow != 3072 || fwd.PortHigh != 3583 || fwd.BlockIndex != 4 {
		t.Fatalf("forward B mismatch: %+v", fwd)
	}

	// Reverse the two golden tuples back to their subscribers.
	rev, err := LookupReverse(view, "cgn-pool", "203.0.113.1", 3584)
	if err != nil {
		t.Fatalf("reverse A: unexpected error %v", err)
	}
	if rev.InternalHost != "100.64.0.5" || rev.PortLow != 3584 || rev.PortHigh != 4095 || rev.AppliedGeneration != 7 {
		t.Fatalf("reverse A mismatch: %+v", rev)
	}
	rev, err = LookupReverse(view, "cgn-pool", "203.0.113.3", 3072)
	if err != nil {
		t.Fatalf("reverse B: unexpected error %v", err)
	}
	if rev.InternalHost != "100.64.1.0" {
		t.Fatalf("reverse B mismatch: %+v", rev)
	}
}

// TestDeterministicV6GoldenVectors pins the mode-2 (NAPT64) forward +
// reverse mapping to the Rust golden vectors.
func TestDeterministicV6GoldenVectors(t *testing.T) {
	view := v6View(3)

	// Subscriber A = 2001:db8:0:5:: -> word 5 -> sub_idx 5, ip_idx 0,
	// block_idx 5, block [3584, 4095], external pool[0] = 198.51.100.1.
	fwd, err := LookupForward(view, "napt64-pool", "2001:db8:0:5::")
	if err != nil {
		t.Fatalf("forward A: unexpected error %v", err)
	}
	if fwd.ExternalIP != "198.51.100.1" || fwd.PortLow != 3584 || fwd.PortHigh != 4095 ||
		fwd.BlockIndex != 5 || fwd.Mode != ModeV6 {
		t.Fatalf("forward A mismatch: %+v", fwd)
	}

	// Subscriber B = 2001:db8:0:100:: -> word 256 -> sub_idx 256, ip_idx 2,
	// block_idx 4, block [3072, 3583], external pool[2] = 198.51.100.3.
	fwd, err = LookupForward(view, "napt64-pool", "2001:db8:0:100::")
	if err != nil {
		t.Fatalf("forward B: unexpected error %v", err)
	}
	if fwd.ExternalIP != "198.51.100.3" || fwd.PortLow != 3072 || fwd.PortHigh != 3583 || fwd.BlockIndex != 4 {
		t.Fatalf("forward B mismatch: %+v", fwd)
	}

	// Reverse recovers the subscriber PREFIX (network base + word).
	rev, err := LookupReverse(view, "napt64-pool", "198.51.100.1", 3584)
	if err != nil {
		t.Fatalf("reverse A: unexpected error %v", err)
	}
	if rev.InternalHost != "2001:db8:0:5::" {
		t.Fatalf("reverse A mismatch: got %q want 2001:db8:0:5::", rev.InternalHost)
	}
	rev, err = LookupReverse(view, "napt64-pool", "198.51.100.3", 3072)
	if err != nil {
		t.Fatalf("reverse B: unexpected error %v", err)
	}
	if rev.InternalHost != "2001:db8:0:100::" {
		t.Fatalf("reverse B mismatch: got %q", rev.InternalHost)
	}

	// A subscriber beyond the pool-bounded host_count (504) fails closed.
	// sub_idx 504 is word 0x1f8 -> 2001:db8:0:1f8::.
	if _, e := LookupForward(view, "napt64-pool", "2001:db8:0:1f8::"); e == nil || e.Code != ErrCodeOutOfRange {
		t.Fatalf("beyond-capacity subscriber must be out-of-range, got %v", e)
	}
}

// TestDeterministicV6Prefix64 checks the /64 subscriber-word offset (octet
// 8) golden value from the Rust test: 2001:db8::7:0:0 -> sub_idx 7.
func TestDeterministicV6Prefix64(t *testing.T) {
	pool := &config.NATPool{
		Name:      "p64",
		Addresses: []string{"198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4"},
		Deterministic: &config.DeterministicNATConfig{
			BlockSize:   512,
			HostAddress: "2001:db8::/64",
		},
	}
	cfg := &config.Config{}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{"p64": pool}
	cfg.Security.NAT.NAT64 = []*config.NAT64RuleSet{{
		Name:       "v6-to-v4",
		Prefix:     "64:ff9b::/96",
		SourcePool: "p64",
	}}
	view := AppliedView{Config: cfg, Generation: 1, Available: true}

	// word 7 -> sub_idx 7, ip_idx 0, block_idx 7, block [1024+7*512, ..+511]
	// = [4608, 5119], external pool[0].
	fwd, err := LookupForward(view, "p64", "2001:db8::7:0:0")
	if err != nil {
		t.Fatalf("forward /64: %v", err)
	}
	if fwd.BlockIndex != 7 || fwd.ExternalIP != "198.51.100.1" || fwd.PortLow != 4608 || fwd.PortHigh != 5119 {
		t.Fatalf("/64 forward mismatch: %+v", fwd)
	}
	rev, err := LookupReverse(view, "p64", "198.51.100.1", 4700)
	if err != nil {
		t.Fatalf("reverse /64: %v", err)
	}
	if rev.InternalHost != "2001:db8::7:0:0" {
		t.Fatalf("/64 reverse mismatch: got %q", rev.InternalHost)
	}
}

// TestRoundTripV4 is a bounded property test: every subscriber in the pool's
// range maps forward to a block, and any port in that block reverses back to
// the same subscriber.
func TestRoundTripV4(t *testing.T) {
	pool := &config.NATPool{
		Name:      "small",
		Addresses: []string{"203.0.113.1", "203.0.113.2"},
		PortLow:   1024,
		PortHigh:  1039,
		Deterministic: &config.DeterministicNATConfig{
			BlockSize:   4,
			HostAddress: "100.64.0.0/29",
		},
	}
	cfg := &config.Config{}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{"small": pool}
	view := AppliedView{Config: cfg, Generation: 1, Available: true}

	// Two addresses * four blocks/address exactly serves every subscriber in
	// the /29. Cover all eight, and assert no two subscribers receive the same
	// external address + block before checking reverse lookup at three ports.
	seen := make(map[string]string)
	for i := 0; i < 8; i++ {
		host := fmt.Sprintf("100.64.0.%d", i)
		fwd, err := LookupForward(view, "small", host)
		if err != nil {
			t.Fatalf("forward %s: %v", host, err)
		}
		mapping := fmt.Sprintf("%s:%d-%d", fwd.ExternalIP, fwd.PortLow, fwd.PortHigh)
		if prior, exists := seen[mapping]; exists {
			t.Fatalf("non-injective mapping: subscribers %s and %s both map to %s", prior, host, mapping)
		}
		seen[mapping] = host
		// First, middle, and last port of the block must all reverse back.
		// (Compute the midpoint without overflowing uint16.)
		for _, port := range []uint16{fwd.PortLow, fwd.PortLow + (fwd.PortHigh-fwd.PortLow)/2, fwd.PortHigh} {
			rev, rerr := LookupReverse(view, "small", fwd.ExternalIP, port)
			if rerr != nil {
				t.Fatalf("reverse %s:%d: %v", fwd.ExternalIP, port, rerr)
			}
			if rev.InternalHost != host {
				t.Fatalf("round-trip mismatch: %s -> %s:%d -> %s", host, fwd.ExternalIP, port, rev.InternalHost)
			}
		}
	}
}

// TestReverseRejectsDuplicatePoolAddress pins the #14623 rule: the
// Rust dataplane keeps only the first occurrence of a pool address (seen-set
// in expand_pool_address's production caller), so a duplicated address has
// exactly one pool position. The Go pool must dedupe the same way — the
// address is no longer ambiguous on reverse, and subscribers past the
// duplicate index into the single deduped position.
func TestReverseRejectsDuplicatePoolAddress(t *testing.T) {
	pool := &config.NATPool{
		Name:      "duplicate",
		Addresses: []string{"203.0.113.1", "203.0.113.1"},
		PortLow:   1024,
		PortHigh:  1031,
		Deterministic: &config.DeterministicNATConfig{
			BlockSize:   4,
			HostAddress: "100.64.0.0/29",
		},
	}
	cfg := &config.Config{}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{"duplicate": pool}
	view := AppliedView{Config: cfg, Generation: 1, Available: true}

	// Deduped pool is [203.0.113.1] with 2 blocks (1024-1027, 1028-1031):
	// sub_idx 0 -> block 0, sub_idx 1 -> block 1. sub_idx 2 would need a
	// second pool position the dataplane does not have.
	fwd, err := LookupForward(view, "duplicate", "100.64.0.1")
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	if fwd.ExternalIP != "203.0.113.1" || fwd.PortLow != 1028 {
		t.Fatalf("forward mismatch: %+v, want 203.0.113.1 block 1028-1031", fwd)
	}
	if _, e := LookupForward(view, "duplicate", "100.64.0.2"); e == nil || e.Code != ErrCodeOutOfRange {
		t.Fatalf("subscriber past the deduped pool must be out-of-range, got %v", e)
	}
	rev, e := LookupReverse(view, "duplicate", "203.0.113.1", 1028)
	if e != nil {
		t.Fatalf("reverse of deduped address must succeed (first occurrence wins), got %v", e)
	}
	if rev.InternalHost != "100.64.0.1" {
		t.Fatalf("reverse mismatch: got %s, want 100.64.0.1", rev.InternalHost)
	}
}

func TestUnreferencedDeterministicV6PoolIsNotDeterministic(t *testing.T) {
	view := v6View(1)
	view.Config.Security.NAT.NAT64 = nil
	wantDetail := "pool is not referenced by a NAT64 rule; translations are round-robin, not deterministic"

	if _, e := LookupForward(view, "napt64-pool", "2001:db8:0:5::"); e == nil ||
		e.Code != ErrCodeNotDeterministic || e.Detail != wantDetail {
		t.Fatalf("unreferenced v6 forward must be not-deterministic, got %v", e)
	}
	if _, e := LookupReverse(view, "napt64-pool", "198.51.100.1", 3584); e == nil ||
		e.Code != ErrCodeNotDeterministic || e.Detail != wantDetail {
		t.Fatalf("unreferenced v6 reverse must be not-deterministic, got %v", e)
	}
}

// TestDeterministicV6RejectsSubnetPoolAddress covers the mode-2 distinction
// from source NAT: Rust NAT64 parse_pool_v4 filters a non-/32 entry instead
// of expanding it, so the forensic lookup must never invent those addresses.
func TestDeterministicV6RejectsSubnetPoolAddress(t *testing.T) {
	view := v6View(1)
	view.Config.Security.NAT.SourcePools["napt64-pool"].Addresses = []string{"203.0.113.0/28"}
	wantDetail := "NAT64 deterministic pool requires host (/32) external addresses; subnet \"203.0.113.0/28\" is not enforced deterministically"

	if _, e := LookupForward(view, "napt64-pool", "2001:db8::"); e == nil ||
		e.Code != ErrCodeNotDeterministic || e.Detail != wantDetail {
		t.Fatalf("NAT64 subnet-pool forward must be not-deterministic, got %v", e)
	}
	if _, e := LookupReverse(view, "napt64-pool", "203.0.113.0", 1024); e == nil ||
		e.Code != ErrCodeNotDeterministic || e.Detail != wantDetail {
		t.Fatalf("NAT64 subnet-pool reverse must be not-deterministic, got %v", e)
	}
}

// TestNAT64UninstallablePrefixRuleIsNotDeterministic covers the finding that a
// NAT64 rule whose prefix the dataplane refuses to install (empty, non-/96,
// extra-slash, or unparseable — userspace-dp/src/nat64.rs skips the whole rule)
// must NOT expose its source pool as deterministic. Before the fix
// nat64ReferencedPools counted any bare reference, so an empty-prefix rule
// reported a confident mapping that no installed rule actually performs.
func TestNAT64UninstallablePrefixRuleIsNotDeterministic(t *testing.T) {
	wantDetail := "pool is not referenced by a NAT64 rule; translations are round-robin, not deterministic"
	for _, prefix := range []string{"", "64:ff9b::", "64:ff9b::/64", "64:ff9b::/96/x", "not-an-ip/96"} {
		view := v6View(1)
		view.Config.Security.NAT.NAT64[0].Prefix = prefix
		if _, e := LookupForward(view, "napt64-pool", "2001:db8:0:5::"); e == nil ||
			e.Code != ErrCodeNotDeterministic || e.Detail != wantDetail {
			t.Fatalf("prefix %q forward must be not-deterministic, got %v", prefix, e)
		}
		if _, e := LookupReverse(view, "napt64-pool", "198.51.100.1", 3584); e == nil ||
			e.Code != ErrCodeNotDeterministic || e.Detail != wantDetail {
			t.Fatalf("prefix %q reverse must be not-deterministic, got %v", prefix, e)
		}
	}
	// Control: the canonical <ipv6>/96 rule stays deterministic.
	if _, e := LookupForward(v6View(1), "napt64-pool", "2001:db8:0:5::"); e != nil {
		t.Fatalf("valid /96 rule must stay deterministic, got %v", e)
	}
	// Control: an IPv4-mapped IPv6 prefix (::ffff:.../96) IS installable —
	// Rust Ipv6Addr::from_str accepts it, so the reference gate must not reject
	// it via a To4()-based family test (the round-3 false-negative divergence).
	mapped := v6View(1)
	mapped.Config.Security.NAT.NAT64[0].Prefix = "::ffff:192.0.2.1/96"
	if _, e := LookupForward(mapped, "napt64-pool", "2001:db8:0:5::"); e != nil {
		t.Fatalf("IPv4-mapped /96 prefix must stay deterministic (Rust accepts it), got %v", e)
	}
}

// TestDeterministicV6RejectsIPv6PoolMember covers the finding that a mode-2
// pool containing a non-IPv4 member must reject the WHOLE pool, mirroring Rust
// parse_pool_v4 (`continue 'rules`, #3888 all-or-nothing). Before the fix the
// v6 member was silently skipped and a mapping was invented from the surviving
// v4 members.
func TestDeterministicV6RejectsIPv6PoolMember(t *testing.T) {
	// Includes IPv4-mapped forms (bare + CIDR): Go net.IP.To4() folds them to a
	// 4-byte v4 address, but Rust parse_pool_v4 rejects every colon-bearing form
	// and skips the whole rule — so they must reject the whole pool, not be
	// silently accepted as a v4 member (the round-3 fabricated-mapping case).
	for _, member := range []string{"2001:db8:aaaa::1", "2001:db8:aaaa::/64", "::ffff:198.51.100.9", "::ffff:198.51.100.0/120"} {
		view := v6View(1)
		p := view.Config.Security.NAT.SourcePools["napt64-pool"]
		p.Addresses = []string{"198.51.100.1", member, "198.51.100.2"}
		wantDetail := "NAT64 deterministic pool member \"" + member + "\" is not an IPv4 host; the dataplane skips the whole rule"
		if _, e := LookupForward(view, "napt64-pool", "2001:db8:0:5::"); e == nil ||
			e.Code != ErrCodeNotDeterministic || e.Detail != wantDetail {
			t.Fatalf("mixed pool member %q forward must reject whole pool, got %v", member, e)
		}
		if _, e := LookupReverse(view, "napt64-pool", "198.51.100.1", 3584); e == nil ||
			e.Code != ErrCodeNotDeterministic || e.Detail != wantDetail {
			t.Fatalf("mixed pool member %q reverse must reject whole pool, got %v", member, e)
		}
	}
}

// TestDeterministicV4ExcludesMappedIPv6PoolMember covers round-3 finding #3:
// a mode-1 (IPv4 source-NAT) pool with a bare IPv4-mapped IPv6 member must
// EXCLUDE it from poolV4 — Rust IpAddr classifies it V6 and the v4 allocator
// skips it, but Go net.IP.To4() would fold it in and expose an extra pool
// position the allocator does not have. poolParams keys on config.NATAddrFamily.
func TestDeterministicV4ExcludesMappedIPv6PoolMember(t *testing.T) {
	pool := &config.NATPool{
		Addresses: []string{"203.0.113.1", "::ffff:203.0.113.9", "203.0.113.2"},
		PortLow:   1024,
		PortHigh:  65535,
		Deterministic: &config.DeterministicNATConfig{
			BlockSize:   512,
			HostAddress: "100.64.0.0/24",
		},
	}
	p, err := poolParams(pool, false)
	if err != nil {
		t.Fatalf("mode-1 mapped-member pool: %v", err)
	}
	if len(p.poolV4) != 2 || p.poolV4[0].String() != "203.0.113.1" || p.poolV4[1].String() != "203.0.113.2" {
		t.Fatalf("mode-1 must exclude the IPv4-mapped member, got %v", p.poolV4)
	}
}

// TestDeterministicRejectsMappedQueryFamily covers round-4: a QUERY address's
// family must be classified with the colon-strict SSOT, not net.IP.To4(). An
// IPv4-mapped literal (::ffff:...) is "v6" — it must NOT map in a mode-1 (IPv4)
// pool (Rust mode 1 only handles IpAddr::V4; To4() would fabricate a mapping)
// and must NOT reverse as a translated IPv4 address.
func TestDeterministicRejectsMappedQueryFamily(t *testing.T) {
	if r, e := LookupForward(v4View(7), "cgn-pool", "::ffff:100.64.0.5"); e == nil || e.Code != ErrCodeMalformedInput {
		t.Fatalf("mapped mode-1 subscriber must be malformed-input, got r=%+v e=%v", r, e)
	}
	if r, e := LookupReverse(v4View(7), "cgn-pool", "::ffff:203.0.113.1", 3584); e == nil || e.Code != ErrCodeMalformedInput {
		t.Fatalf("mapped reverse natIP must be malformed-input, got r=%+v e=%v", r, e)
	}
	// Control: the ordinary dotted-quad still maps and reverses.
	if _, e := LookupForward(v4View(7), "cgn-pool", "100.64.0.5"); e != nil {
		t.Fatalf("ordinary v4 subscriber must still map, got %v", e)
	}
	if _, e := LookupReverse(v4View(7), "cgn-pool", "203.0.113.1", 3584); e != nil {
		t.Fatalf("ordinary v4 translated addr must still reverse, got %v", e)
	}
}

func TestDeterministicV4SubnetPoolStillExpands(t *testing.T) {
	pool := &config.NATPool{
		Addresses: []string{"203.0.113.0/28"},
		PortLow:   1024,
		PortHigh:  65535,
		Deterministic: &config.DeterministicNATConfig{
			BlockSize:   512,
			HostAddress: "100.64.0.0/24",
		},
	}
	p, err := poolParams(pool, false)
	if err != nil {
		t.Fatalf("mode-1 subnet pool: %v", err)
	}
	if len(p.poolV4) != 16 || p.poolV4[0].String() != "203.0.113.0" || p.poolV4[15].String() != "203.0.113.15" {
		t.Fatalf("mode-1 /28 expansion changed: %v", p.poolV4)
	}
}

// TestDeterministicV6PoolV4MatchesNAT64Allocator is the pool-vector parity
// golden for mode 2. Unlike scalar wire-field parity, this pins the exact
// ordered members accepted by Rust parse_pool_v4 (bare hosts and /32s) and
// the pool-bounded host_count derived from that vector.
func TestDeterministicV6PoolV4MatchesNAT64Allocator(t *testing.T) {
	pool := &config.NATPool{
		Address:   "198.51.100.9/32",
		Addresses: []string{"198.51.100.10", "198.51.100.11/32"},
		Deterministic: &config.DeterministicNATConfig{
			BlockSize:   512,
			HostAddress: "2001:db8::/32",
		},
	}
	p, err := poolParams(pool, true)
	if err != nil {
		t.Fatalf("mode-2 params: %v", err)
	}
	gotPool := make([]string, len(p.poolV4))
	for i, ip := range p.poolV4 {
		gotPool[i] = ip.String()
	}
	wantPool := []string{"198.51.100.9", "198.51.100.10", "198.51.100.11"}
	if fmt.Sprint(gotPool) != fmt.Sprint(wantPool) {
		t.Fatalf("mode-2 pool_v4 drift: got %v want NAT64 allocator %v", gotPool, wantPool)
	}
	if p.mode != ModeV6 || p.blocksPerIP != 126 || p.hostCount != uint32(len(wantPool))*126 {
		t.Fatalf("mode-2 capacity drift: mode=%d blocks-per-ip=%d host-count=%d", p.mode, p.blocksPerIP, p.hostCount)
	}
}

// TestForwardBeyondPoolCapacity documents that a subscriber inside the host
// CIDR but past the pool's servable capacity (ip_idx >= len(pool)) fails
// closed, matching the Rust allocator's ip_idx bound. 100.64.1.248 is
// sub_idx 504, whose ip_idx (504/126 = 4) exceeds the 4-address pool.
func TestForwardBeyondPoolCapacity(t *testing.T) {
	view := v4View(1)
	if _, e := LookupForward(view, "cgn-pool", "100.64.1.248"); e == nil || e.Code != ErrCodeOutOfRange {
		t.Fatalf("expected out-of-range for beyond-capacity subscriber, got %v", e)
	}
}

func TestErrorCases(t *testing.T) {
	view := v4View(1)

	// No applied view.
	if _, e := LookupForward(AppliedView{Available: false}, "cgn-pool", "100.64.0.5"); e == nil || e.Code != ErrCodeNoAppliedView {
		t.Fatalf("expected no-applied-view, got %v", e)
	}
	// Unknown pool.
	if _, e := LookupForward(view, "nope", "100.64.0.5"); e == nil || e.Code != ErrCodeUnknownPool {
		t.Fatalf("expected unknown-pool, got %v", e)
	}
	// Malformed subscriber.
	if _, e := LookupForward(view, "cgn-pool", "not-an-ip"); e == nil || e.Code != ErrCodeMalformedInput {
		t.Fatalf("expected malformed-input, got %v", e)
	}
	// Out-of-range subscriber (100.64.4.0 is past the /22).
	if _, e := LookupForward(view, "cgn-pool", "100.64.4.0"); e == nil || e.Code != ErrCodeOutOfRange {
		t.Fatalf("expected out-of-range, got %v", e)
	}
	// Wrong family for a mode-1 pool.
	if _, e := LookupForward(view, "cgn-pool", "2001:db8::1"); e == nil || e.Code != ErrCodeMalformedInput {
		t.Fatalf("expected malformed-input for v6 subscriber on v4 pool, got %v", e)
	}
	// Reverse: translated IP not in pool.
	if _, e := LookupReverse(view, "cgn-pool", "192.0.2.99", 3584); e == nil || e.Code != ErrCodeNotFound {
		t.Fatalf("expected not-found, got %v", e)
	}
	// Reverse: malformed port.
	if _, e := LookupReverse(view, "cgn-pool", "203.0.113.1", 0); e == nil || e.Code != ErrCodeMalformedInput {
		t.Fatalf("expected malformed-input for port 0, got %v", e)
	}

	// Non-deterministic pool.
	plain := &config.NATPool{Name: "plain", Addresses: []string{"203.0.113.9"}, PortLow: 1024, PortHigh: 65535}
	cfg := &config.Config{}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{"plain": plain}
	pv := AppliedView{Config: cfg, Generation: 1, Available: true}
	if _, e := LookupForward(pv, "plain", "100.64.0.5"); e == nil || e.Code != ErrCodeNotDeterministic {
		t.Fatalf("expected not-deterministic, got %v", e)
	}
}

// TestAmbiguousReverse verifies that when no pool is selected and two
// deterministic pools share the same external tuple, the reverse query is
// rejected as ambiguous rather than returning a first-match (invariant 6).
func TestAmbiguousReverse(t *testing.T) {
	poolA := &config.NATPool{
		Name: "a", Addresses: []string{"203.0.113.1"}, PortLow: 1024, PortHigh: 65535,
		Deterministic: &config.DeterministicNATConfig{BlockSize: 512, HostAddress: "100.64.0.0/24"},
	}
	poolB := &config.NATPool{
		Name: "b", Addresses: []string{"203.0.113.1"}, PortLow: 1024, PortHigh: 65535,
		Deterministic: &config.DeterministicNATConfig{BlockSize: 512, HostAddress: "100.65.0.0/24"},
	}
	cfg := &config.Config{}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{"a": poolA, "b": poolB}
	view := AppliedView{Config: cfg, Generation: 1, Available: true}

	// The external tuple 203.0.113.1:1024 (block 0) exists in both pools.
	if _, e := LookupReverse(view, "", "203.0.113.1", 1024); e == nil || e.Code != ErrCodeAmbiguousPool {
		t.Fatalf("expected ambiguous-pool, got %v", e)
	}
	// Selecting a pool disambiguates.
	rev, err := LookupReverse(view, "a", "203.0.113.1", 1024)
	if err != nil {
		t.Fatalf("pool-scoped reverse: %v", err)
	}
	if rev.InternalHost != "100.64.0.0" {
		t.Fatalf("pool a reverse mismatch: %+v", rev)
	}
	// A pool-less forward for a subscriber only in pool "a" resolves.
	fwd, ferr := LookupForward(view, "", "100.64.0.5")
	if ferr != nil {
		t.Fatalf("pool-less forward: %v", ferr)
	}
	if fwd.Pool != "a" {
		t.Fatalf("expected pool a, got %q", fwd.Pool)
	}
}

// TestAppliedGenerationEchoed confirms the applied generation is reported
// (invariant 3 / 4: N+1 desired must return N's mapping — the caller passes
// the APPLIED generation, and it is surfaced verbatim).
func TestAppliedGenerationEchoed(t *testing.T) {
	view := v4View(42)
	fwd, err := LookupForward(view, "cgn-pool", "100.64.0.5")
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	if fwd.AppliedGeneration != 42 {
		t.Fatalf("expected applied generation 42, got %d", fwd.AppliedGeneration)
	}
}

func TestRenderContainsKeyFields(t *testing.T) {
	view := v4View(9)
	fwd, _ := LookupForward(view, "cgn-pool", "100.64.0.5")
	var sb strings.Builder
	fwd.Render(&sb)
	out := sb.String()
	for _, want := range []string{"203.0.113.1", "3584-4095", "generation: 9"} {
		if !strings.Contains(out, want) {
			t.Fatalf("forward render missing %q:\n%s", want, out)
		}
	}
}

// v6View64 is v6View with a /64-configured subscriber prefix (#9070).
//
// The distinction is the whole point of the cells below: a /32-configured pool
// has wordOffset 4 and a /64 deterministic unit, a /64-configured pool has
// wordOffset 8 and a /96 unit. The two are never equal, so a fix that echoed
// the configured prefix would look right on one fixture and be wrong on this
// one.
func v6View64(gen uint64) AppliedView {
	pool := &config.NATPool{
		Name:      "napt64-pool64",
		Addresses: []string{"198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4"},
		Deterministic: &config.DeterministicNATConfig{
			BlockSize:   512,
			HostAddress: "2001:db8::/64",
		},
	}
	cfg := &config.Config{}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{"napt64-pool64": pool}
	cfg.Security.NAT.NAT64 = []*config.NAT64RuleSet{{
		Name:       "v6-to-v4-64",
		Prefix:     "64:ff9b::/96",
		SourcePool: "napt64-pool64",
	}}
	return AppliedView{Config: cfg, Generation: gen, Available: true}
}

// #9070: the reverse lookup returns the deterministic UNIT's network BASE, and
// must report that unit's prefix length so a bare address is not read as an
// exact /128.
//
// THE /64 ROW IS THE LOAD-BEARING ONE. The obvious annotation — echo the
// configured pool prefix — yields /64 there, and the true unit is a /96,
// because the unit is the configured prefix PLUS the reconstructed 32-bit
// subscriber word. An assertion that merely checked "a prefix length is
// present" would pass that confidently-wrong value.
func TestReverseReportsDeterministicUnitPrefixLen9070(t *testing.T) {
	// /32-configured pool -> wordOffset 4 -> /64 unit.
	rev, err := LookupReverse(v6View(1), "napt64-pool", "198.51.100.1", 3584)
	if err != nil {
		t.Fatalf("reverse (/32 pool): %v", err)
	}
	if rev.InternalPrefixLen != 64 {
		t.Fatalf("/32-configured pool: InternalPrefixLen = %d, want 64 (the unit, "+
			"= configured 32 + the 32-bit subscriber word)", rev.InternalPrefixLen)
	}

	// /64-configured pool -> wordOffset 8 -> /96 unit. NOT 64.
	rev64, err := LookupReverse(v6View64(1), "napt64-pool64", "198.51.100.1", 3584)
	if err != nil {
		t.Fatalf("reverse (/64 pool): %v", err)
	}
	if rev64.InternalPrefixLen == 64 {
		t.Fatalf("/64-configured pool reported /64 — that is the CONFIGURED pool " +
			"prefix echoed back, not the deterministic unit. The unit is a /96 " +
			"(configured 64 + the 32-bit subscriber word), and echoing the pool " +
			"prefix replaces an ambiguous answer with a confidently wrong one (#9070)")
	}
	if rev64.InternalPrefixLen != 96 {
		t.Fatalf("/64-configured pool: InternalPrefixLen = %d, want 96",
			rev64.InternalPrefixLen)
	}

	// IPv4 mode: an exact host, so no prefix at all.
	rev4, err := LookupReverse(v4View(1), "cgn-pool", "203.0.113.1", 3584)
	if err != nil {
		t.Fatalf("reverse (v4): %v", err)
	}
	if rev4.InternalPrefixLen != 0 {
		t.Fatalf("IPv4 mode: InternalPrefixLen = %d, want 0 — the value is an exact "+
			"host and must not acquire a prefix", rev4.InternalPrefixLen)
	}
}

// #9070: the rendered reverse output must carry the unit length, and must not
// present a network base under a label that reads as an exact host.
func TestReverseRenderShowsUnitPrefix9070(t *testing.T) {
	rev64, err := LookupReverse(v6View64(1), "napt64-pool64", "198.51.100.1", 3584)
	if err != nil {
		t.Fatalf("reverse: %v", err)
	}
	var b strings.Builder
	rev64.Render(&b)
	out := b.String()
	if !strings.Contains(out, "/96") {
		t.Fatalf("rendered reverse result must carry the /96 unit length:\n%s", out)
	}
	if strings.Contains(out, "Internal host:") {
		t.Fatalf("a reconstructed network BASE must not be rendered under \"Internal "+
			"host\", which reads as an exact /128:\n%s", out)
	}
	if !strings.Contains(out, "Internal prefix:") {
		t.Fatalf("expected the base to be labelled as a prefix:\n%s", out)
	}

	// CONTROL: the IPv4 reverse result is an exact host and keeps that label
	// with no prefix — a change that relabelled everything would pass the
	// assertions above while mislabelling real hosts.
	rev4, err := LookupReverse(v4View(1), "cgn-pool", "203.0.113.1", 3584)
	if err != nil {
		t.Fatalf("reverse v4: %v", err)
	}
	var b4 strings.Builder
	rev4.Render(&b4)
	out4 := b4.String()
	if !strings.Contains(out4, "Internal host:") {
		t.Fatalf("an IPv4 exact host must keep the host label:\n%s", out4)
	}
	if strings.Contains(out4, "/") && strings.Contains(out4, "Internal prefix:") {
		t.Fatalf("an IPv4 exact host must not acquire a prefix:\n%s", out4)
	}
}
