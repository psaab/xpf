package nat

import (
	"fmt"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// #9498: the Go deterministic-NAT reverse lookup multiplied in uint32. With
// block-size 1 and the default 1024-65535 range, blocksPerIP = 64512 and
// 2^32 = 64512*66576 + 16384, so pool index 66576 at block >= 16384 wrapped to
// subscriber index 0, below hostCount even for a /32 subscriber. The lookup
// returned the WRONG subscriber instead of failing closed. Every row compiles
// through the real strict commit gate (`configstore.CheckText`), and lookups run
// on exactly the config that gate returns.

func poolConfig9498(addresses ...string) string {
	s := "system { host-name p; }\nsecurity {\n    nat {\n        source {\n            pool WRAP {\n"
	for _, a := range addresses {
		s += "                address " + a + ";\n"
	}
	return s + "                port {\n                    deterministic {\n                        block-size 1;\n" +
		"                        host {\n                            address 100.64.0.0/32;\n                        }\n" +
		"                    }\n                }\n            }\n        }\n    }\n}\n"
}

func committedView9498(t *testing.T, addresses ...string) AppliedView {
	t.Helper()
	cfg, err := configstore.CheckText(poolConfig9498(addresses...), -1)
	if err != nil {
		t.Fatalf("precondition: the strict commit gate must ACCEPT this pool (it did before #9498): %v", err)
	}
	pool := cfg.Security.NAT.SourcePools["WRAP"]
	if pool == nil || pool.Deterministic == nil || pool.Deterministic.BlockSize != 1 {
		t.Fatalf("precondition: the pool must compile as deterministic with block-size 1, got %+v", pool)
	}
	return AppliedView{Config: cfg, Generation: 1, Available: true}
}

func mustFailClosed9498(t *testing.T, view AppliedView, ip string, port uint16, why string) {
	t.Helper()
	rev, err := LookupReverse(view, "WRAP", ip, port)
	if err == nil {
		t.Fatalf("#9498: reverse(%s:%d) must FAIL CLOSED (%s); it attributed the tuple to %q -- a wrapped uint32 "+
			"index landing inside the subscriber range", ip, port, why, rev.InternalHost)
	}
	if err.Code != ErrCodeNotFound {
		t.Fatalf("#9498: reverse(%s:%d) must fail with not-found, got %v", ip, port, err)
	}
}

// FAIL-ON-REVERT: the fewest-statements witness (/16 + /21).
func TestDeterministicReverseDoesNotWrapToASubscriber9498(t *testing.T) {
	view := committedView9498(t, "10.0.0.0/16", "10.1.0.0/21")
	// idx 66576 (10.1.4.16), block 16384: the first index whose uint32 product wraps.
	mustFailClosed9498(t, view, "10.1.4.16", 17408, "pool index 66576, block 16384")
	// idx 66575, largest block: the largest product that does NOT wrap. Fail-closed before and after.
	mustFailClosed9498(t, view, "10.1.4.15", 65535, "the largest non-wrapping product")

	// NON-REGRESSION: the real mapping still resolves, so the fix did not simply refuse everything.
	rev, err := LookupReverse(view, "WRAP", "10.0.0.0", 1024)
	if err != nil || rev.InternalHost != "100.64.0.0" {
		t.Fatalf("#9498: the subscriber's REAL block 10.0.0.0:1024 must still reverse to 100.64.0.0; got rev=%+v err=%v", rev, err)
	}
	fwd, ferr := LookupForward(view, "WRAP", "100.64.0.0")
	if ferr != nil || fwd.ExternalIP != "10.0.0.0" || fwd.PortLow != 1024 {
		t.Fatalf("#9498: forward(100.64.0.0) must still be 10.0.0.0:1024; got fwd=%+v err=%v", fwd, ferr)
	}
}

// FAIL-ON-REVERT: the fewest-addresses witness (66,577 = /16 + /22 + /28 + /32).
func TestDeterministicReverseDoesNotWrapAtTheMinimumPool9498(t *testing.T) {
	view := committedView9498(t, "10.0.0.0/16", "10.1.0.0/22", "10.1.4.0/28", "10.1.5.0/32")
	mustFailClosed9498(t, view, "10.1.5.0", 17408, "the /32 is pool index 66576")
}

// CONTROL: one address short (66,576). No index reaches 66576, so it never wrapped.
func TestDeterministicReverseOneAddressShortNeverWrapped9498(t *testing.T) {
	view := committedView9498(t, "10.0.0.0/16", "10.1.0.0/22", "10.1.4.0/28")
	mustFailClosed9498(t, view, "10.1.4.15", 65535, "the pool's last index at its last block")
	mustFailClosed9498(t, view, "10.1.4.15", 17408, "the pool's last index")
}

// ModeV6 (NAPT64): the capacity product len(pool) x blocks_per_ip must not wrap.
// 66,577 x 64,512 overflows uint32; the Rust dataplane downgrades that pool to
// round-robin, so Go must report it NOT deterministic rather than answer on a
// wrapped capacity.
func nat64View9498(n int) AppliedView {
	addrs := make([]string, n)
	for i := 0; i < n; i++ {
		addrs[i] = fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff)
	}
	pool := &config.NATPool{
		Name:      "p64",
		Addresses: addrs,
		Deterministic: &config.DeterministicNATConfig{
			BlockSize:   1,
			HostAddress: "2001:db8::/32",
		},
	}
	cfg := &config.Config{}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{"p64": pool}
	cfg.Security.NAT.NAT64 = []*config.NAT64RuleSet{{Name: "rs", Prefix: "64:ff9b::/96", SourcePool: "p64"}}
	return AppliedView{Config: cfg, Generation: 1, Available: true}
}

func TestDeterministicNAT64CapacityPastUint32IsNotDeterministic9498(t *testing.T) {
	_, err := LookupForward(nat64View9498(66577), "p64", "2001:db8::")
	if err == nil || err.Code != ErrCodeNotDeterministic {
		t.Fatalf("#9498: a NAT64 pool of 66,577 addresses at 64,512 blocks overflows uint32 capacity; the dataplane "+
			"downgrades it, so Go must report it NOT deterministic, got err=%v", err)
	}
	// CONTROL: 66,576 x 64,512 = 4,294,950,912 fits, and must stay deterministic.
	if _, err := LookupForward(nat64View9498(66576), "p64", "2001:db8::"); err != nil {
		t.Fatalf("#9498 control: 66,576 addresses fit the 32-bit capacity and must stay deterministic, got %v", err)
	}
}
