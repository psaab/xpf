package api

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16822 (R3-F08-05): deterministicPoolBlockCapacity /
// deterministicSubscriberCapacity hard-coded the NAT64 1024-65535 window
// for IPv6 subscribers, so the deterministic gauges overstated a
// range-limited NAT64 pool. #15283 made mode 2 honour the pool's own
// `port range` (default 1024-65535) in pkg/nat, the wire builder, and
// the Rust allocator; this gauge was the missed consumer.
//
// Probe (issue): pool 2000-3000 (1001 ports), block-size 100, IPv6
// host 2001:db8::/32 => pkg/nat blocksPerIP=10, gauge was 645.
//
// RED-on-revert: restoring `rangeForBlocks = 65535-1024+1` for
// ipv6Subscriber makes the SUBJECT cases report 645/1290 instead of
// 10/20 and this test fails.
func TestDeterministicPoolBlockCapacityMode2PoolPortRange16822(t *testing.T) {
	// SUBJECT: range-limited mode-2 pool — 1 bare /32 v4 host,
	// (3000-2000+1)/100 = 10 blocks.
	subject := &config.NATPool{
		Addresses: []string{"203.0.113.1"},
		PortLow:   2000,
		PortHigh:  3000,
		Deterministic: &config.DeterministicNATConfig{
			BlockSize:   100,
			HostAddress: "2001:db8::/32",
		},
	}
	if got := deterministicPoolBlockCapacity(subject, "p", nil); got != 10 {
		t.Fatalf("#16822 SUBJECT: deterministicPoolBlockCapacity = %d, want 10 (1001 ports / 100)", got)
	}
	if got := deterministicSubscriberCapacity(subject, "p", nil); got != 10 {
		t.Fatalf("#16822 SUBJECT: deterministicSubscriberCapacity (host_count) = %d, want 10", got)
	}

	// SUBJECT scaled: 2 counted mode-2 hosts => 20.
	subject2 := &config.NATPool{
		Addresses: []string{"203.0.113.1", "203.0.113.2"},
		PortLow:   2000,
		PortHigh:  3000,
		Deterministic: &config.DeterministicNATConfig{
			BlockSize:   100,
			HostAddress: "2001:db8::/32",
		},
	}
	if got := deterministicPoolBlockCapacity(subject2, "p", nil); got != 20 {
		t.Fatalf("#16822 SUBJECT x2: deterministicPoolBlockCapacity = %d, want 20", got)
	}
	if got := deterministicSubscriberCapacity(subject2, "p", nil); got != 20 {
		t.Fatalf("#16822 SUBJECT x2: deterministicSubscriberCapacity = %d, want 20", got)
	}

	// CONTROL: default range (no port range configured) is unchanged —
	// 64512/100 = 645 blocks per host (the 15177 mode-2 cell shape).
	ctrl := &config.NATPool{
		Addresses: []string{"203.0.113.1"},
		Deterministic: &config.DeterministicNATConfig{
			BlockSize:   100,
			HostAddress: "2001:db8::/32",
		},
	}
	if got := deterministicPoolBlockCapacity(ctrl, "p", nil); got != 645 {
		t.Fatalf("#16822 CONTROL: deterministicPoolBlockCapacity = %d, want 645 (64512/100)", got)
	}
	if got := deterministicSubscriberCapacity(ctrl, "p", nil); got != 645 {
		t.Fatalf("#16822 CONTROL: deterministicSubscriberCapacity = %d, want 645", got)
	}

	// Block size larger than the configured range => 0 (fail-closed,
	// mirrors pkg/nat mode-2 `block-size exceeds the NAT64 port range`).
	tooBig := &config.NATPool{
		Addresses: []string{"203.0.113.1"},
		PortLow:   2000,
		PortHigh:  3000,
		Deterministic: &config.DeterministicNATConfig{
			BlockSize:   2000,
			HostAddress: "2001:db8::/32",
		},
	}
	if got := deterministicPoolBlockCapacity(tooBig, "p", nil); got != 0 {
		t.Fatalf("#16822 block>range: deterministicPoolBlockCapacity = %d, want 0", got)
	}
	if got := deterministicSubscriberCapacity(tooBig, "p", nil); got != 0 {
		t.Fatalf("#16822 block>range: deterministicSubscriberCapacity = %d, want 0", got)
	}
}
