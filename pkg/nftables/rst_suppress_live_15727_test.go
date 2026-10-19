package nftables

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
)

// TestRSTSuppressionDropsConntracklessRSTLive15727 is the live-kernel
// counterpart of TestRSTDropExprsScopedToConntrackless14949 (#15727).
// The unit test pins the expression shape; this test proves the kernel
// actually evaluates it. It installs the real xpf_dp_rst table in a
// private netns, generates genuine kernel no-socket RSTs (TCP SYNs to
// the SNAT address with no listener, answered by tcp_v4_send_reset
// through a fresh control socket), and asserts the rule counter moves.
//
// Before the #15727 fix the rule matched `ct state & 0x4f == 0`, which
// nft_ct_get_eval can never satisfy (it always writes INVALID,
// UNTRACKED, or a tracked ctinfo bit), so the counter stayed at zero
// and this test fails. After the fix (match ct state invalid) the
// counter must reach >= 1.
//
// Needs CAP_NET_ADMIN for the netns; SKIPs otherwise (see
// enterPrivateNetns). Run with:
//
//	unshare -rn go test ./pkg/nftables/ -run TestRSTSuppressionDropsConntracklessRSTLive15727 -count=1 -v
func TestRSTSuppressionDropsConntracklessRSTLive15727(t *testing.T) {
	enterPrivateNetns(t)

	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatalf("lo link: %v", err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatalf("bring lo up: %v", err)
	}
	snat := netip.MustParseAddr("127.0.0.2")
	addr, err := netlink.ParseAddr(snat.String() + "/8")
	if err != nil {
		t.Fatalf("parse addr: %v", err)
	}
	addr.Scope = int(netlink.SCOPE_HOST)
	if err := netlink.AddrAdd(lo, addr); err != nil {
		t.Fatalf("assign %s to lo: %v", snat, err)
	}

	if err := InstallRSTSuppression([]netip.Addr{snat}, nil); err != nil {
		t.Fatalf("InstallRSTSuppression: %v", err)
	}
	before, err := rstDropPackets()
	if err != nil {
		t.Fatalf("read counter before: %v", err)
	}
	t.Logf("counter before: packets=%d", before)

	// SYN to a closed port on the SNAT address: no listener and no
	// conntrack entry exist, so the kernel emits precisely the spurious
	// no-socket RST this table exists to suppress. Repeat so a single
	// lost probe cannot flake the verdict.
	dst := net.JoinHostPort(snat.String(), "44999")
	for range 3 {
		c, err := net.DialTimeout("tcp4", dst, 500*time.Millisecond)
		if err == nil {
			_ = c.Close()
			t.Fatalf("dial %s unexpectedly succeeded (something is listening)", dst)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	var mid uint64
	for {
		mid, err = rstDropPackets()
		if err != nil {
			t.Fatalf("read counter after spurious RSTs: %v", err)
		}
		if mid > before || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("counter after spurious RSTs: packets=%d", mid)
	if mid <= before {
		t.Fatalf("rule counter did not move for conntrack-less RSTs: before=%d after=%d "+
			"— the ct predicate does not match the state nft_ct reports at OUTPUT (#15727)", before, mid)
	}

	// Negative control: a tracked, non-target RST must not be counted.
	// Abort a real connection with SO_LINGER 0 so the client emits a
	// RST belonging to a live socket; its source is the ephemeral
	// client address (the SNAT address is the destination), so it is
	// outside the rule's saddr scope as well as tracked. The counter
	// must stay exactly where the positive trigger left it.
	ln, err := net.Listen("tcp4", net.JoinHostPort(snat.String(), "44998"))
	if err != nil {
		t.Fatalf("listen for tracked control: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	cli, err := net.DialTimeout("tcp4", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial tracked control: %v", err)
	}
	if tc, ok := cli.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	_ = cli.Close()
	time.Sleep(300 * time.Millisecond)
	after, err := rstDropPackets()
	if err != nil {
		t.Fatalf("read counter after tracked RST: %v", err)
	}
	t.Logf("counter after tracked RST: packets=%d", after)
	if after != mid {
		t.Fatalf("counter moved for non-target traffic: mid=%d after=%d", mid, after)
	}
}

// rstDropPackets sums the packet counters of every rule in the
// xpf_dp_rst output chain.
func rstDropPackets() (uint64, error) {
	c, err := nftables.New()
	if err != nil {
		return 0, fmt.Errorf("nftables conn: %w", err)
	}
	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: rstTableName}
	chain := &nftables.Chain{Name: "output", Table: table}
	rules, err := c.GetRules(table, chain)
	if err != nil {
		return 0, fmt.Errorf("get rules: %w", err)
	}
	var total uint64
	found := false
	for _, r := range rules {
		for _, e := range r.Exprs {
			if ctr, ok := e.(*expr.Counter); ok {
				found = true
				total += ctr.Packets
			}
		}
	}
	if !found {
		return 0, fmt.Errorf("no counter expression in %d rules", len(rules))
	}
	return total, nil
}
