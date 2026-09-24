package userspace

import (
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf"
)

// Behavioural coverage for #9888/#10657: nested and legacy-tagged frames with
// a complete L2 header must be dropped-and-counted by the shim, never
// XDP_PASSed to the kernel. (A runt truncating inside the tag takes
// parse_l2's None path and carries no L3 payload, so no transit rides
// that shape — it is out of this contract.)
//
// WHY THIS EXISTS. userspace-xdp/src/lib.rs::parse_l2 unwraps exactly ONE
// 0x8100/0x88a8 tag. A nested tag therefore leaves its TPID as eth_proto;
// 0x9100/0x9200/0x9300 legacy outer tags are never unwrapped. Without
// recognition, these non-IP shapes took the pass_non_ip_l2_direct XDP_PASS
// arm ABOVE the ingress-ifindex gate — an unadjudicated handoff to the
// kernel. While ARMED the kernel forward path is deliberately open and
// unfiltered (pkg/nftables/transit_barrier.go: the forward-hook DROP is
// scoped strictly to the unarmed window), and on a bridged port the bridge
// forwards by MAC irrespective of ethertype: zone policy, screens, and
// session accounting never see the frame. The #5879 gate refuses QinQ
// CONFIGS, not frames.
//
// THE FIX UNDER TEST. A post-unwrap TPID still in the VLAN set (0x8100/
// 0x88a8/0x9100/0x9200/0x9300) is an explicit XDP_DROP via
// drop_degraded_transit with the qinq_drop reason, plus the transit_drop
// verdict all degraded drops carry. No unwrap loop (the single `if` stays,
// keeping verifier cost flat). Applied on the armed non-IP arm, its
// unreachable-by-construction match twin, and the degraded-path non-IP arm,
// so the invariant is total for complete-L2-header frames: the shim never
// XDP_PASSes a nested or legacy-tagged VLAN frame on any path.
//
// HARNESS. Same BPF_PROG_TEST_RUN surface as xdp_shim_decouple_test.go
// (loadUserspaceXDPTestCollection + name-based degraded-path stat asserts),
// which these cells reuse. Memlock-gated like those cells: they SKIP under
// `make test-go` and execute under `make test-memlock-guards` / `make
// test-root`. They are additionally wired into `make test-shim-run` by name
// (predicate + census over this file), so a rename that orphaned them from
// the gate reds instead of going silently invisible (#9052 shape). No new
// memlockcensus row is needed: the RemoveMemlock call site is the shared
// loadUserspaceXDPTestCollection helper, already registered; the census
// scans call sites, not callers.
//
// RED-ON-BASE. The #9888 rows fail against their pre-fix object; the #10657
// 0x9200/0x9300 rows fail against the pre-#10657 object. Each regression
// fails at the action check: the frame returns XDP_PASS(2), without the
// qinq_drop reason. The unchanged-behaviour controls pass on BOTH objects:
// they assert shared-baseline counters (slots 0-15, present in both maps)
// strictly and read the head-only qinq_drop slot tolerantly —
// qinqDropCountTolerant treats a missing slot 16 as zero rather than
// fataling the way the strict helpers do on a lookup error. The #10657
// red is reproduced by using the tracked pre-fix object; controls remain
// green against it.
//
// DISCLOSED COST (see is_vlan_tpid). A single legacy-TPID outer
// (0x9100/0x9200/0x9300) may hide ARP/LLDP the shim never unwraps; dropping
// it fail-closed denies that L2 to the kernel on XDP-bound ports. Passing
// an opaque shape unadjudicated on bridged ports is the hole, so the drop
// stands — but it is a behaviour change for those tagged segments, stated
// here rather than buried.

// qinqTestPacket builds dst/src MAC + outer TPID/TCI + inner TPID/TCI +
// inner ethertype + zero body. The body is never parsed: the shim drops at
// the L2 arm before any L3 read.
func qinqTestPacket(outerTPID, innerTPID, innerEthertype uint16) []byte {
	pkt := make([]byte, 128)
	copy(pkt[0:6], []byte{0x02, 0, 0, 0, 0, 1})
	copy(pkt[6:12], []byte{0x02, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(pkt[12:14], outerTPID)
	binary.BigEndian.PutUint16(pkt[14:16], 100) // outer TCI VID 100
	binary.BigEndian.PutUint16(pkt[16:18], innerTPID)
	binary.BigEndian.PutUint16(pkt[18:20], 200) // inner TCI VID 200
	binary.BigEndian.PutUint16(pkt[20:22], innerEthertype)
	return pkt
}

// singleTagTestPacket builds dst/src MAC + one TPID/TCI + ethertype + zero
// body. With tpid 0x9100 this is the legacy outer shape the shim never
// unwraps (so it arrives at the non-IP arm as eth_proto 0x9100).
func singleTagTestPacket(tpid, ethertype uint16) []byte {
	pkt := make([]byte, 128)
	copy(pkt[0:6], []byte{0x02, 0, 0, 0, 0, 1})
	copy(pkt[6:12], []byte{0x02, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(pkt[12:14], tpid)
	binary.BigEndian.PutUint16(pkt[14:16], 100) // TCI VID 100
	binary.BigEndian.PutUint16(pkt[16:18], ethertype)
	return pkt
}

// singleTagIPv4UDP builds a single-tagged IPv4/UDP frame that parses clean
// through parse_ipv4/parse_l4, so it must steer past L2 exactly as an
// untagged frame does — the guard against a predicate that tests the OUTER
// ethertype and would catch every single-tagged frame.
func singleTagIPv4UDP(tpid uint16, src, dst [4]byte) []byte {
	pkt := make([]byte, 128)
	copy(pkt[0:6], []byte{0x02, 0, 0, 0, 0, 1})
	copy(pkt[6:12], []byte{0x02, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(pkt[12:14], tpid)
	binary.BigEndian.PutUint16(pkt[14:16], 100)
	binary.BigEndian.PutUint16(pkt[16:18], 0x0800)

	ip := pkt[18:38]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)+8))
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], src[:])
	copy(ip[16:20], dst[:])

	udp := pkt[38:]
	binary.BigEndian.PutUint16(udp[0:2], 12345)
	binary.BigEndian.PutUint16(udp[2:4], 443)
	binary.BigEndian.PutUint16(udp[4:6], 8)
	return pkt
}

// qinqDropCountTolerant reads the head-only qinq_drop reason WITHOUT failing
// when the loaded object predates it. The base 16-slot map has no index 16,
// and a lookup there ERRORS (it does not return zero), so the strict shared
// helpers — which t.Fatal on a lookup error — cannot express "absent"
// across both objects. The drop cells do not need this (they fail at the
// action check on the base object before any stat assert); the
// unchanged-behaviour controls use it so they mean the same thing on the
// 16-slot base map and the 17-slot fixed map.
func qinqDropCountTolerant(t *testing.T, coll *ebpf.Collection) uint64 {
	t.Helper()
	stats := coll.Maps["userspace_fallback_stats"]
	if stats == nil {
		t.Fatal("userspace_fallback_stats compatibility map not loaded")
	}
	idx := degradedPathReasonIndex(t, "qinq_drop")
	var perCPU []uint64
	if err := stats.Lookup(idx, &perCPU); err != nil {
		return 0 // base map: no slot 16, so no QinQ accounting exists
	}
	var got uint64
	for _, v := range perCPU {
		got += v
	}
	return got
}

// assertQinqDropAbsentTolerant asserts the tolerant qinq_drop count is zero,
// for controls that must pass on both the base and the fixed object.
func assertQinqDropAbsentTolerant(t *testing.T, coll *ebpf.Collection, what string) {
	t.Helper()
	if got := qinqDropCountTolerant(t, coll); got != 0 {
		t.Fatalf("%s: qinq_drop = %d, want 0", what, got)
	}
}

func TestUserspaceXDPQinQDoubleTagDropsAndCounts_9888(t *testing.T) {
	shapes := []struct {
		name          string
		outer, inner  uint16
		payload       uint16
		singleTagOnly bool // legacy outer: one tag, never unwrapped
	}{
		{name: "q-in-q", outer: 0x8100, inner: 0x8100, payload: 0x0800},
		{name: "ad-over-q", outer: 0x88a8, inner: 0x8100, payload: 0x0800},
		{name: "q-over-ad", outer: 0x8100, inner: 0x88a8, payload: 0x86dd},
		{name: "ad-over-ad", outer: 0x88a8, inner: 0x88a8, payload: 0x0800},
		{name: "legacy-9100-inner", outer: 0x8100, inner: 0x9100, payload: 0x0800},
		{name: "ad-9100-inner", outer: 0x88a8, inner: 0x9100, payload: 0x0800},
		{name: "legacy-9100-outer", outer: 0x9100, payload: 0x0800, singleTagOnly: true},
		{name: "legacy-9200-inner", outer: 0x8100, inner: 0x9200, payload: 0x0800},
		{name: "ad-9200-inner", outer: 0x88a8, inner: 0x9200, payload: 0x0800},
		{name: "legacy-9300-inner", outer: 0x8100, inner: 0x9300, payload: 0x0800},
		{name: "ad-9300-inner", outer: 0x88a8, inner: 0x9300, payload: 0x0800},
		{name: "legacy-9200-outer", outer: 0x9200, payload: 0x0800, singleTagOnly: true},
		{name: "legacy-9300-outer", outer: 0x9300, payload: 0x0800, singleTagOnly: true},
	}
	for _, sh := range shapes {
		t.Run(sh.name, func(t *testing.T) {
			coll := loadUserspaceXDPTestCollection(t)
			updateUserspaceXDPTestCtrl(t, coll, userspaceCtrlValue{
				Enabled:            1,
				MetadataVersion:    userspaceMetadataVersion,
				Workers:            1,
				QueueCount:         1,
				HeartbeatTimeoutMS: 30000,
			})
			// Bound-port premise: the arrival interface IS in the ingress
			// set. The non-IP arm sits above the gate, so the gate cannot
			// be the variable under test; seeding it proves the drop
			// holds on a bound (bridged) port rather than via gate
			// rejection (which is silent — no counter — in any case).
			updateUserspaceXDPTestIngress(t, coll, userspaceXDPTestRunIfindex(t))

			var pkt []byte
			if sh.singleTagOnly {
				pkt = singleTagTestPacket(sh.outer, sh.payload)
			} else {
				pkt = qinqTestPacket(sh.outer, sh.inner, sh.payload)
			}
			ret := runUserspaceXDPTestPacket(t, coll, pkt)
			if ret != xdpActionDrop {
				t.Fatalf("%s: action = %d, want XDP_DROP(%d)", sh.name, ret, xdpActionDrop)
			}
			assertUserspaceXDPDegradedPathStat(t, coll, "qinq_drop")
			assertUserspaceXDPDegradedPathStat(t, coll, "transit_drop")
			assertUserspaceXDPDegradedPathStatAbsent(t, coll, "pass_to_kernel")
		})
	}
}

func TestUserspaceXDPQinQSingleTagBehaviorUnchanged_9888(t *testing.T) {
	// Single C-tagged ARP still takes plain XDP_PASS: the QinQ predicate
	// tests post-unwrap ethertype, and one tag unwraps to ARP. S-tags are
	// explicit drops under #10655; paired S-tag cells live in their own file.
	for _, tpid := range []uint16{0x8100} {
		coll := loadUserspaceXDPTestCollection(t)
		updateUserspaceXDPTestCtrl(t, coll, userspaceCtrlValue{
			Enabled:            1,
			MetadataVersion:    userspaceMetadataVersion,
			Workers:            1,
			QueueCount:         1,
			HeartbeatTimeoutMS: 30000,
		})
		updateUserspaceXDPTestIngress(t, coll, userspaceXDPTestRunIfindex(t))

		ret := runUserspaceXDPTestPacket(t, coll, singleTagTestPacket(tpid, 0x0806))
		if ret != xdpActionPass {
			t.Fatalf("single-tagged ARP (tpid %#04x): action = %d, want XDP_PASS(%d)", tpid, ret, xdpActionPass)
		}
		// Shared baseline (slots 0-15) asserted strictly; the head-only
		// qinq_drop slot read tolerantly so this control passes on the
		// 16-slot base map too.
		assertUserspaceXDPDegradedPathStatAbsent(t, coll, "transit_drop")
		assertQinqDropAbsentTolerant(t, coll, "single-tagged ARP")
	}

	// Single C-tagged IPv4 UDP still steers to the userspace helper. The
	// XSK map is empty in the fixture, so the redirect errors — measured
	// as XDP_DROP with redirect_err + transit_drop, the same disposition
	// as an untagged transit frame — and it is NOT a QinQ drop. S-tags now
	// have their own explicit drop disposition (#10655), covered by the
	// S-tag cells in stag_disposition_10655_test.go.
	for _, tpid := range []uint16{0x8100} {
		coll := loadUserspaceXDPTestCollection(t)
		updateUserspaceXDPTestCtrl(t, coll, userspaceCtrlValue{
			Enabled:            1,
			MetadataVersion:    userspaceMetadataVersion,
			Workers:            1,
			QueueCount:         1,
			HeartbeatTimeoutMS: 30000,
		})
		updateUserspaceXDPTestIngress(t, coll, userspaceXDPTestRunIfindex(t))
		updateUserspaceXDPTestBinding(t, coll, userspaceXDPTestRunBindingIndex(t, 0), userspaceBindingValue{
			Slot:  0,
			Flags: userspaceBindingReady,
		})
		updateUserspaceXDPTestHeartbeat(t, coll, 0)

		ret := runUserspaceXDPTestPacket(t, coll, singleTagIPv4UDP(
			tpid,
			[4]byte{198, 51, 100, 10},
			[4]byte{203, 0, 113, 20},
		))
		if ret != xdpActionDrop {
			t.Fatalf("single-tagged IPv4 UDP (tpid %#04x): action = %d, want XDP_DROP(%d)", tpid, ret, xdpActionDrop)
		}
		assertUserspaceXDPDegradedPathStat(t, coll, "redirect_err")
		assertUserspaceXDPDegradedPathStat(t, coll, "transit_drop")
		assertQinqDropAbsentTolerant(t, coll, "single-tagged IPv4 UDP")
	}
}

func TestUserspaceXDPQinQDegradedPathDrops_9888(t *testing.T) {
	// The degraded (ctrl-disabled) non-IP arm drops nested and legacy-tagged
	// VLAN frames too. This is fail-closed on shapes the shim cannot
	// adjudicate (#5879 refuses QinQ configs, so no stacked identity exists)
	// — including, as a disclosed cost, single legacy-TPID outers that may
	// hide ARP/LLDP the shim never unwraps. (Degraded ARP PASS is pinned by
	// TestUserspaceXDPDegradedNonIPL2PassesDirect and is not re-asserted here.)
	shapes := []struct {
		name          string
		outer, inner  uint16
		payload       uint16
		singleTagOnly bool
	}{
		{name: "q-in-q", outer: 0x8100, inner: 0x8100, payload: 0x0800},
		{name: "ad-over-ad", outer: 0x88a8, inner: 0x88a8, payload: 0x0800},
		{name: "legacy-9100-inner", outer: 0x8100, inner: 0x9100, payload: 0x0800},
		{name: "legacy-9100-outer", outer: 0x9100, payload: 0x0800, singleTagOnly: true},
		{name: "legacy-9200-inner", outer: 0x8100, inner: 0x9200, payload: 0x0800},
		{name: "ad-9200-inner", outer: 0x88a8, inner: 0x9200, payload: 0x0800},
		{name: "legacy-9300-inner", outer: 0x8100, inner: 0x9300, payload: 0x0800},
		{name: "ad-9300-inner", outer: 0x88a8, inner: 0x9300, payload: 0x0800},
		{name: "legacy-9200-outer", outer: 0x9200, payload: 0x0800, singleTagOnly: true},
		{name: "legacy-9300-outer", outer: 0x9300, payload: 0x0800, singleTagOnly: true},
	}
	for _, sh := range shapes {
		t.Run(sh.name, func(t *testing.T) {
			coll := loadUserspaceXDPTestCollection(t)
			updateUserspaceXDPTestCtrl(t, coll, userspaceCtrlValue{
				Enabled:            0,
				QueueCount:         1,
				HeartbeatTimeoutMS: 30000,
			})

			var pkt []byte
			if sh.singleTagOnly {
				pkt = singleTagTestPacket(sh.outer, sh.payload)
			} else {
				pkt = qinqTestPacket(sh.outer, sh.inner, sh.payload)
			}
			ret := runUserspaceXDPTestPacket(t, coll, pkt)
			if ret != xdpActionDrop {
				t.Fatalf("degraded %s: action = %d, want XDP_DROP(%d)", sh.name, ret, xdpActionDrop)
			}
			assertUserspaceXDPDegradedPathStat(t, coll, "qinq_drop")
			assertUserspaceXDPDegradedPathStat(t, coll, "transit_drop")
			assertUserspaceXDPDegradedPathStatAbsent(t, coll, "pass_to_kernel")
		})
	}
}
