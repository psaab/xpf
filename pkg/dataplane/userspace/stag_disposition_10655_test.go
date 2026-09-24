package userspace

import (
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf"
)

// Behavioural coverage for #10655: a single-tagged 802.1ad S-tag (0x88a8)
// frame must NEVER be adjudicated as the 802.1Q unit with the same VID.
//
// WHAT. userspace-xdp/src/lib.rs::parse_l2 unwrapped 0x8100 and 0x88a8
// identically, the UserspaceDpMeta carried no TPID, and the workers keyed
// identity on (parent ifindex, VID) only — while the kernel side is
// 802.1Q-only. A frame from a trunk's native/untagged domain carrying an
// S-tag was therefore adjudicated in the ZONE of whichever tagged unit its
// VID named: VID 100 arriving S-tagged took unit .100's (C-tag) zone,
// filters, and session accounting.
//
// THE FIX UNDER TEST. A single outer 0x88a8 is an explicit XDP_DROP with a
// dedicated stag_drop reason (plus the transit_drop verdict all degraded
// drops carry), on the armed non-IP arm, the armed IP match (below the
// ingress-interface gate, per #8279), its unreachable-by-construction match
// twin, and the degraded-path arms. 802.1ad is 802.1Q-only on this box:
// there is no S-tag identity to steer by, so keying distinctly would only
// relocate the alias. QinQ taxonomy is unchanged: a DOUBLE tag with an 88a8
// outer still counts as qinq_drop (#9888), never stag_drop.
//
// HARNESS. Same BPF_PROG_TEST_RUN surface as qinq_disposition_9888_test.go
// (loadUserspaceXDPTestCollection + name-based degraded-path stat asserts).
// Memlock-gated like those cells: SKIP under `make test-go`, execute under
// `make test-memlock-guards` / `make test-root`, and wired into `make
// test-shim-run` by name. No new memlockcensus row: the RemoveMemlock call
// site is the shared loadUserspaceXDPTestCollection helper, already
// registered; the census scans call sites, not callers.
//
// RED-ON-BASE. Against the pre-fix object, S-tagged ARP returns XDP_PASS(2)
// instead of DROP; IP cells steer to the helper and fail the `stag_drop`
// counter assertion (the fixture's empty XSK map turns that steer into
// redirect_err + transit_drop). The C-tag separation controls pass on BOTH
// objects: they read the head-only stag_drop slot tolerantly.
//
// STRIPPING RESIDUAL (#10915). These cells cover an S-tag present in packet
// bytes. A separate S-tag RX-strip offload can remove the 0x88a8 header before
// XDP; the C-tag `rx-vlan-offload` fence (#5268/#9946) does not control it.

// singleTagIPv6UDP builds a single-tagged IPv6/UDP frame that parses clean
// through parse_ipv6/parse_l4, mirroring singleTagIPv4UDP (which lives in
// qinq_disposition_9888_test.go, same package) and icmpv6TestPacket's v6
// header shape with next-header UDP.
func singleTagIPv6UDP(tpid uint16, src, dst [16]byte) []byte {
	pkt := make([]byte, 128)
	copy(pkt[0:6], []byte{0x02, 0, 0, 0, 0, 1})
	copy(pkt[6:12], []byte{0x02, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(pkt[12:14], tpid)
	binary.BigEndian.PutUint16(pkt[14:16], 100) // TCI VID 100: SAME VID as the C-tag twin
	binary.BigEndian.PutUint16(pkt[16:18], 0x86dd)

	ip := pkt[18:58]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], 8)
	ip[6] = 17
	ip[7] = 64
	copy(ip[8:24], src[:])
	copy(ip[24:40], dst[:])

	udp := pkt[58:]
	binary.BigEndian.PutUint16(udp[0:2], 12345)
	binary.BigEndian.PutUint16(udp[2:4], 443)
	binary.BigEndian.PutUint16(udp[4:6], 8)
	return pkt
}

// stagDropCountTolerant reads the head-only stag_drop reason WITHOUT failing
// when the loaded object or the Go table predates it. The base 17-slot map
// has no index 17 (a lookup there ERRORS, it does not return zero) and the
// base Go table has no such name (degradedPathReasonIndex would t.Fatal), so
// the strict shared helpers cannot express "absent" across both objects.
// The drop cells do not need this (they fail at the action check on the base
// object before any stat assert); the separation controls use it so they mean
// the same thing on the base and the fixed object.
func stagDropCountTolerant(t *testing.T, coll *ebpf.Collection) uint64 {
	t.Helper()
	idx := -1
	for i, candidate := range degradedPathReasonNames {
		if candidate == "stag_drop" {
			idx = i
			break
		}
	}
	if idx < 0 {
		return 0 // base Go table: no such reason, so no S-tag accounting exists
	}
	stats := coll.Maps["userspace_fallback_stats"]
	if stats == nil {
		t.Fatal("userspace_fallback_stats compatibility map not loaded")
	}
	var perCPU []uint64
	if err := stats.Lookup(uint32(idx), &perCPU); err != nil {
		return 0 // base map: no slot 17, so no S-tag accounting exists
	}
	var got uint64
	for _, v := range perCPU {
		got += v
	}
	return got
}

// assertStagDropAbsentTolerant asserts the tolerant stag_drop count is zero,
// for controls that must pass on both the base and the fixed object.
func assertStagDropAbsentTolerant(t *testing.T, coll *ebpf.Collection, what string) {
	t.Helper()
	if got := stagDropCountTolerant(t, coll); got != 0 {
		t.Fatalf("%s: stag_drop = %d, want 0", what, got)
	}
}

func TestUserspaceXDPSTagSingleTagDropsAndCounts_10655(t *testing.T) {
	// Single-S-tagged ARP: explicit DROP, never the XDP_PASS a C-tagged
	// (or untagged) ARP takes. The kernel side is 802.1Q-only, so passing
	// it would hand an S-tag-domain frame to a stack with no S-tag unit.
	t.Run("arp", func(t *testing.T) {
		coll := loadUserspaceXDPTestCollection(t)
		updateUserspaceXDPTestCtrl(t, coll, userspaceCtrlValue{
			Enabled:            1,
			MetadataVersion:    userspaceMetadataVersion,
			Workers:            1,
			QueueCount:         1,
			HeartbeatTimeoutMS: 30000,
		})
		updateUserspaceXDPTestIngress(t, coll, userspaceXDPTestRunIfindex(t))

		ret := runUserspaceXDPTestPacket(t, coll, singleTagTestPacket(0x88a8, 0x0806))
		if ret != xdpActionDrop {
			t.Fatalf("single-S-tag ARP: action = %d, want XDP_DROP(%d)", ret, xdpActionDrop)
		}
		assertUserspaceXDPDegradedPathStat(t, coll, "stag_drop")
		assertUserspaceXDPDegradedPathStat(t, coll, "transit_drop")
		assertUserspaceXDPDegradedPathStatAbsent(t, coll, "pass_to_kernel")
	})

	// Single-S-tagged IPv4/UDP: explicit DROP, never steered to the
	// helper. Steering would stamp (parent, VID) metadata the workers
	// resolve to the C-tag unit — the zone confusion itself. The
	// redirect_err-absent assert is the steering negation: a steered
	// frame in this fixture (empty XSK map) errors the redirect.
	t.Run("ipv4-udp", func(t *testing.T) {
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
			0x88a8,
			[4]byte{198, 51, 100, 10},
			[4]byte{203, 0, 113, 20},
		))
		if ret != xdpActionDrop {
			t.Fatalf("single-S-tag IPv4 UDP: action = %d, want XDP_DROP(%d)", ret, xdpActionDrop)
		}
		assertUserspaceXDPDegradedPathStat(t, coll, "stag_drop")
		assertUserspaceXDPDegradedPathStat(t, coll, "transit_drop")
		assertUserspaceXDPDegradedPathStatAbsent(t, coll, "redirect_err")
	})

	// Single-S-tagged IPv6/UDP: the v6 twin of the cell above.
	t.Run("ipv6-udp", func(t *testing.T) {
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

		ret := runUserspaceXDPTestPacket(t, coll, singleTagIPv6UDP(
			0x88a8,
			[16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10},
			[16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20},
		))
		if ret != xdpActionDrop {
			t.Fatalf("single-S-tag IPv6 UDP: action = %d, want XDP_DROP(%d)", ret, xdpActionDrop)
		}
		assertUserspaceXDPDegradedPathStat(t, coll, "stag_drop")
		assertUserspaceXDPDegradedPathStat(t, coll, "transit_drop")
		assertUserspaceXDPDegradedPathStatAbsent(t, coll, "redirect_err")
	})
}

func TestUserspaceXDPSTagCTagSeparation_10655(t *testing.T) {
	// The SAME VID (100, the TCI every builder above stamps) under the
	// C-tag TPID keeps its verdicts: ARP takes the plain XDP_PASS and
	// IPv4 steers to the helper. These pass on the base object too (the
	// stag_drop reads are tolerant), so a RED here names a regression in
	// C-tag handling rather than the S-tag fix.
	coll := loadUserspaceXDPTestCollection(t)
	updateUserspaceXDPTestCtrl(t, coll, userspaceCtrlValue{
		Enabled:            1,
		MetadataVersion:    userspaceMetadataVersion,
		Workers:            1,
		QueueCount:         1,
		HeartbeatTimeoutMS: 30000,
	})
	updateUserspaceXDPTestIngress(t, coll, userspaceXDPTestRunIfindex(t))

	ret := runUserspaceXDPTestPacket(t, coll, singleTagTestPacket(0x8100, 0x0806))
	if ret != xdpActionPass {
		t.Fatalf("single-C-tag ARP (VID 100): action = %d, want XDP_PASS(%d)", ret, xdpActionPass)
	}
	assertUserspaceXDPDegradedPathStatAbsent(t, coll, "transit_drop")
	assertStagDropAbsentTolerant(t, coll, "single-C-tag ARP")

	coll = loadUserspaceXDPTestCollection(t)
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

	ret = runUserspaceXDPTestPacket(t, coll, singleTagIPv4UDP(
		0x8100,
		[4]byte{198, 51, 100, 10},
		[4]byte{203, 0, 113, 20},
	))
	if ret != xdpActionDrop {
		t.Fatalf("single-C-tag IPv4 UDP (VID 100): action = %d, want XDP_DROP(%d)", ret, xdpActionDrop)
	}
	assertUserspaceXDPDegradedPathStat(t, coll, "redirect_err")
	assertUserspaceXDPDegradedPathStat(t, coll, "transit_drop")
	assertStagDropAbsentTolerant(t, coll, "single-C-tag IPv4 UDP")
}

func TestUserspaceXDPSTagDegradedPathDrops_10655(t *testing.T) {
	// The degraded (ctrl-disabled) arms drop single-S-tag frames too.
	// With ctrl disabled the shim fails closed on every attached
	// interface; an S-tag must not find a PASS there that the armed path
	// denies.
	for _, tc := range []struct {
		name string
		pkt  func() []byte
	}{
		{"arp", func() []byte { return singleTagTestPacket(0x88a8, 0x0806) }},
		{"ipv4-udp", func() []byte {
			return singleTagIPv4UDP(0x88a8, [4]byte{198, 51, 100, 10}, [4]byte{203, 0, 113, 20})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			coll := loadUserspaceXDPTestCollection(t)
			updateUserspaceXDPTestCtrl(t, coll, userspaceCtrlValue{
				Enabled:            0,
				MetadataVersion:    userspaceMetadataVersion,
				Workers:            1,
				QueueCount:         1,
				HeartbeatTimeoutMS: 30000,
			})

			ret := runUserspaceXDPTestPacket(t, coll, tc.pkt())
			if ret != xdpActionDrop {
				t.Fatalf("degraded single-S-tag %s: action = %d, want XDP_DROP(%d)", tc.name, ret, xdpActionDrop)
			}
			assertUserspaceXDPDegradedPathStat(t, coll, "stag_drop")
			assertUserspaceXDPDegradedPathStat(t, coll, "transit_drop")
			assertUserspaceXDPDegradedPathStatAbsent(t, coll, "pass_to_kernel")
		})
	}
}

func TestUserspaceXDPSTagOuterDoubleTagStaysQinQ_10655(t *testing.T) {
	// Taxonomy pin: a DOUBLE tag with an 88a8 outer is still QinQ
	// (qinq_drop), never stag_drop. The S-tag verdict is for the SINGLE
	// outer shape only; nesting keeps its own counter so #9888's
	// "double-tagged is qinq_drop" invariant stays total.
	coll := loadUserspaceXDPTestCollection(t)
	updateUserspaceXDPTestCtrl(t, coll, userspaceCtrlValue{
		Enabled:            1,
		MetadataVersion:    userspaceMetadataVersion,
		Workers:            1,
		QueueCount:         1,
		HeartbeatTimeoutMS: 30000,
	})
	updateUserspaceXDPTestIngress(t, coll, userspaceXDPTestRunIfindex(t))

	ret := runUserspaceXDPTestPacket(t, coll, qinqTestPacket(0x88a8, 0x8100, 0x0800))
	if ret != xdpActionDrop {
		t.Fatalf("ad-over-q double tag: action = %d, want XDP_DROP(%d)", ret, xdpActionDrop)
	}
	assertUserspaceXDPDegradedPathStat(t, coll, "qinq_drop")
	assertStagDropAbsentTolerant(t, coll, "ad-over-q double tag")
}
