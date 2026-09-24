package userspace

import (
	"encoding/binary"
	"os"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// Behavioural coverage for the non-first-fragment handling #7494 is about.
//
// WHY THIS EXISTS. Until now the shim's control flow had NO executable test
// surface at all: every test in the tree is either a source-text census in Go
// or a pure module `#[path]`-included into userspace-dp. The verifier gate
// (#1864) is a HEADROOM instrument, not a correctness one, so two distinct
// wrong implementations of the #7494 fix both PASS it:
//
//   - having `parse_ipv6` decline a fragment, which lands on
//     `drop_degraded_transit` and blackholes every legitimate fragment;
//   - hoisting the fragment guard into `if !native_gre && !frag`, which routes
//     non-native-GRE fragments into the native-GRE inner classifier.
//
// Neither is distinguishable from a correct fix by anything that existed
// before this file. These cells run the REAL program via BPF_PROG_TEST_RUN
// against synthetic frames and read back the disposition.
//
// ROOT. Loading a BPF program needs privilege, so these skip unprivileged.
// `make test-go` therefore does NOT run them -- `make test-shim-run` does.
// A skip is a result that looks exactly like a pass, so the skip message says
// so, and the instrument-validation cells below exist to keep a green run from
// being mistaken for a covered one.
//
// READING THE DISPOSITION. The XDP return code alone is NOT a discriminator:
// the xsk map is empty here, so a successful redirect falls back and returns
// XDP_PASS just like several other paths. The per-CPU `userspace_fallback_stats`
// reason counters are what separate them:
//
//	REDIRECT_ERR  reached the XSK redirect -- i.e. handed to the userspace
//	              helper, which is the CORRECT disposition for a fragment
//	PASS_TO_KERNEL  diverted to the kernel by a session-table hit
//	PARSE_FAIL      dropped by drop_degraded_transit
//
// Note that the ingress-iface gate returns XDP_PASS with NO counter at all, so
// "no reasons" is ambiguous between "clean redirect" and "rejected at the iface
// gate". That ambiguity produced a false negative during development -- the
// session-collision cell reported the exposure as unreachable when in fact the
// packet had never reached the session lookup. spikeLoad maps a range of
// ifindexes precisely so that gate is never the variable under test.

const (
	fragMetaVersion = 4
	fragSlot        = 0
	fragIfaceRange  = 64
)

var fragReasons = map[int]string{
	0: "CTRL_DISABLED", 1: "PARSE_FAIL", 2: "BINDING_MISSING", 3: "BINDING_NOT_READY",
	4: "HEARTBEAT_MISSING", 5: "HEARTBEAT_STALE", 6: "ICMP", 7: "EARLY_FILTER",
	8: "ADJUST_META", 9: "META_BOUNDS", 10: "REDIRECT_ERR", 11: "INTERFACE_NAT_NO_SESSION",
	12: "NO_SESSION", 13: "STRICT_DROP", 14: "PASS_TO_KERNEL", 15: "TRANSIT_DROP",
}

type fragSessionKey struct {
	AddrFamily uint8
	Protocol   uint8
	Pad        uint16
	SrcPort    uint16
	DstPort    uint16
	SrcAddr    [16]byte
	DstAddr    [16]byte
}

func fragLoad(t *testing.T) *ebpf.Collection {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("SKIPPED, NOT PASSED: loading a BPF program needs root. " +
			"`make test-go` never runs this file; use `make test-shim-run`. " +
			"A green `make test-go` is NOT evidence that fragment handling is covered.")
	}
	spec, err := ebpf.LoadCollectionSpec("../userspace_xdp_bpfel.o")
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("load collection: %v", err)
	}
	t.Cleanup(coll.Close)

	ctrl := userspaceCtrlValue{
		Enabled: 1, MetadataVersion: fragMetaVersion,
		Workers: 1, QueueCount: 1, HeartbeatTimeoutMS: 100000,
	}
	if err := coll.Maps["userspace_ctrl"].Put(uint32(0), &ctrl); err != nil {
		t.Fatalf("ctrl: %v", err)
	}
	// See the ambiguity note above: the iface gate is silent, so it must never
	// be the variable. Same for the binding gate.
	for idx := uint32(0); idx < fragIfaceRange; idx++ {
		if err := coll.Maps["userspace_ingress_ifaces"].Put(idx, uint8(1)); err != nil {
			t.Fatalf("ingress_ifaces[%d]: %v", idx, err)
		}
	}
	bv := userspaceBindingValue{Slot: fragSlot, Flags: userspaceBindingReady}
	for i := uint32(0); i < fragIfaceRange*bindingQueuesPerIface; i++ {
		if err := coll.Maps["userspace_bindings"].Put(i, &bv); err != nil {
			t.Fatalf("bindings[%d]: %v", i, err)
		}
	}
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		t.Fatalf("clock: %v", err)
	}
	now := uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
	if err := coll.Maps["userspace_heartbeat"].Put(uint32(fragSlot), now); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	return coll
}

// fragStats sums the per-CPU reason counters. A lookup failure is FATAL rather
// than skipped: an empty reason set is a meaningful observation here, so it
// must not also be what a broken read produces.
func fragStats(t *testing.T, coll *ebpf.Collection) map[string]uint64 {
	t.Helper()
	m := coll.Maps["userspace_fallback_stats"]
	out := map[string]uint64{}
	for i := 0; i < len(fragReasons); i++ {
		var vals []uint64
		if err := m.Lookup(uint32(i), &vals); err != nil {
			t.Fatalf("fallback_stats lookup(%d): %v -- the instrument is dead, and "+
				"an empty reason set would be indistinguishable from a clean run", i, err)
		}
		var sum uint64
		for _, v := range vals {
			sum += v
		}
		if sum > 0 {
			out[fragReasons[i]] = sum
		}
	}
	return out
}

func fragDelta(before, after map[string]uint64) map[string]uint64 {
	d := map[string]uint64{}
	for k, v := range after {
		if x := v - before[k]; x > 0 {
			d[k] = x
		}
	}
	return d
}

// fragRun executes the real program. No Context is passed: for XDP the kernel
// derives data/data_end from Data, and a zeroed ctx_in clobbers them so the
// frame stops parsing at parse_l2 -- which returns XDP_PASS with no counter and
// is therefore invisible. That cost real debugging time; do not add one back
// without setting data/data_end.
func fragRun(t *testing.T, coll *ebpf.Collection, pkt []byte) (uint32, map[string]uint64) {
	t.Helper()
	before := fragStats(t, coll)
	ret, err := coll.Programs["xdp_userspace_prog"].Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("prog run: %v", err)
	}
	return ret, fragDelta(before, fragStats(t, coll))
}

// ipv4Frame builds ethernet+IPv4+TCP. fragOff is the raw flags+offset field:
// 0 = not a fragment, a non-zero OFFSET = a non-first fragment.
func ipv4Frame(fragOff uint16) []byte {
	p := make([]byte, 128)
	p[12], p[13] = 0x08, 0x00
	ip := p[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(len(p)-14))
	binary.BigEndian.PutUint16(ip[6:], fragOff)
	ip[8] = 64
	ip[9] = unix.IPPROTO_TCP
	copy(ip[12:16], []byte{10, 0, 1, 50})
	copy(ip[16:20], []byte{10, 0, 2, 60})
	l4 := p[34:]
	binary.BigEndian.PutUint16(l4[0:], 12345)
	binary.BigEndian.PutUint16(l4[2:], 443)
	// parse_l4 REQUIRES (byte 12 >> 4)*4 >= 20 for TCP. On a NON-FIRST fragment
	// this byte is PAYLOAD, which is what
	// TestNonFirstFragmentDispositionDependsOnPayloadBytes_7494 exploits.
	l4[12] = 0x50
	return p
}

func fragSessionKeyFor(srcPort, dstPort uint16) fragSessionKey {
	var src, dst [16]byte
	copy(src[:], []byte{10, 0, 1, 50})
	copy(dst[:], []byte{10, 0, 2, 60})
	return fragSessionKey{
		AddrFamily: 2, Protocol: unix.IPPROTO_TCP,
		SrcPort: srcPort, DstPort: dstPort, SrcAddr: src, DstAddr: dst,
	}
}

// TestFragmentHarnessInstrumentIsAlive is the known-answer control. An empty
// reason set is a legitimate observation elsewhere in this file, and it is also
// what a dead counter read produces. Driving a case whose reason is known a
// priori -- ctrl.enabled = 0 must report CTRL_DISABLED -- separates them. If
// this cell cannot produce a non-empty reason set, every other cell is VOID.
func TestFragmentHarnessInstrumentIsAlive(t *testing.T) {
	coll := fragLoad(t)
	ctrl := userspaceCtrlValue{Enabled: 0, MetadataVersion: fragMetaVersion}
	if err := coll.Maps["userspace_ctrl"].Put(uint32(0), &ctrl); err != nil {
		t.Fatalf("ctrl: %v", err)
	}
	ret, d := fragRun(t, coll, ipv4Frame(0))
	t.Logf("ctrl-disabled -> ret=%d reasons=%v", ret, d)
	if d["CTRL_DISABLED"] == 0 {
		t.Fatalf("CTRL_DISABLED did not increment (reasons=%v). The reason "+
			"counters are not observable, so an empty reason set proves nothing "+
			"and every other cell in this file is VOID rather than green", d)
	}
}

// TestFragmentSessionPlantingIsObservable is the known-positive control for
// the collision cell below. That cell plants a session and looks for a change
// in disposition; "no change" is ambiguous between "the collision is
// unreachable" and "no session would EVER match because the key layout is
// wrong". This drives the case that MUST match -- an ordinary non-fragment
// whose real ports are the planted ones.
//
// This control earned its place: it failed during development and correctly
// invalidated a "the exposure is not reachable" result that was really a
// harness defect.
func TestFragmentSessionPlantingIsObservable(t *testing.T) {
	coll := fragLoad(t)
	key := fragSessionKeyFor(12345, 443)
	if err := coll.Maps["userspace_sessions"].Put(&key, uint8(2)); err != nil {
		t.Fatalf("plant: %v", err)
	}
	ret, d := fragRun(t, coll, ipv4Frame(0)) // NOT a fragment: ports are real
	t.Logf("non-fragment + planted PASS_TO_KERNEL session -> ret=%d reasons=%v", ret, d)
	if d["PASS_TO_KERNEL"] == 0 {
		t.Fatalf("a planted session did NOT take effect on a NON-fragment whose "+
			"real ports match the key (reasons=%v). The key layout or byte order "+
			"is wrong, so a negative result from the collision cell would be VOID "+
			"rather than evidence of anything", d)
	}
}

// TestNonFirstFragmentIsAdjudicatedByPayloadKeyedSession_7494 demonstrates the
// first exposure #7494 lists: `live_userspace_session_action` is keyed on
// ports, and for a non-first fragment those "ports" are the first four bytes of
// fragment PAYLOAD. A collision with a live PASS_TO_KERNEL session hands the
// fragment to the kernel instead of the userspace helper.
//
// This cell was written as characterization of the DEFECT and has been
// re-pointed now that #7494's IPv4 half has landed. It previously asserted the
// fragment WAS diverted to the kernel; it now asserts it is not. The history
// matters: the exposure was demonstrated before it was fixed, so this is a
// regression test with a measured red behind it rather than an assertion
// written after the fact.
func TestNonFirstFragmentIsAdjudicatedByPayloadKeyedSession_7494(t *testing.T) {
	coll := fragLoad(t)
	frag := ipv4Frame(0x00b9) // offset 185 -> a NON-FIRST fragment

	retControl, dControl := fragRun(t, coll, frag)
	t.Logf("CONTROL   fragment, no session -> ret=%d reasons=%v", retControl, dControl)
	if dControl["REDIRECT_ERR"] == 0 {
		t.Fatalf("without a planted session the fragment did not reach the XSK "+
			"redirect (reasons=%v); the cell is not exercising the path it "+
			"claims to. A PARSE_FAIL here means the fix took the must-not-build "+
			"blackhole shape -- declining in the parser lands on "+
			"drop_degraded_transit and discards every legitimate fragment", dControl)
	}

	// The tuple the shim derives from PAYLOAD bytes, not from any real header.
	key := fragSessionKeyFor(12345, 443)
	if err := coll.Maps["userspace_sessions"].Put(&key, uint8(2)); err != nil {
		t.Fatalf("plant: %v", err)
	}
	retHit, dHit := fragRun(t, coll, frag)
	t.Logf("COLLISION fragment + payload-keyed session -> ret=%d reasons=%v", retHit, dHit)

	if dHit["REDIRECT_ERR"] == 0 || dHit["PASS_TO_KERNEL"] > 0 {
		t.Errorf("a non-first IPv4 fragment was adjudicated by a session keyed on "+
			"its PAYLOAD bytes (reasons=%v). #7494's sentinel makes the session "+
			"lookup a GUARANTEED MISS for fragments -- the helper only ever "+
			"installs real protocols -- so the fragment must fall through to the "+
			"XSK redirect regardless of what its payload collides with. A "+
			"PASS_TO_KERNEL here means the sentinel is not reaching "+
			"live_userspace_session_action", dHit)
	}
}

// TestNonFirstFragmentDispositionDependsOnPayloadBytes_7494 is the sharper
// half, and it is not stated in the issue: `parse_l4` reads offset+12 as a TCP
// data-offset nibble and returns None when it is < 5, which lands on
// `drop_degraded_transit`. On a non-first fragment that byte is PAYLOAD.
//
// So the same fragment of the same flow is DROPPED or FORWARDED depending on
// its content. Both arms are asserted so neither can silently become the other.
//
// Re-pointed with #7494's IPv4 half: both payload values must now produce the
// SAME disposition, and it must be the helper rather than a drop. The pre-fix
// behaviour -- 0x00 dropped, 0x50 forwarded -- was measured, so the inversion
// below is a recorded transition rather than a fresh guess.
func TestNonFirstFragmentDispositionDependsOnPayloadBytes_7494(t *testing.T) {
	coll := fragLoad(t)

	low := ipv4Frame(0x00b9)
	low[34+12] = 0x00 // payload byte parse_l4 reads as the data-offset nibble
	retLow, dLow := fragRun(t, coll, low)

	high := ipv4Frame(0x00b9)
	high[34+12] = 0x50
	retHigh, dHigh := fragRun(t, coll, high)

	t.Logf("payload byte 0x00 -> ret=%d reasons=%v", retLow, dLow)
	t.Logf("payload byte 0x50 -> ret=%d reasons=%v", retHigh, dHigh)

	if dLow["PARSE_FAIL"] > 0 {
		t.Errorf("a non-first IPv4 fragment was DROPPED via PARSE_FAIL because of "+
			"its own payload byte (reasons=%v). This is the #7494 exposure-#5 "+
			"regression: parse_l4's TCP arm returns None when the payload byte it "+
			"reads as a data-offset nibble is < 5, which makes a fragment's "+
			"disposition selectable by an off-path party. The sentinel must route "+
			"fragments to the unknown-protocol arm, which cannot fail", dLow)
	}
	if dHigh["REDIRECT_ERR"] == 0 {
		t.Errorf("a non-first fragment whose payload byte is 0x50 was expected to "+
			"reach the helper via the XSK redirect, got reasons=%v. IF #7494 HAS "+
			"LANDED THIS RED IS EXPECTED only if the disposition is still the "+
			"helper; a PARSE_FAIL here means fragments are being DROPPED, which "+
			"is the blackhole shape the plan rejects. Invert or repair -- do not "+
			"delete", dHigh)
	}
	if !reflect.DeepEqual(dLow, dHigh) {
		t.Errorf("the two payload values produced DIFFERENT dispositions "+
			"(0x00=%v, 0x50=%v). After #7494 a non-first fragment's fate must not "+
			"depend on its own payload at all -- that independence IS the "+
			"invariant, and this is the cell that holds it", dLow, dHigh)
	}
}

// ipv6Frame builds ethernet + IPv6 + a real Fragment extension header + TCP-ish
// payload. This CANNOT be an adaptation of the v4 builder: the v4 sighting is
// one masked load at a fixed offset, while the v6 sighting only exists if the
// frame carries an actual extension-header chain for the shim's walk to
// traverse. A v6 cell built by copying the v4 assertion would assert about a
// packet that never enters the walk -- passing, and testing nothing.
//
// fragOff is the raw 16-bit Fragment-header field: offset in the high 13 bits,
// M flag in bit 0. A non-zero OFFSET is what makes it a non-first fragment.
func ipv6Frame(fragOff uint16, dataOffByte byte) []byte {
	p := make([]byte, 128)
	p[12], p[13] = 0x86, 0xdd // ETH_P_IPV6
	ip := p[14:]
	ip[0] = 0x60                                          // version 6
	binary.BigEndian.PutUint16(ip[4:], uint16(128-14-40)) // payload length
	ip[6] = 44                                            // next header = Fragment
	ip[7] = 64                                            // hop limit
	copy(ip[8:24], []byte{0x20, 0x01, 5, 0x59, 0x85, 0x85, 0xbf, 1, 0, 0, 0, 0, 0, 0, 0, 50})
	copy(ip[24:40], []byte{0x20, 0x01, 5, 0x59, 0x85, 0x85, 0xbf, 2, 0, 0, 0, 0, 0, 0, 0, 60})

	frag := p[14+40:] // the Fragment extension header, 8 bytes
	frag[0] = unix.IPPROTO_TCP
	frag[1] = 0
	binary.BigEndian.PutUint16(frag[2:], fragOff)
	binary.BigEndian.PutUint32(frag[4:], 0xdeadbeef) // identification

	l4 := p[14+40+8:]
	binary.BigEndian.PutUint16(l4[0:], 12345)
	binary.BigEndian.PutUint16(l4[2:], 443)
	l4[12] = dataOffByte
	return p
}

func fragSessionKeyV6(srcPort, dstPort uint16) fragSessionKey {
	var src, dst [16]byte
	copy(src[:], []byte{0x20, 0x01, 5, 0x59, 0x85, 0x85, 0xbf, 1, 0, 0, 0, 0, 0, 0, 0, 50})
	copy(dst[:], []byte{0x20, 0x01, 5, 0x59, 0x85, 0x85, 0xbf, 2, 0, 0, 0, 0, 0, 0, 0, 60})
	return fragSessionKey{
		AddrFamily: 10, Protocol: unix.IPPROTO_TCP,
		SrcPort: srcPort, DstPort: dstPort, SrcAddr: src, DstAddr: dst,
	}
}
// ipv6TCPFrame10662 builds an IPv6 datagram with a complete captured TCP
// header but a caller-selected declared payload length. The addresses match
// fragSessionKeyV6 so an out-of-declared-range SYN can be tested against a
// planted session.
func ipv6TCPFrame10662(payloadLen uint16) []byte {
	p := make([]byte, 14+40+20)
	p[12], p[13] = 0x86, 0xdd
	ip := p[14:]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:], payloadLen)
	ip[6] = unix.IPPROTO_TCP
	ip[7] = 64
	copy(ip[8:24], []byte{0x20, 0x01, 5, 0x59, 0x85, 0x85, 0xbf, 1, 0, 0, 0, 0, 0, 0, 0, 50})
	copy(ip[24:40], []byte{0x20, 0x01, 5, 0x59, 0x85, 0x85, 0xbf, 2, 0, 0, 0, 0, 0, 0, 0, 60})
	tcp := ip[40:]
	binary.BigEndian.PutUint16(tcp[0:], 12345)
	binary.BigEndian.PutUint16(tcp[2:], 443)
	tcp[12] = 0x50 // 20-byte TCP header
	tcp[13] = 0x02 // SYN lies beyond payload_len=13
	return p
}

func TestV6TCPFlagsPastDeclaredEndCannotHitSession_10662(t *testing.T) {
	coll := fragLoad(t)
	key := fragSessionKeyV6(12345, 443)
	if err := coll.Maps["userspace_sessions"].Put(&key, uint8(2)); err != nil {
		t.Fatalf("plant: %v", err)
	}

	_, control := fragRun(t, coll, ipv6TCPFrame10662(20))
	if control["PASS_TO_KERNEL"] == 0 {
		t.Fatalf("declared 20-byte TCP header did not match the planted session "+
			"(reasons=%v); session fixture is not observable", control)
	}

	ret, d := fragRun(t, coll, ipv6TCPFrame10662(13))
	t.Logf("IPv6 payload_len=13 with captured SYN flag at offset+13 -> ret=%d reasons=%v", ret, d)
	if d["PASS_TO_KERNEL"] != 0 || d["PARSE_FAIL"] == 0 {
		t.Fatalf("IPv6 TCP flags outside payload_len reached session admission: "+
			"expected PARSE_FAIL without PASS_TO_KERNEL, got %v", d)
	}
}

// TestV6FixtureReachesTheWalk is the fixture control, and it is the cell that
// makes the v6 cells below mean anything. A v6 frame that does not actually
// enter the extension-header walk would produce a clean-looking disposition for
// entirely the wrong reason. A FIRST fragment (offset 0) must parse normally
// and reach the helper; if this does not hold, the frame is malformed and every
// v6 result here is VOID rather than negative.
func TestV6FixtureReachesTheWalk(t *testing.T) {
	coll := fragLoad(t)
	ret, d := fragRun(t, coll, ipv6Frame(0x0000, 0x50)) // offset 0 => FIRST fragment
	t.Logf("v6 FIRST fragment (offset 0) -> ret=%d reasons=%v", ret, d)
	if d["PARSE_FAIL"] > 0 {
		t.Fatalf("the v6 fixture does not parse (reasons=%v). The frame is "+
			"malformed -- IPv6 header, Fragment header chain, or lengths -- so "+
			"the v6 cells below are VOID, not evidence that v6 is unaffected", d)
	}
}

// TestV6NonFirstFragmentIsNeutralisedForBothExposures_7494 is the inverted form
// of the cell that used to assert these exposures were LIVE.
//
// #7494's v4 half landed at +92 instructions; the v6 half could not be
// consumed at all -- four structurally different channels were rejected by the
// kernel verifier. #8249 established why: reading a SECOND value out of the
// extension-header walk defeats the verifier's state merging at the loop exit,
// and that cost multiplies against every stateful region downstream. Laundering
// the sighting through a per-CPU slot makes `protocol` depend on an opaque map
// read instead of the walk's exit state, which verifies.
//
// So this now asserts the FIXED invariant, on the same two fixtures the old
// cell used, and it fails if either exposure comes back:
//
//   - a non-first fragment with a payload-keyed session planted must NOT be
//     handed to the kernel. The payload-derived tuple can no longer be built,
//     so the session cannot match and the packet is adjudicated by the full
//     dataplane instead.
//   - a non-first fragment whose payload byte is 0x00 must NOT be dropped.
//     That byte used to be read as a TCP data-offset nibble, which made a
//     packet's disposition selectable by an off-path party choosing a byte.
//
// Both now take the SAME disposition as the first-fragment control, which is
// the point: the fragment's own payload no longer influences its fate.
func TestV6NonFirstFragmentIsNeutralisedForBothExposures_7494(t *testing.T) {
	coll := fragLoad(t)
	frag := ipv6Frame(0x00b8, 0x50) // offset 23 => NON-FIRST fragment

	key := fragSessionKeyV6(12345, 443)
	if err := coll.Maps["userspace_sessions"].Put(&key, uint8(2)); err != nil {
		t.Fatalf("plant: %v", err)
	}
	retHit, dHit := fragRun(t, coll, frag)
	t.Logf("v6 non-first fragment + payload-keyed session -> ret=%d reasons=%v", retHit, dHit)

	lowRet, dLow := fragRun(t, coll, ipv6Frame(0x00b8, 0x00))
	t.Logf("v6 non-first fragment, payload byte 0x00 -> ret=%d reasons=%v", lowRet, dLow)

	if dHit["PASS_TO_KERNEL"] != 0 {
		t.Errorf("exposure #1 is back: a v6 non-first fragment with a "+
			"payload-keyed session was handed to the KERNEL (%v). The sentinel "+
			"substitution in parse_ipv6 must make a non-first fragment a "+
			"guaranteed session miss -- a payload-derived tuple must never "+
			"reach the session lookup (#7494/#8249)", dHit)
	}
	if dLow["PARSE_FAIL"] != 0 {
		t.Errorf("exposure #5 is back: a v6 non-first fragment was DROPPED "+
			"because of its own payload byte (%v). That byte is read as a TCP "+
			"data-offset nibble only if the fragment reaches parse_l4's TCP "+
			"arm; the sentinel routes it to the unknown-protocol arm, which "+
			"cannot fail. A drop here is a disposition chosen by an off-path "+
			"party (#7494/#8249)", dLow)
	}

	// NON-VACUITY. Both assertions above are absence checks, and an absence
	// holds for free if the fixture stopped reaching the code. The first-
	// fragment control in TestV6FixtureReachesTheWalk proves the walk is
	// entered; this proves these two frames produced a real disposition rather
	// than nothing at all.
	if len(dHit) == 0 || len(dLow) == 0 {
		t.Fatalf("a fixture produced NO disposition at all (hit=%v, low=%v) -- "+
			"the absence assertions above would hold for free", dHit, dLow)
	}
}

// TestFragmentNeverCreatesASession_7494 proves the premise that clears every
// operator-visible surface. #7494's sentinel is a value no real protocol has,
// and the argument that it never reaches an operator rests on fragments never
// producing a session at all -- if one did, protocol 255 would surface in
// `show security flow session` and in flow export, and someone would eventually
// "fix" it by mapping it back to TCP.
//
// That was an inference from reading the code. This asserts it: run fragments
// of both families through and require the session table to be untouched.
func TestFragmentNeverCreatesASession_7494(t *testing.T) {
	coll := fragLoad(t)
	sessions := coll.Maps["userspace_sessions"]

	count := func() int {
		n := 0
		var k fragSessionKey
		var v uint8
		it := sessions.Iterate()
		for it.Next(&k, &v) {
			n++
		}
		if err := it.Err(); err != nil {
			t.Fatalf("iterate sessions: %v -- the instrument is dead and an "+
				"empty table would prove nothing", err)
		}
		return n
	}

	if before := count(); before != 0 {
		t.Fatalf("session table is not empty at start (%d entries); this cell "+
			"cannot distinguish an install from pre-existing state", before)
	}

	for _, pkt := range [][]byte{
		ipv4Frame(0x00b9),       // v4 non-first fragment
		ipv4Frame(0x0000),       // v4 non-fragment, for contrast
		ipv6Frame(0x00b8, 0x50), // v6 non-first fragment
		ipv6Frame(0x0000, 0x50), // v6 first fragment
	} {
		fragRun(t, coll, pkt)
	}

	if after := count(); after != 0 {
		t.Errorf("%d session(s) were installed by running fragments through the "+
			"shim. The shim is not supposed to install sessions at all -- the "+
			"helper does -- so this both breaks the #7494 sentinel's "+
			"operator-visibility argument and means protocol %d can reach "+
			"`show security flow session`", after, 255)
	}
}
