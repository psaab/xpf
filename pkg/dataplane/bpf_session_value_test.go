package dataplane

import (
	"encoding/binary"
	"testing"
	"unsafe"
)

// Sizes of the on-map C `struct session_value` / `struct session_value_v6`
// conntrack ABI (bpf/headers/xpf_conntrack.h), mirrored by the Rust helper's
// BpfSessionValueV4 / BpfSessionValueV6 and asserted on the Rust side at
// userspace-dp/src/afxdp/bpf_map_tests.rs (size_of == 144 / 192; 136 / 184
// before the #4983 ingress_ifindex append, 128 / 176 before the #5460 __u16
// flags widen). These are the authoritative on-map
// value sizes — the Go map registration MUST match them, not sizeOf[SessionValue]
// (which is larger due to sync-only trailing fields, #2360).
const (
	// #9546 appended routing_domain: 144/192 -> 152/200.
	conntrackValueSizeV4 = 152
	conntrackValueSizeV6 = 200
)

// TestBPFSessionValueMatchesConntrackABI pins the dedicated on-map ABI types to
// the C/Rust conntrack struct sizes. Fails if a field drifts so the Go layout
// no longer mirrors the kernel struct.
func TestBPFSessionValueMatchesConntrackABI(t *testing.T) {
	if got := unsafe.Sizeof(bpfSessionValue{}); got != conntrackValueSizeV4 {
		t.Fatalf("sizeof(bpfSessionValue) = %d, want %d (C struct session_value / Rust BpfSessionValueV4)",
			got, conntrackValueSizeV4)
	}
	if got := unsafe.Sizeof(bpfSessionValueV6{}); got != conntrackValueSizeV6 {
		t.Fatalf("sizeof(bpfSessionValueV6) = %d, want %d (C struct session_value_v6 / Rust BpfSessionValueV6)",
			got, conntrackValueSizeV6)
	}
	// The exported SSOT constants (used by production registration AND test
	// fixtures) must equal the literal C/Rust contract.
	if ConntrackSessionValueSize != conntrackValueSizeV4 {
		t.Fatalf("ConntrackSessionValueSize = %d, want %d", ConntrackSessionValueSize, conntrackValueSizeV4)
	}
	if ConntrackSessionValueSizeV6 != conntrackValueSizeV6 {
		t.Fatalf("ConntrackSessionValueSizeV6 = %d, want %d", ConntrackSessionValueSizeV6, conntrackValueSizeV6)
	}
}

// TestBPFSessionValueMarshalsAtConntrackABISize is the fail-on-revert guard for
// #6082. cilium/ebpf's map I/O (Lookup / Iterate / BatchLookup) unmarshals the
// on-map value through internal/sysenc.Unmarshal, which only takes the correct
// zero-copy fast path when encoding/binary's binary.Size(T) equals the native
// unsafe.Sizeof(T). encoding/binary does NOT count implicit alignment padding,
// so when the three head-padding gaps (after State, after IsReverse, before
// SessionID) are left implicit, binary.Size is 129/177 while unsafe.Sizeof is
// 144/192. sysenc then falls back to binary.Decode, which consumes only
// binary.Size bytes of every value_size-byte kernel record and fails the batch
// with "unmarshaling []dataplane.bpfSessionValue doesn't consume all data" —
// the live HA session-sync sweep breakage.
//
// Declaring the padding explicitly (named `_ [N]byte` gaps) makes binary.Size
// == unsafe.Sizeof == value_size, keeping the fast path engaged. This test goes
// RED if the explicit pads are removed (reverting to implicit padding), because
// binary.Size drops back to 129/177. It asserts all three sizes are equal AND
// equal to the on-map conntrack ABI value_size (144/192) — the exact invariant
// cilium/ebpf relies on.
func TestBPFSessionValueMarshalsAtConntrackABISize(t *testing.T) {
	cases := []struct {
		name    string
		native  uintptr
		binSize int
		want    int
	}{
		{"bpfSessionValue", unsafe.Sizeof(bpfSessionValue{}), binary.Size(bpfSessionValue{}), conntrackValueSizeV4},
		{"bpfSessionValueV6", unsafe.Sizeof(bpfSessionValueV6{}), binary.Size(bpfSessionValueV6{}), conntrackValueSizeV6},
	}
	for _, tc := range cases {
		if int(tc.native) != tc.want {
			t.Errorf("unsafe.Sizeof(%s) = %d, want %d (on-map conntrack ABI value_size)", tc.name, tc.native, tc.want)
		}
		// The load-bearing #6082 assertion: encoding/binary's field-sum size
		// must equal the native size, or cilium/ebpf's sysenc falls off the
		// zero-copy path and mis-sizes every batch element.
		if tc.binSize != int(tc.native) {
			t.Errorf("binary.Size(%s) = %d, want %d (== unsafe.Sizeof); implicit padding makes cilium/ebpf "+
				"mis-marshal the batch element and fail the HA sync sweep (#6082) — declare pads explicitly",
				tc.name, tc.binSize, tc.native)
		}
		if tc.binSize != tc.want {
			t.Errorf("binary.Size(%s) = %d, want %d (kernel value_size)", tc.name, tc.binSize, tc.want)
		}
	}
}

// TestBatchLookupSessionsRoundTrip drives the actual failing #6082 path: it
// creates real kernel v4/v6 session HASH maps at the on-map ABI value_size,
// installs entries through the production Set/toBPF path, then reads them back
// via the batch sweep (BatchIterateSessions / V6). Before the explicit-padding
// fix this returns "batch lookup sessions: ... doesn't consume all data". Skips
// on unprivileged CI (no BPF map create); runs on the privileged cluster where
// #6082 was observed.
func TestBatchLookupSessionsRoundTrip(t *testing.T) {
	m := newClearTestManager(t)

	const flows = 400 // spans multiple 256-entry batch chunks
	for i := uint32(0); i < flows; i++ {
		v4 := SessionValue{State: 1, Flags: SessFlagSNAT, TCPState: 2, SessionID: uint64(i) + 1, PolicyID: i, AppID: uint16(i)}
		if err := m.SetSessionV4(clearTestV4Key(i, false), v4); err != nil {
			t.Fatalf("set v4 %d: %v", i, err)
		}
		v6 := SessionValueV6{State: 1, Flags: SessFlagDNAT, TCPState: 2, SessionID: uint64(i) + 1, PolicyID: i, AppID: uint16(i)}
		if err := m.SetSessionV6(clearTestV6Key(i, false), v6); err != nil {
			t.Fatalf("set v6 %d: %v", i, err)
		}
	}

	got := map[uint32]SessionValue{}
	if err := m.BatchIterateSessions(func(k SessionKey, v SessionValue) bool {
		got[binary.BigEndian.Uint32(k.SrcIP[:])] = v
		return true
	}); err != nil {
		t.Fatalf("BatchIterateSessions (the #6082 failing path): %v", err)
	}
	if len(got) != flows {
		t.Fatalf("BatchIterateSessions returned %d sessions, want %d", len(got), flows)
	}
	// Spot-check a value survived the marshal round trip with correct field
	// offsets (a mis-sized element would smear fields across the boundary).
	if v, ok := got[7]; !ok || v.SessionID != 8 || v.PolicyID != 7 || v.Flags != SessFlagSNAT || v.AppID != 7 {
		t.Fatalf("v4 flow 7 round-trip mismatch: %+v (ok=%v)", v, ok)
	}

	gotV6 := map[uint32]SessionValueV6{}
	if err := m.BatchIterateSessionsV6(func(k SessionKeyV6, v SessionValueV6) bool {
		gotV6[binary.BigEndian.Uint32(k.SrcIP[12:])] = v
		return true
	}); err != nil {
		t.Fatalf("BatchIterateSessionsV6 (the #6082 failing path): %v", err)
	}
	if len(gotV6) != flows {
		t.Fatalf("BatchIterateSessionsV6 returned %d sessions, want %d", len(gotV6), flows)
	}
	if v, ok := gotV6[7]; !ok || v.SessionID != 8 || v.PolicyID != 7 || v.Flags != SessFlagDNAT || v.AppID != 7 {
		t.Fatalf("v6 flow 7 round-trip mismatch: %+v (ok=%v)", v, ok)
	}

	// Single-entry Lookup (GetSessionV4/V6) shares the same sysenc path.
	if v, err := m.GetSessionV4(clearTestV4Key(9, false)); err != nil || v.SessionID != 10 {
		t.Fatalf("GetSessionV4 flow 9: v=%+v err=%v", v, err)
	}
	if v, err := m.GetSessionV6(clearTestV6Key(9, false)); err != nil || v.SessionID != 10 {
		t.Fatalf("GetSessionV6 flow 9: v=%+v err=%v", v, err)
	}
}

// TestSessionValueCarriesSyncOnlyGeneration confirms SessionValue is exactly 8
// bytes (one uint64 Generation) larger than the on-map ABI type, and that the
// extra bytes are the trailing Generation field — the #2170 sync-only guard
// that must NOT be registered into the BPF map (#2360).
func TestSessionValueCarriesSyncOnlyGeneration(t *testing.T) {
	// The sync-only fields (#2170 Generation, #3301 PolicyCounterIdx) sit
	// strictly past the on-map conntrack ABI layout (bpfSessionValue). The
	// hard invariant guarding #2360 is that bpfSessionValue equals the on-map
	// ABI size — it must NOT pick up the sync-only fields — and that those
	// fields begin immediately past it. (The exact byte delta now includes
	// Generation(u64)+PolicyCounterIdx(u32)+alignment padding, so we assert
	// the field offsets, not a fixed delta.)
	if got := unsafe.Sizeof(bpfSessionValue{}); uintptr(conntrackValueSizeV4) != got {
		t.Fatalf("bpfSessionValue size = %d, want %d (on-map conntrack ABI)", got, conntrackValueSizeV4)
	}
	if got := unsafe.Sizeof(bpfSessionValueV6{}); uintptr(conntrackValueSizeV6) != got {
		t.Fatalf("bpfSessionValueV6 size = %d, want %d (on-map conntrack ABI)", got, conntrackValueSizeV6)
	}
	if unsafe.Sizeof(SessionValue{}) <= unsafe.Sizeof(bpfSessionValue{}) {
		t.Fatal("SessionValue must be larger than bpfSessionValue (carries sync-only fields)")
	}
	if unsafe.Sizeof(SessionValueV6{}) <= unsafe.Sizeof(bpfSessionValueV6{}) {
		t.Fatal("SessionValueV6 must be larger than bpfSessionValueV6 (carries sync-only fields)")
	}
	// Generation must be the first field past the on-map layout.
	if off := unsafe.Offsetof(SessionValue{}.Generation); off != conntrackValueSizeV4 {
		t.Fatalf("SessionValue.Generation offset = %d, want %d (must sit immediately past the on-map layout)",
			off, conntrackValueSizeV4)
	}
	if off := unsafe.Offsetof(SessionValueV6{}.Generation); off != conntrackValueSizeV6 {
		t.Fatalf("SessionValueV6.Generation offset = %d, want %d (must sit immediately past the on-map layout)",
			off, conntrackValueSizeV6)
	}
	// #3301: PolicyCounterIdx follows Generation (also sync-only, never on the
	// BPF map).
	if off := unsafe.Offsetof(SessionValue{}.PolicyCounterIdx); off != conntrackValueSizeV4+unsafe.Sizeof(uint64(0)) {
		t.Fatalf("SessionValue.PolicyCounterIdx offset = %d, want %d (immediately past Generation)",
			off, conntrackValueSizeV4+unsafe.Sizeof(uint64(0)))
	}
	if off := unsafe.Offsetof(SessionValueV6{}.PolicyCounterIdx); off != conntrackValueSizeV6+unsafe.Sizeof(uint64(0)) {
		t.Fatalf("SessionValueV6.PolicyCounterIdx offset = %d, want %d (immediately past Generation)",
			off, conntrackValueSizeV6+unsafe.Sizeof(uint64(0)))
	}
}

// TestSessionMapRegisteredAtConntrackABISize is the regression guard for
// #2360: the `sessions` / `sessions_v6` BPF maps MUST be registered with the
// on-map conntrack ABI value_size (144 / 192 post-#4983; 136 / 184 post-#5460),
// NOT sizeOf[SessionValue] / sizeOf[SessionValueV6], which are larger by the
// sync-only trailing fields (Generation, PolicyCounterIdx, ...). Registering at
// the larger SessionValue size makes the kernel value_size exceed the Rust
// helper's on-map lookup buffer, causing an out-of-bounds copy. This test fails
// if anyone reverts the registration to sizeOf[SessionValue].
func TestSessionMapRegisteredAtConntrackABISize(t *testing.T) {
	specs := userspaceShimSharedMapSpecs()
	valueSize := make(map[string]uint32, len(specs))
	for _, spec := range specs {
		valueSize[spec.Name] = spec.ValueSize
	}

	if got := valueSize["sessions"]; got != conntrackValueSizeV4 {
		t.Fatalf("sessions map value_size = %d, want %d (C/Rust conntrack ABI); "+
			"must NOT be sizeOf[SessionValue]=%d which inflates the map by the sync-only Generation (#2360)",
			got, conntrackValueSizeV4, unsafe.Sizeof(SessionValue{}))
	}
	if got := valueSize["sessions_v6"]; got != conntrackValueSizeV6 {
		t.Fatalf("sessions_v6 map value_size = %d, want %d (C/Rust conntrack ABI); "+
			"must NOT be sizeOf[SessionValueV6]=%d which inflates the map by the sync-only Generation (#2360)",
			got, conntrackValueSizeV6, unsafe.Sizeof(SessionValueV6{}))
	}

	// And the registration must equal the dedicated ABI type's size — the
	// single source of the on-map layout.
	if got, want := valueSize["sessions"], uint32(unsafe.Sizeof(bpfSessionValue{})); got != want {
		t.Fatalf("sessions map value_size = %d, want sizeOf[bpfSessionValue]=%d", got, want)
	}
	if got, want := valueSize["sessions_v6"], uint32(unsafe.Sizeof(bpfSessionValueV6{})); got != want {
		t.Fatalf("sessions_v6 map value_size = %d, want sizeOf[bpfSessionValueV6]=%d", got, want)
	}
}

// TestSessionValueBPFRoundTripDropsGeneration verifies the conversion contract:
// every field except the sync-only Generation survives a SessionValue -> on-map
// -> SessionValue round trip, and Generation is dropped (the BPF map never
// stores it). The authoritative Generation lives in the Go session table / on
// the cluster sync wire, so dropping it at the map boundary is correct.
//
// What this test can and cannot see, because it is a SYMMETRIC composition
// (orig.toBPF().sessionValue()): it detects any field a SINGLE direction drops
// or corrupts, since the other direction cannot put the value back. It is
// structurally blind to the SAME mistake made in BOTH directions — most
// obviously a transposition, where toBPF writes v.IngressVlanID into
// IngressIfindex and sessionValue reads it back out of IngressIfindex into
// IngressVlanID. That composes to the identity and passes here while every
// on-map record is written and read at the wrong offset.
//
// The two direction-specific tests below cover exactly that residual, and
// TestBPFSessionValueIngressIdentityOffsets covers the Go-vs-C layout. All
// three are needed: this one for per-direction loss, the direction tests for
// symmetric mis-assignment, the offsets test for a struct reorder.
func TestSessionValueBPFRoundTripDropsGeneration(t *testing.T) {
	orig := SessionValue{
		State:       3,
		Flags:       SessFlagSNAT,
		TCPState:    4,
		IsReverse:   0,
		AppTimeout:  120,
		SessionID:   0xdeadbeefcafef00d,
		Created:     111,
		LastSeen:    222,
		Timeout:     300,
		PolicyID:    7,
		IngressZone: 1,
		EgressZone:  2,
		NATSrcIP:    0x0a000001,
		NATDstIP:    0x0a000002,
		NATSrcPort:  1234,
		NATDstPort:  5678,
		FwdPackets:  10,
		FwdBytes:    1000,
		RevPackets:  20,
		RevBytes:    2000,
		ReverseKey:  SessionKey{SrcPort: 5678, DstPort: 1234, Protocol: 6},
		ALGType:     1,
		LogFlags:    2,
		AppID:       42,
		FibIfindex:  9,
		FibVlanID:   50,
		FibDmac:     [6]byte{1, 2, 3, 4, 5, 6},
		FibSmac:     [6]byte{6, 5, 4, 3, 2, 1},
		FibGen:      99,
		// #4983: NON-ZERO, and deliberately different from each other and from
		// FibIfindex/FibVlanID above. A zero here would make the round trip
		// pass with both conversion directions dropping the field entirely
		// (0 -> absent -> 0), which is exactly what it did before.
		IngressIfindex:   11,
		IngressVlanID:    50,
		Generation:       0x1122334455667788, // sync-only — must NOT survive to the map
		PolicyCounterIdx: 7,                  // #3301 sync-only — must NOT survive to the map
	}

	got := orig.toBPF().sessionValue()

	want := orig
	want.Generation = 0       // dropped at the map boundary
	want.PolicyCounterIdx = 0 // #3301 sync-only — dropped at the map boundary
	if got != want {
		t.Fatalf("v4 round trip mismatch:\n got=%+v\nwant=%+v", got, want)
	}

	origV6 := SessionValueV6{
		State:            3,
		Flags:            SessFlagDNAT,
		TCPState:         4,
		IsReverse:        1,
		AppTimeout:       60,
		SessionID:        0x0102030405060708,
		Created:          1,
		LastSeen:         2,
		Timeout:          30,
		PolicyID:         8,
		IngressZone:      2,
		EgressZone:       1,
		NATSrcIP:         [16]byte{0xfe, 0x80, 15: 1},
		NATDstIP:         [16]byte{0x20, 0x01, 15: 2},
		NATSrcPort:       4321,
		NATDstPort:       8765,
		FwdPackets:       5,
		FwdBytes:         500,
		RevPackets:       6,
		RevBytes:         600,
		ReverseKey:       SessionKeyV6{SrcPort: 8765, DstPort: 4321, Protocol: 17},
		ALGType:          2,
		LogFlags:         3,
		AppID:            43,
		FibIfindex:       10,
		FibVlanID:        80,
		FibDmac:          [6]byte{9, 8, 7, 6, 5, 4},
		FibSmac:          [6]byte{4, 5, 6, 7, 8, 9},
		FibGen:           77,
		IngressIfindex:   14, // #4983, non-zero and distinct — see the v4 note
		IngressVlanID:    80,
		Generation:       0x8877665544332211,
		PolicyCounterIdx: 11, // #3301 sync-only — must NOT survive to the map
	}

	gotV6 := origV6.toBPF().sessionValue()
	wantV6 := origV6
	wantV6.Generation = 0
	wantV6.PolicyCounterIdx = 0
	if gotV6 != wantV6 {
		t.Fatalf("v6 round trip mismatch:\n got=%+v\nwant=%+v", gotV6, wantV6)
	}
}

// Byte OFFSETS of the #4983 ingress-identity pair inside the on-map conntrack
// ABI (bpf/headers/xpf_conntrack.h `ingress_ifindex` / `ingress_vlan_id`,
// mirrored by the Rust BpfSessionValueV4 / V6).
//
// v4: the pair is appended at the old 136-byte tail, so ifindex occupies
// [136,140) and the u16 vlan id [140,142), with the struct padded to 144.
// v6: the same append at the old 184-byte tail — [184,188) and [188,190),
// padded to 192.
const (
	conntrackIngressIfindexOffV4 = 136
	conntrackIngressVlanIDOffV4  = 140
	conntrackIngressIfindexOffV6 = 184
	conntrackIngressVlanIDOffV6  = 188
	// #9546: appended after the ingress pair; no existing offset moved.
	conntrackRoutingDomainOffV4 = 144
	conntrackRoutingDomainOffV6 = 192
)

// TestBPFSessionValueIngressIdentityOffsets pins WHERE the #4983 identity pair
// sits, not just how big the struct is.
//
// The size guards above cannot see a field REORDER. Swapping the Go tail to
// `IngressVlanID; pad; IngressIfindex` leaves sizeof at 144/192 and
// binary.Size equal to it, so `TestBPFSessionValueMatchesConntrackABI` and
// `TestBPFSessionValueMarshalsAtConntrackABISize` both stay green — while C
// and Rust still write the ifindex at 136/184. A record carrying
// `{ifindex: 11, vlan: 50}` then decodes in Go as `{ifindex: 50, vlan: 11}`.
//
// That failure mode is worse than a decode error: 50 and 11 are both plausible
// values, so the CLI filters confidently on the wrong interface instead of
// falling back to the zone approximation the way a zero would make it.
//
// RED on revert: swap the two field declarations in `bpfSessionValue` (and/or
// `bpfSessionValueV6`) in bpf_session_value.go and this fails on the offset
// that moved, naming the field. Size and binary.Size guards stay GREEN under
// that same edit, which is why this test has to exist separately.
func TestBPFSessionValueIngressIdentityOffsets(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"bpfSessionValue.IngressIfindex", unsafe.Offsetof(bpfSessionValue{}.IngressIfindex), conntrackIngressIfindexOffV4},
		{"bpfSessionValue.IngressVlanID", unsafe.Offsetof(bpfSessionValue{}.IngressVlanID), conntrackIngressVlanIDOffV4},
		{"bpfSessionValueV6.IngressIfindex", unsafe.Offsetof(bpfSessionValueV6{}.IngressIfindex), conntrackIngressIfindexOffV6},
		{"bpfSessionValueV6.IngressVlanID", unsafe.Offsetof(bpfSessionValueV6{}.IngressVlanID), conntrackIngressVlanIDOffV6},
	} {
		if tc.got != tc.want {
			t.Errorf("offsetof(%s) = %d, want %d — the Go layout no longer "+
				"matches where C/Rust write this field, so on-map records "+
				"decode with the ingress identity fields transposed and the "+
				"CLI filters confidently on the wrong interface",
				tc.name, tc.got, tc.want)
		}
	}
}

// #4983 conversion-direction fixtures. ifindex and VLAN id are deliberately
// DIFFERENT numbers within each family, and different across families, so that
// an assertion which reads the wrong field of the pair fails on the value
// rather than coincidentally agreeing.
const (
	convIngressIfindexV4 uint32 = 11
	convIngressVlanIDV4  uint16 = 50
	convIngressIfindexV6 uint32 = 14
	convIngressVlanIDV6  uint16 = 80
)

// TestSessionValueToBPFCarriesIngressIdentity pins the WRITE direction on its
// own: SessionValue -> bpfSessionValue must place the #4983 ingress identity
// into the matching on-map fields, for both address families.
//
// Split out from the round trip deliberately. The round trip composes both
// directions, so it passes whenever the two agree — including when they agree
// on the WRONG field. Asserting on the intermediate bpf value is the only way
// to state "toBPF puts the ifindex in the ifindex slot".
//
// RED on revert: delete `IngressIfindex: v.IngressIfindex` (or the VlanID line)
// from either toBPF in bpf_session_value.go and the corresponding case fails,
// naming the field and the family.
func TestSessionValueToBPFCarriesIngressIdentity(t *testing.T) {
	gotV4 := SessionValue{
		IngressIfindex: convIngressIfindexV4,
		IngressVlanID:  convIngressVlanIDV4,
	}.toBPF()
	if gotV4.IngressIfindex != convIngressIfindexV4 {
		t.Errorf("v4 toBPF().IngressIfindex = %d, want %d — the ifindex slot of the "+
			"on-map record does not carry the session's ingress ifindex (dropped, "+
			"or written from the wrong source field), so the CLI reads a binding "+
			"the packet never arrived on, or none at all (#4983)",
			gotV4.IngressIfindex, convIngressIfindexV4)
	}
	if gotV4.IngressVlanID != convIngressVlanIDV4 {
		t.Errorf("v4 toBPF().IngressVlanID = %d, want %d — without the VLAN half "+
			"two units of one trunk NIC are indistinguishable on the map (#4983)",
			gotV4.IngressVlanID, convIngressVlanIDV4)
	}

	gotV6 := SessionValueV6{
		IngressIfindex: convIngressIfindexV6,
		IngressVlanID:  convIngressVlanIDV6,
	}.toBPF()
	if gotV6.IngressIfindex != convIngressIfindexV6 {
		t.Errorf("v6 toBPF().IngressIfindex = %d, want %d (#4983)",
			gotV6.IngressIfindex, convIngressIfindexV6)
	}
	if gotV6.IngressVlanID != convIngressVlanIDV6 {
		t.Errorf("v6 toBPF().IngressVlanID = %d, want %d (#4983)",
			gotV6.IngressVlanID, convIngressVlanIDV6)
	}
}

// TestBPFSessionValueLiftsIngressIdentity pins the READ direction on its own:
// an on-map entry that already carries the #4983 identity must surface it on
// the Go SessionValue the CLI and the HA sync path read.
//
// The fixture is a bpfSessionValue built DIRECTLY rather than produced by
// toBPF. Feeding this direction from the other one would reintroduce the
// symmetry the round trip already has, and the point of this test is to
// observe the lift against a value toBPF never touched — which is the real
// case: the record was written by the Rust helper, not by Go.
//
// RED on revert: delete `IngressIfindex: v.IngressIfindex` (or the VlanID
// line) from either sessionValue in bpf_session_value.go.
func TestBPFSessionValueLiftsIngressIdentity(t *testing.T) {
	gotV4 := bpfSessionValue{
		IngressIfindex: convIngressIfindexV4,
		IngressVlanID:  convIngressVlanIDV4,
	}.sessionValue()
	if gotV4.IngressIfindex != convIngressIfindexV4 {
		t.Errorf("v4 sessionValue().IngressIfindex = %d, want %d — a record the "+
			"helper wrote WITH an ingress binding is lifted with the wrong value "+
			"in the ifindex field (dropped, or read from the wrong on-map field), "+
			"so the exact interface filter either points at the wrong NIC or "+
			"silently degrades to the zone approximation for every live "+
			"session (#4983)", gotV4.IngressIfindex, convIngressIfindexV4)
	}
	if gotV4.IngressVlanID != convIngressVlanIDV4 {
		t.Errorf("v4 sessionValue().IngressVlanID = %d, want %d (#4983)",
			gotV4.IngressVlanID, convIngressVlanIDV4)
	}

	gotV6 := bpfSessionValueV6{
		IngressIfindex: convIngressIfindexV6,
		IngressVlanID:  convIngressVlanIDV6,
	}.sessionValue()
	if gotV6.IngressIfindex != convIngressIfindexV6 {
		t.Errorf("v6 sessionValue().IngressIfindex = %d, want %d (#4983)",
			gotV6.IngressIfindex, convIngressIfindexV6)
	}
	if gotV6.IngressVlanID != convIngressVlanIDV6 {
		t.Errorf("v6 sessionValue().IngressVlanID = %d, want %d (#4983)",
			gotV6.IngressVlanID, convIngressVlanIDV6)
	}
}
