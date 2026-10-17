package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #3077: `from flexible-match-range` is parsed + compiled into
// config.FirewallFilterTerm.FlexMatch, but the userspace snapshot builder
// previously dropped it — so the byte-offset constraint never reached the sole
// runtime dataplane and the term matched too broadly (fail-open). These tests
// fail on the pre-fix builder (FlexMatch stays nil on the wire) and pass after
// the wire-through fix.

// TestFilterSnapshotFlexMatchSerialized is the FAIL-ON-REVERT guard at the
// snapshot layer. A term carrying flexible-match-range must serialize its
// offset/length/value/mask into the wire snapshot. REVERT (dropping the
// serialization in filters.go) makes FlexMatch go nil and this assert FAIL.
func TestFilterSnapshotFlexMatchSerialized(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"edge": {Name: "edge", Terms: []*config.FirewallFilterTerm{{
			Name:      "flex",
			Protocols: []string{"tcp"},
			Action:    "discard",
			FlexMatch: &config.FlexMatchConfig{
				MatchStart: "layer-3",
				ByteOffset: 6,
				BitLength:  16,
				Value:      0x0800,
				Mask:       0xFFFF,
			},
		}}},
	}
	snaps := buildFirewallFilterSnapshots(cfg)
	if len(snaps) != 1 || len(snaps[0].Terms) != 1 {
		t.Fatalf("expected 1 filter with 1 term, got %#v", snaps)
	}
	fm := snaps[0].Terms[0].FlexMatch
	if fm == nil {
		t.Fatal("flexible-match-range was dropped from the snapshot (#3077 fail-open)")
	}
	if fm.Offset != 6 {
		t.Errorf("flex offset = %d, want 6", fm.Offset)
	}
	// bit-length 16 -> 2 bytes.
	if fm.Length != 2 {
		t.Errorf("flex length = %d, want 2 (16-bit)", fm.Length)
	}
	if fm.Value != 0x0800 {
		t.Errorf("flex value = 0x%04x, want 0x0800", fm.Value)
	}
	if fm.Mask != 0xFFFF {
		t.Errorf("flex mask = 0x%04x, want 0xFFFF", fm.Mask)
	}
}

// TestFilterSnapshotFlexMatchStart is the #3232 wire guard: a `match-start
// layer-4` term carries MatchStart "layer-4" on the wire so the Rust matcher
// reads from the L4 base; layer-3 (the default) maps to "" so the wire stays
// byte-identical to every pre-#3232 term (omitempty). REVERT (drop MatchStart
// from the snapshot builder) makes the layer-4 case carry "" and this FAILS.
func TestFilterSnapshotFlexMatchStart(t *testing.T) {
	cases := []struct {
		start string
		want  string
	}{
		{"layer-3", ""}, // default base — omitted on the wire (byte-identical)
		{"", ""},        // unset also means layer-3
		{"layer-4", "layer-4"},
	}
	for _, tc := range cases {
		cfg := &config.Config{}
		cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
			"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
				Name:   "t",
				Action: "discard",
				FlexMatch: &config.FlexMatchConfig{
					MatchStart: tc.start,
					ByteOffset: 0,
					BitLength:  16,
					Value:      0x0800,
					Mask:       0xFFFF,
				},
			}}},
		}
		fm := buildFirewallFilterSnapshots(cfg)[0].Terms[0].FlexMatch
		if fm == nil {
			t.Fatalf("match-start %q: flex dropped", tc.start)
		}
		if fm.MatchStart != tc.want {
			t.Errorf("match-start %q: wire MatchStart = %q, want %q", tc.start, fm.MatchStart, tc.want)
		}
	}
}

// TestFilterSnapshotFlexMatchValuePreMasked checks the compiled value is ANDed
// with the mask on the wire (mirrors the legacy dataplane FlexValue =
// Value & Mask lowering), so a snapshot value can never carry bits outside the
// mask.
func TestFilterSnapshotFlexMatchValuePreMasked(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
			Name:   "t",
			Action: "discard",
			FlexMatch: &config.FlexMatchConfig{
				MatchStart: "layer-3",
				ByteOffset: 0,
				BitLength:  16,
				Value:      0xFFFF, // bits outside the mask must be stripped
				Mask:       0x00FF,
			},
		}}},
	}
	snaps := buildFirewallFilterSnapshots(cfg)
	fm := snaps[0].Terms[0].FlexMatch
	if fm == nil {
		t.Fatal("flexible-match-range dropped (#3077)")
	}
	if fm.Value != 0x00FF {
		t.Errorf("flex value = 0x%04x, want 0x00FF (pre-masked)", fm.Value)
	}
	if fm.Mask != 0x00FF {
		t.Errorf("flex mask = 0x%04x, want 0x00FF", fm.Mask)
	}
}

// TestFilterSnapshotNoFlexMatchStaysNil confirms a term WITHOUT
// flexible-match-range carries no flex constraint on the wire (no regression
// for the common case — an absent flex-match means NO constraint, not a
// degenerate always-fail match).
func TestFilterSnapshotNoFlexMatchStaysNil(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
			Name: "t", Protocols: []string{"tcp"}, Action: "accept",
		}}},
	}
	snaps := buildFirewallFilterSnapshots(cfg)
	if snaps[0].Terms[0].FlexMatch != nil {
		t.Errorf("term without flexible-match-range must have nil FlexMatch, got %#v",
			snaps[0].Terms[0].FlexMatch)
	}
}

// TestFilterSnapshotFlexMatchDefaultLength confirms a flex-match with an unset
// bit-length defaults to a 4-byte (32-bit) window, matching the legacy
// dataplane lowering (FlexLength defaults to 4).
func TestFilterSnapshotFlexMatchDefaultLength(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
			Name:   "t",
			Action: "discard",
			FlexMatch: &config.FlexMatchConfig{
				MatchStart: "layer-3",
				ByteOffset: 0,
				BitLength:  0, // unset -> default 32-bit
				Value:      0x12345678,
				Mask:       0xFFFFFFFF,
			},
		}}},
	}
	snaps := buildFirewallFilterSnapshots(cfg)
	fm := snaps[0].Terms[0].FlexMatch
	if fm == nil {
		t.Fatal("flexible-match-range dropped (#3077)")
	}
	if fm.Length != 4 {
		t.Errorf("flex length = %d, want 4 (default 32-bit)", fm.Length)
	}
}

// TestFilterSnapshotFlexMatchCeilByteLength is the #3203 #02 guard: a
// non-multiple-of-8 bit-length must round UP to whole bytes so the matcher
// reads enough bytes to cover the field. The old BitLength/8 truncation gave 1
// byte for 12 bits (dropping the trailing nibble) and 2 bytes for 24 bits. The
// byte-aligned 8/16/32-bit cases must stay byte-identical to the #3077 result.
// REVERT (BitLength/8 truncation) -> the 12/24-bit rows FAIL.
func TestFilterSnapshotFlexMatchCeilByteLength(t *testing.T) {
	cases := []struct {
		bits    uint8
		wantLen uint8
	}{
		{8, 1},  // byte-aligned, unchanged
		{12, 2}, // non-multiple-of-8 -> ceil to 2 bytes (was truncated to 1)
		{16, 2}, // byte-aligned, unchanged
		{24, 3}, // byte-aligned, unchanged (was truncated to 2 only if non-mult)
		{20, 3}, // non-multiple-of-8 -> ceil to 3 bytes
		{32, 4}, // byte-aligned, unchanged
	}
	for _, tc := range cases {
		cfg := &config.Config{}
		cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
			"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
				Name:   "t",
				Action: "discard",
				FlexMatch: &config.FlexMatchConfig{
					MatchStart: "layer-3",
					ByteOffset: 0,
					BitLength:  tc.bits,
					Value:      0x1,
					Mask:       0xFFFFFFFF,
				},
			}}},
		}
		snaps := buildFirewallFilterSnapshots(cfg)
		fm := snaps[0].Terms[0].FlexMatch
		if fm == nil {
			t.Fatalf("bit-length %d: flexible-match-range dropped", tc.bits)
		}
		if fm.Length != tc.wantLen {
			t.Errorf("bit-length %d: flex length = %d, want %d", tc.bits, fm.Length, tc.wantLen)
		}
	}
}

// flexAlignMSB14634 converts an operator-authored (value, mask) pair over a
// bit-length field into the MSB-first-aligned wire pair for the ceil-byte
// window (#14634). It is the test-side oracle for the alignment arithmetic:
// the field occupies the TOP bits of the window, so both the expected value
// and the field mask shift left by (windowBits - bitLength).
func flexAlignMSB14634(value, mask uint32, bits uint8) (uint32, uint32) {
	length := (int(bits) + 7) / 8
	shift := uint(length*8 - int(bits))
	return (value & mask) << shift, mask << shift
}

// TestFilterSnapshotFlexMatchSubByteMSBAligned14634 is the #14634
// FAIL-ON-REVERT guard at the snapshot layer. A sub-byte flexible-match-range
// field starts at the byte-offset (bit-offset 0, MSB-first per Junos), so a
// 4-bit field at byte-offset 0 occupies the HIGH nibble of the first byte.
// Pre-fix the compiler defaulted the mask to the low bits, the builder passed
// the pre-masked value/mask verbatim, and the Rust matcher read the LOW
// nibble: `bit-length 4 range 0x4` on wire byte 0x45 matched the IHL nibble
// (5) instead of the version nibble (4) — a discard term failed open and an
// accept term over-permitted, with a clean commit. After the fix the wire
// pair is MSB-aligned and byte 0x45 compares as version=4.
//
// REVERT (drop the alignment in buildFilterTermSnapshots) -> every row whose
// bit-length is not a multiple of 8 FAILS; byte-aligned rows (shift 0) are
// the unchanged control.
func TestFilterSnapshotFlexMatchSubByteMSBAligned14634(t *testing.T) {
	cases := []struct {
		name                string
		bits                uint8
		value, mask         uint32
		wantValue, wantMask uint32
	}{
		// Compiler-default mask (operator wrote no match-mask): 4-bit field,
		// value 0x4 -> wire 0x40/0xF0 (high nibble), so 0x45 matches.
		{"sub-byte-4-default-mask", 4, 0x4, 0xF, 0x40, 0xF0},
		// Explicit Junos match-mask 0xf covers the same 4-bit field and must
		// be shifted identically; only a pre-shifted non-Junos mask (0xF0)
		// avoided the bug pre-fix.
		{"sub-byte-4-explicit-mask", 4, 0x4, 0xF, 0x40, 0xF0},
		// 12-bit field over a 2-byte window: top 12 bits.
		{"sub-byte-12-default-mask", 12, 0xABC, 0xFFF, 0xABC0, 0xFFF0},
		// Trailing partial byte: 20-bit field over 3 bytes.
		{"sub-byte-20-default-mask", 20, 0xABCDE, 0xFFFFF, 0xABCDE0, 0xFFFFF0},
		// Byte-aligned controls: alignment is a no-op (shift 0).
		{"byte-aligned-8-control", 8, 0x11, 0xFF, 0x11, 0xFF},
		{"byte-aligned-16-control", 16, 0x0800, 0xFFFF, 0x0800, 0xFFFF},
		{"full-32-control", 32, 0x12345678, 0xFFFFFFFF, 0x12345678, 0xFFFFFFFF},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
				"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
					Name:   "t",
					Action: "discard",
					FlexMatch: &config.FlexMatchConfig{
						MatchStart: "layer-3",
						ByteOffset: 0,
						BitLength:  tc.bits,
						Value:      tc.value,
						Mask:       tc.mask,
					},
				}}},
			}
			fm := buildFirewallFilterSnapshots(cfg)[0].Terms[0].FlexMatch
			if fm == nil {
				t.Fatalf("bit-length %d: flexible-match-range dropped", tc.bits)
			}
			if fm.Value != tc.wantValue || fm.Mask != tc.wantMask {
				t.Errorf("bit-length %d value 0x%x mask 0x%x: wire = {Value:0x%x Mask:0x%x}, "+
					"want MSB-aligned {Value:0x%x Mask:0x%x} — the sub-byte field must occupy "+
					"the TOP bits of the ceil-byte window, not the low bits (#14634)",
					tc.bits, tc.value, tc.mask, fm.Value, fm.Mask, tc.wantValue, tc.wantMask)
			}
			// Cross-check the oracle helper agrees (guards a typo'd table).
			if ov, om := flexAlignMSB14634(tc.value, tc.mask, tc.bits); ov != tc.wantValue || om != tc.wantMask {
				t.Fatalf("oracle mismatch: flexAlignMSB14634(0x%x,0x%x,%d) = (0x%x,0x%x)", tc.value, tc.mask, tc.bits, ov, om)
			}
		})
	}
}
