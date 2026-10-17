package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14634: a sub-byte flexible-match-range field occupies the TOP bits of its
// ceil-byte window (MSB-first from byte-offset, bit-offset 0). The lo0 nft
// text renderer must MSB-align the field value/mask into the window exactly
// as the userspace snapshot builder does, or host-bound traffic is evaluated
// against the LOW bits: `bit-length 4 range 0x4` on first byte 0x45 would
// compare the IHL nibble (5) instead of the version nibble (4).
//
// FAIL-ON-REVERT: drop the alignment in nftFlexMatchExpr and the sub-byte
// rows render `& 0xf == 0x4` (low nibble) instead of `& 0xf0 == 0x40`.
func TestNftFlexMatchExprSubByteMSBAligned14634(t *testing.T) {
	for _, tc := range []struct {
		name string
		fm   config.FlexMatchConfig
		want string
	}{
		{"sub-byte-4-default-mask", config.FlexMatchConfig{MatchStart: "layer-3", ByteOffset: 0, BitLength: 4, Value: 0x4, Mask: 0xF}, "@nh,0,8 & 0xf0 == 0x40"},
		{"sub-byte-4-explicit-mask", config.FlexMatchConfig{MatchStart: "layer-3", ByteOffset: 0, BitLength: 4, Value: 0x4, Mask: 0xF}, "@nh,0,8 & 0xf0 == 0x40"},
		{"sub-byte-12", config.FlexMatchConfig{MatchStart: "layer-3", ByteOffset: 6, BitLength: 12, Value: 0xABC, Mask: 0xFFF}, "@nh,48,16 & 0xfff0 == 0xabc0"},
		{"sub-byte-20", config.FlexMatchConfig{MatchStart: "layer-3", ByteOffset: 0, BitLength: 20, Value: 0xABCDE, Mask: 0xFFFFF}, "@nh,0,24 & 0xfffff0 == 0xabcde0"},
		{"byte-aligned-8-control", config.FlexMatchConfig{MatchStart: "layer-3", ByteOffset: 9, BitLength: 8, Value: 0x11, Mask: 0xFF}, "@nh,72,8 & 0xff == 0x11"},
		{"full-32-control", config.FlexMatchConfig{MatchStart: "layer-3", ByteOffset: 12, BitLength: 32, Value: 0x0A000001, Mask: 0xFFFFFFFF}, "@nh,96,32 & 0xffffffff == 0xa000001"},
		{"layer-4-sub-byte-4", config.FlexMatchConfig{MatchStart: "layer-4", ByteOffset: 0, BitLength: 4, Value: 0x4, Mask: 0xF}, "@th,0,8 & 0xf0 == 0x40"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := nftFlexMatchExpr(tc.fm); got != tc.want {
				t.Errorf("nftFlexMatchExpr(%+v) = %q, want %q — the sub-byte field must be MSB-aligned into its ceil-byte window (#14634)", tc.fm, got, tc.want)
			}
		})
	}
}

// End-to-end through the term renderer: a representable sub-byte term must
// render the aligned predicate (not match-nothing, not the low bits).
func TestNftRuleSubByteFlexRendersAligned14634(t *testing.T) {
	fm := config.FlexMatchConfig{MatchStart: "layer-3", ByteOffset: 0, BitLength: 4, Value: 0x4, Mask: 0xF}
	got := nftRule(t, &config.FirewallFilterTerm{
		Name: "flex-subbyte", FlexMatch: &fm, Action: "discard",
	}, "ip", map[string]*config.PrefixList{})
	if !strings.Contains(got, "@nh,0,8 & 0xf0 == 0x40") {
		t.Errorf("sub-byte term rendered %q, want it to contain %q", got, "@nh,0,8 & 0xf0 == 0x40")
	}
}
