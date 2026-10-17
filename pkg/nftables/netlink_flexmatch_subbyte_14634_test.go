package nftables

import (
	"bytes"
	"testing"

	"github.com/google/nftables/expr"
)

// #14634: a sub-byte flexible-match-range field occupies the TOP bits of its
// ceil-byte window (MSB-first from byte-offset, bit-offset 0). The netlink
// builder takes the LOW bytes of the big-endian value/mask, so it must
// MSB-align the field pair into the window first, or the kernel compares the
// low nibble: `bit-length 4 range 0x4` on first byte 0x45 would read IHL (5)
// instead of version (4).
//
// FAIL-ON-REVERT: drop the alignment in flexMatchExprs and the sub-byte rows
// carry mask/value [0x0f]/[0x04] instead of [0xf0]/[0x40].
func TestFlexMatchExprsSubByteMSBAligned14634(t *testing.T) {
	for _, tc := range []struct {
		name      string
		fm        Lo0FlexMatch
		wantMask  []byte
		wantValue []byte
	}{
		{"sub-byte-4", Lo0FlexMatch{MatchStart: "layer-3", ByteOffset: 0, BitLength: 4, Value: 0x4, Mask: 0xF}, []byte{0xF0}, []byte{0x40}},
		{"sub-byte-12", Lo0FlexMatch{MatchStart: "layer-3", ByteOffset: 6, BitLength: 12, Value: 0xABC, Mask: 0xFFF}, []byte{0xFF, 0xF0}, []byte{0xAB, 0xC0}},
		{"sub-byte-20", Lo0FlexMatch{MatchStart: "layer-3", ByteOffset: 0, BitLength: 20, Value: 0xABCDE, Mask: 0xFFFFF}, []byte{0xFF, 0xFF, 0xF0}, []byte{0xAB, 0xCD, 0xE0}},
		{"byte-aligned-8-control", Lo0FlexMatch{MatchStart: "layer-3", ByteOffset: 9, BitLength: 8, Value: 0x11, Mask: 0xFF}, []byte{0xFF}, []byte{0x11}},
		{"full-32-control", Lo0FlexMatch{MatchStart: "layer-3", ByteOffset: 12, BitLength: 32, Value: 0x0A000001, Mask: 0xFFFFFFFF}, []byte{0xFF, 0xFF, 0xFF, 0xFF}, []byte{0x0A, 0x00, 0x00, 0x01}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exprs := flexMatchExprs(tc.fm)
			var bw *expr.Bitwise
			var cmp *expr.Cmp
			for _, e := range exprs {
				switch v := e.(type) {
				case *expr.Bitwise:
					bw = v
				case *expr.Cmp:
					cmp = v
				}
			}
			if bw == nil || cmp == nil {
				t.Fatalf("flexMatchExprs(%+v) rendered %d exprs without bitwise/cmp", tc.fm, len(exprs))
			}
			if !bytes.Equal(bw.Mask, tc.wantMask) {
				t.Errorf("mask = %x, want MSB-aligned %x (#14634)", bw.Mask, tc.wantMask)
			}
			if !bytes.Equal(cmp.Data, tc.wantValue) {
				t.Errorf("value = %x, want MSB-aligned %x (#14634)", cmp.Data, tc.wantValue)
			}
		})
	}
}
