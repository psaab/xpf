package userspace

import (
	"testing"
)

// TestDecodeSessionEventAllocsBudget9905 pins the F-083 fix: binary open-frame
// decode must be pure copies with no string format/parse round trip. Base cost
// is 7 allocs/op (5x Sprintf IP + 2x Sprintf MAC); the binary carry-through
// removes all of them.
func TestDecodeSessionEventAllocsBudget9905(t *testing.T) {
	payload := buildSessionOpenV4Payload(
		6, 12345, 443,
		[4]byte{10, 0, 1, 2}, [4]byte{172, 16, 0, 1},
		[4]byte{192, 0, 2, 7}, [4]byte{198, 51, 100, 9},
		23456, 0,
		1, 12, 11, 0, 80, 0, 1, 2, 0,
		[6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		[6]byte{0x02, 0xbf, 0x72, 0x00, 0x50, 0x08},
		[4]byte{172, 16, 80, 1},
	)
	if _, ok := decodeSessionEvent(payload); !ok {
		t.Fatal("fixture: open payload does not decode, the budget assertion would be vacuous")
	}
	allocs := testing.AllocsPerRun(200, func() {
		if _, ok := decodeSessionEvent(payload); !ok {
			panic("fixture payload stopped decoding")
		}
	})
	t.Logf("decodeSessionEvent: %.1f allocs/op", allocs)
	if allocs > 0 {
		t.Fatalf("decodeSessionEvent = %.1f allocs/op, want 0 (binary decode must be pure copies, #9905 F-083)", allocs)
	}
}

// TestDecodeSessionCloseEventAllocsBudget9905 is the close-frame twin: 2 Sprintf
// allocs on base, 0 after the binary carry-through.
func TestDecodeSessionCloseEventAllocsBudget9905(t *testing.T) {
	payload := buildSessionCloseV4Payload(
		6, 12345, 443,
		[4]byte{10, 0, 1, 2}, [4]byte{172, 16, 0, 1},
		1, 0, 1, 2,
	)
	if _, ok := decodeSessionCloseEvent(payload); !ok {
		t.Fatal("fixture: close payload does not decode, the budget assertion would be vacuous")
	}
	allocs := testing.AllocsPerRun(200, func() {
		if _, ok := decodeSessionCloseEvent(payload); !ok {
			panic("fixture payload stopped decoding")
		}
	})
	t.Logf("decodeSessionCloseEvent: %.1f allocs/op", allocs)
	if allocs > 0 {
		t.Fatalf("decodeSessionCloseEvent = %.1f allocs/op, want 0 (#9905 F-083)", allocs)
	}
}
