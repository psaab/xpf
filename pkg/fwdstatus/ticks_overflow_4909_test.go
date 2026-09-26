package fwdstatus

import (
	"math/big"
	"testing"
)

// TestTicksToNanosNoOverflow pins #4909: converting a large scheduler-tick
// count to nanoseconds must not overflow. Multiplying ticks by 1e9 before
// dividing by the runtime USER_HZ wraps uint64 once ticks exceed
// approximately 1.845e10, corrupting the CPU windows used to diagnose
// saturation. Divide-before-multiply preserves the exact conversion.
//
// RED on revert: restore the overflowing intermediate and the wrap/near-wrap
// cases below produce a wrong result, mismatching the big.Int oracle.
func TestTicksToNanosNoOverflow(t *testing.T) {
	// Old intermediate wrap point: 2^64 / 1e9 ≈ 1.8446744073e10 ticks.
	const wrap = ^uint64(0) / 1_000_000_000

	// Upper bound of the inputs: the exact runtime-HZ conversion must still
	// fit uint64 for the tested Linux scheduler rate.
	cases := []uint64{
		0, 1, 99, 100, 101, 12_345,
		wrap - 1, wrap, wrap + 1, wrap + 1000,
		1 << 40,
	}

	bilNano := big.NewInt(1_000_000_000)
	bilHZ := big.NewInt(int64(userHZ))
	for _, ticks := range cases {
		got := ticksToNanos(ticks)

		// Exact expected value via big.Int (no intermediate overflow).
		want := new(big.Int).SetUint64(ticks)
		want.Mul(want, bilNano)
		want.Div(want, bilHZ)
		if !want.IsUint64() {
			// Result itself does not fit uint64 — not exercised by these inputs.
			t.Fatalf("test oracle overflow for ticks=%d", ticks)
		}
		if want.Uint64() != got {
			t.Errorf("ticksToNanos(%d) = %d, want %d (overflow/wrap)", ticks, got, want.Uint64())
		}
	}
}
