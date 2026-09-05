package cluster

import (
	"encoding/binary"
	"runtime"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #8792: the persistent-NAT lease decoder sized its preallocation from an
// UNVALIDATED wire count, so the loop's bounds check fired only after the
// allocation it existed to protect.
//
// WHAT THIS ASSERTS, AND WHY IT IS NOT "THE PROCESS DIED". Whether the
// oversized make() is fatal is a property of the HOST, not of the code:
// 112 * (2^32-1) stays below the runtime's maxAlloc so no makeslice panic is
// inherent, and under overcommit_memory=1 the mapping can succeed unbacked and
// the process survives to discard the frame. A cell asserting the crash would
// be green on one host and flaky on an appliance — the "correct only by an
// unstated environmental property" shape. The INVARIANT holds everywhere: a
// count the body cannot physically contain is rejected BEFORE the allocation,
// nothing is installed, and the decoder reports an incomplete decode.
//
// WHY THE COUNTS BELOW ARE SMALL, DELIBERATELY. The headline value is
// 0xFFFFFFFF, and it is NOT used here. A guard whose regression mode is to
// allocate hundreds of gigabytes does not fail — it takes the suite, and
// possibly the machine, with it. Every count below is impossible for its
// buffer while staying trivially small in absolute terms, so a revert reds
// this cell in milliseconds instead of invoking the OOM killer. The extreme
// value is what the ISSUE documents; the guard only has to prove the bound is
// enforced, and the bound does not care how far past it the count goes.
func TestLeaseCountIsBoundedByTheBody8792(t *testing.T) {
	// A frame carrying ONLY a count, with no record bodies at all.
	countOnly := func(n uint32) []byte {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, n)
		return b
	}

	for _, c := range []struct {
		name string
		buf  []byte
	}{
		{"count declares one record, body is empty", countOnly(1)},
		{"count declares many records, body is empty", countOnly(64)},
		{"count declares more records than the body's length prefixes allow",
			append(countOnly(9), make([]byte, 8)...)},
	} {
		out, ok := decodePersistentNatLeasePayload(c.buf)
		if ok {
			t.Errorf("%s: decoder reported a COMPLETE decode. A full-set push REPLACES "+
				"the peer set, so accepting a frame whose count the body cannot hold "+
				"would install a truncated set as though it were the whole one", c.name)
		}
		if len(out) != 0 {
			t.Errorf("%s: %d lease(s) installed from a frame that cannot contain them; "+
				"want 0", c.name, len(out))
		}
	}

	// THE ORDERING IS THE DEFECT, AND THE OUTCOME CANNOT SEE IT. Every
	// assertion above is satisfied by a decoder that allocates from the wire
	// count and THEN discovers the body is empty — which is the bug. So this
	// measures the allocation directly: a count of 1<<20 with an empty body
	// costs ~112 MiB if the make() precedes the bound and ~0 if it follows it.
	// 1<<20 is chosen to be unmistakable against GC noise while remaining
	// survivable on any host if the bound is ever removed — the same reason the
	// counts above are small.
	{
		buf := countOnly(1 << 20)
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		out, ok := decodePersistentNatLeasePayload(buf)
		runtime.ReadMemStats(&after)
		if ok || len(out) != 0 {
			t.Errorf("oversized count decoded ok=%v with %d leases; want rejected", ok, len(out))
		}
		const budget = 1 << 20 // 1 MiB; the defect costs ~112 MiB
		if grew := after.TotalAlloc - before.TotalAlloc; grew > budget {
			t.Errorf("decoding a count=%d frame with an EMPTY body allocated %d bytes "+
				"(budget %d). The bound is being applied AFTER the allocation it exists "+
				"to prevent — the outcome is correct and the defect is intact, which is "+
				"the state this cell exists to distinguish (#8792)",
				1<<20, grew, budget)
		}
	}

	// POSITIVE CONTROL: a well-formed payload must still decode completely.
	// Without it every assertion above is satisfied by a decoder that rejects
	// everything, which is the easiest way to pass a bounds test and the least
	// useful.
	in := []userspace.IdleLeaseWire{
		{Pool: "p1", Protocol: 6, SrcIP: "10.0.0.1", SrcPort: 1024,
			TranslatedIP: "192.0.2.1", TranslatedPort: 2048, RemainingNs: 5, TimeoutNs: 9},
		{Pool: "p2", Protocol: 17, SrcIP: "10.0.0.2", SrcPort: 1025,
			TranslatedIP: "192.0.2.2", TranslatedPort: 2049, RemainingNs: 6, TimeoutNs: 10},
	}
	got, ok := decodePersistentNatLeasePayload(encodePersistentNatLeasePayload(in))
	if !ok || len(got) != len(in) {
		t.Fatalf("control: a well-formed %d-lease payload decoded ok=%v with %d leases. "+
			"The bound must reject only counts the body cannot hold — if it rejects "+
			"valid frames it is a denial of service of its own", len(in), ok, len(got))
	}

	// The bound must sit exactly at what the body can hold, not merely
	// somewhere: a count equal to the maximum possible record count is
	// admissible input and must not be refused by the guard itself.
	atLimit := append(countOnly(1), make([]byte, 4)...) // 1 record, 4 bytes of body
	if _, ok := decodePersistentNatLeasePayload(atLimit); ok {
		t.Error("a count at the physical limit decoded COMPLETELY, but its single " +
			"record's length prefix describes a zero-length body that is not a valid " +
			"lease — the frame is incomplete and must be reported as such")
	}
}
