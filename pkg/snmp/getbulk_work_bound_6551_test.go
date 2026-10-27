package snmp

import (
	"bytes"
	"math"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6551: GETBULK used to materialize the whole repeaters x max-repetitions grid
// BEFORE the RFC 3416 §4.2.3 response-size bound was applied. repeaterCount is
// len(oids)-nonRepeaters and is bounded only by how many varbinds a manager can
// pack into one request datagram, and every grid cell costs a findNextOIDSnap
// MIB walk plus a getOIDValueSnap.
//
// Measured on the pre-fix code with 50 interfaces, a 4094-byte v2c GETBULK
// carrying 580 minimal repeater OIDs and max-repetitions >= 100:
//
//	varbinds BUILT   58,000   (405 ms inside buildBulkVarbinds)
//	varbinds RETURNED   116   (4092-byte response)
//	end-to-end handlePacket   667 ms   vs a ~2.5 us single-varbind poll
//
// (the trim itself accounts for the remaining ~260 ms: trimToFit binary-searches
// ~log2(58000) = 16 full re-encodes of the 58,000-varbind list). ~1.5 requests
// per second saturate the single serial SNMP goroutine permanently.
//
// Post-fix the same request builds 118 varbinds in 48 us and answers in 1.0 ms,
// returning the identical 116 varbinds.
//
// These tests assert on varbinds BUILT, not returned: the returned count was
// always ~116, so a test that only checked the response would pass on the
// unfixed code.

// minVarbindEncodedBytes is a lower bound on the bytes any varbind can occupy
// in an encoded varbind list: a SEQUENCE header (tag + 1 length byte, a minimal
// body being far below 128) wrapping an OID TLV and a value TLV, each at least
// a bare tag + length byte. 2+2+2.
//
// It is used for one thing only — capping how many cells a build that stops at
// the response ceiling could possibly have produced — and for that a valid
// floor is all that is required. The floor is attained only by the degenerate
// shape berEncodeOID emits a nil body for (an OID with fewer than two
// components), which TestVarbindEncodedLenMatchesEncoder_6551 exercises as
// "short-oid-no-body". buildBulkVarbinds cannot produce one from a real
// request: its OIDs are either walked out of the MIB or echoed from the
// request, and berDecodeOID rejects an empty body while turning any non-empty
// one into at least two components, so every varbind reachable from the wire
// re-encodes to at least 7 bytes. A floor of 6 therefore makes the cap
// CONSERVATIVE, never unsound. TestWireVarbindByteFloors_6551 pins both halves
// of that.
//
// The cap bounds the CELL COUNT of the build. It says nothing about whether the
// response fits: real returned varbinds carry full OIDs and values and are far
// larger than any floor. Fitting is trimToFit's job, and the equality oracle
// TestGetBulkBoundedMatchesUnbounded_6551 is what proves the stop does not
// disturb it.
const minVarbindEncodedBytes = 6

// varbindListEncodedLen sums the exact encoded size of a varbind list.
func varbindListEncodedLen(vbs []varbind) int {
	total := 0
	for _, vb := range vbs {
		total += varbindEncodedLen(vb)
	}
	return total
}

// maxRepeaterBulkRequest builds the largest v2c GETBULK datagram that still fits
// in maxPacketSize, packing as many copies of start as possible as repeater
// OIDs. It returns the datagram and the repeater count, which is the R that
// multiplies max-repetitions in the grid.
func maxRepeaterBulkRequest(t *testing.T, community string, maxReps int, start []int) (req []byte, repeaters int) {
	t.Helper()
	var oids [][]int
	for {
		cand := append(oids, start)
		next := buildV2cGetBulkRequest(community, 1, 0, maxReps, cand)
		if len(next) > maxPacketSize {
			break
		}
		oids, req = cand, next
	}
	if len(oids) == 0 {
		t.Fatalf("no repeater OID fits in %d bytes", maxPacketSize)
	}
	return req, len(oids)
}

// bulkTestAgent returns a v2c agent serving n synthetic interfaces.
func bulkTestAgent(n int) *Agent {
	a := NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"public": {Name: "public", Authorization: "read-only"},
		},
	})
	a.SetIfDataFn(func() []IfData { return manyIfData(n) })
	return a
}

// decodeBulkPDU strips the v2c envelope off a GETBULK request and returns the
// decoded, clamp-applied PDU fields the handler would work from.
func decodeBulkPDU(t *testing.T, req []byte) (nonRepeaters, maxRepetitions int, oids [][]int) {
	t.Helper()
	_, body, err := berDecodeHeader(req)
	if err != nil {
		t.Fatalf("request: outer SEQUENCE: %v", err)
	}
	_, rest, err := berDecodeInteger(body) // version
	if err != nil {
		t.Fatalf("request: version: %v", err)
	}
	_, rest, err = berDecodeOctetString(rest) // community
	if err != nil {
		t.Fatalf("request: community: %v", err)
	}
	_, pduBody, err := berDecodeHeader(rest)
	if err != nil {
		t.Fatalf("request: PDU header: %v", err)
	}
	_, nonRepeaters, maxRepetitions, oids, err = decodePDUFields(pduBody)
	if err != nil {
		t.Fatalf("request: PDU fields: %v", err)
	}
	if maxRepetitions > 100 {
		maxRepetitions = 100 // the handler's own defense-in-depth clamp
	}
	return nonRepeaters, maxRepetitions, oids
}

// TestGetBulkBuildBounded_6551 is the fail-on-revert guard. It drives the
// worst-case shape — a max-size datagram of minimal repeater OIDs with
// max-repetitions clamped to 100 — straight at buildBulkVarbinds and asserts on
// how many varbinds it BUILT.
//
// To neutralize the fix for a RED-on-revert check, make bulkBudget.add always
// report false (`return false` as its body); that compiles cleanly and restores
// the unbounded grid, and this test then fails on the built-count assertions.
func TestGetBulkBuildBounded_6551(t *testing.T) {
	a := bulkTestAgent(50)
	req, repeaters := maxRepeaterBulkRequest(t, "public", 100000, []int{1, 3})
	nonRep, maxReps, oids := decodeBulkPDU(t, req)

	if repeaters < 100 {
		t.Fatalf("test is not exercising the defect: only %d repeaters fit", repeaters)
	}
	if maxReps != 100 {
		t.Fatalf("max-repetitions clamp = %d, want 100", maxReps)
	}
	grid := repeaters * maxReps // what the pre-fix code materialized

	maxSize := effectiveMaxSize(maxPacketSize)
	built := a.buildBulkVarbinds(oids, nonRep, maxReps, a.newIfSnapshot(), maxSize)

	// (1) Structural bound: every varbind occupies at least
	// minVarbindEncodedBytes on the wire, so a build that stops at the response
	// ceiling can never produce more than maxSize/minVarbindEncodedBytes cells
	// (+1 for the cell that trips the budget).
	hardCap := maxSize/minVarbindEncodedBytes + 1
	if len(built) > hardCap {
		t.Fatalf("buildBulkVarbinds built %d varbinds for a %d-byte ceiling; "+
			"at >= %d bytes each no more than %d can ever be returned "+
			"(grid was %d cells, each a MIB walk)",
			len(built), maxSize, minVarbindEncodedBytes, hardCap, grid)
	}

	// (2) Exact invariant: everything built except the cell that tripped the
	// budget must still fit the ceiling. This is the real contract — "never
	// build more than can be returned" — and it is what makes the work
	// proportional to the response rather than to R*M.
	if n := len(built); n > 1 {
		if used := varbindListEncodedLen(built[:n-1]); used > maxSize {
			t.Fatalf("varbinds built beyond the ceiling: built[:%d] encodes to %d bytes > %d",
				n-1, used, maxSize)
		}
	}

	// (3) Amplification: the response for this request is ~116 varbinds. The
	// pre-fix build/return ratio was 500x.
	resp := a.handlePacket(req)
	if resp == nil {
		t.Fatal("nil response")
	}
	errStatus, returned := v2cResponseVarbinds(t, resp)
	if errStatus != errNoError {
		t.Fatalf("error-status = %d, want noError", errStatus)
	}
	if len(returned) == 0 {
		t.Fatal("no varbinds returned; manager cannot continue the walk")
	}
	// Every cell the grid builds past the returned prefix is pure waste. The
	// envelope (version/community/PDU headers) costs at most a handful of
	// varbinds' worth of budget, so a correct stop overshoots by a tiny margin.
	if len(built) > len(returned)+16 {
		t.Fatalf("built %d varbinds to return %d (%.0fx amplification); "+
			"the grid is not bounded by the response ceiling",
			len(built), len(returned), float64(len(built))/float64(len(returned)))
	}
	t.Logf("grid %d cells -> built %d -> returned %d (%d-byte response)",
		grid, len(built), len(returned), len(resp))
}

// getBulkAllocs is the v2c counterpart to v3GetBulkAllocs below, and measures
// the same thing for the same reason: every grid cell allocates, so the count
// rises with the number of cells actually walked. It is a COUNT, so machine
// load cannot move it — which a duration could, and did (#8211).
func getBulkAllocs(t *testing.T, a *Agent, req []byte) float64 {
	t.Helper()
	return testing.AllocsPerRun(3, func() {
		if a.handlePacket(req) == nil {
			t.Fatal("nil response")
		}
	})
}

// TestGetBulkCostDoesNotScaleWithMaxRepetitions_6551 guards the v2c CALL SITE
// (handleGetBulk, agent.go). The assertions above drive buildBulkVarbinds
// directly with the real ceiling, so they would still pass if handleGetBulk
// started handing it an effectively infinite budget. This one goes through
// handlePacket and pins the property that actually matters end to end: once the
// response ceiling is reached, answering a GETBULK must cost the same whether
// the manager asked for 1 repetition or 100.
//
// It covers v2c ONLY. The v3 dispatcher is a separate call site that computes
// its own ceiling, and unbounding it leaves every assertion here green —
// TestGetBulkCostDoesNotScaleWithMaxRepetitionsV3_6551 below is its guard.
//
// Allocations are the work proxy, matching the v3 twin below — see
// getBulkAllocs for why every grid cell allocates. Pre-fix the R*100 grid costs
// ~100x the R*1 grid (58,000 cells vs 580); post-fix both stop at the same ~118
// cells and the ratio sits near 1. The 10x threshold has an order of magnitude
// of headroom on both sides.
//
// This measured WALL TIME until #8211. The rationale then recorded here was
// that a ratio of two measurements on one machine makes load cancel out; that
// is false, and the test flaked in full-suite gates at load ~39 while the diff
// under review could not reach pkg/snmp. Load does not cancel because the two
// readings are taken at different moments — a scheduling hiccup landing on one
// of them moves the ratio and nothing else does. A count has no such exposure.
// See docs/engineering-style.md, "Time in tests", clause 1.
func TestGetBulkCostDoesNotScaleWithMaxRepetitions_6551(t *testing.T) {
	a := bulkTestAgent(50)
	oneRep, _ := maxRepeaterBulkRequest(t, "public", 1, []int{1, 3})
	manyRep, repeaters := maxRepeaterBulkRequest(t, "public", 100, []int{1, 3})

	one, many := getBulkAllocs(t, a, oneRep), getBulkAllocs(t, a, manyRep)
	// Not a Skip. A skip is indistinguishable from a pass in every summary line
	// and CI badge, so the guard would silently stop running and nothing would
	// say so. Zero allocations at M=1 cannot mean "unsuitable machine" now that
	// the measure is a count — it can only mean the probe never reached the
	// walk, which is a broken test. See docs/engineering-style.md clause 2.
	if one <= 0 {
		t.Fatalf("no allocations measured at max-repetitions=1 (%v); the probe is not measuring the walk", one)
	}

	ratio := many / one
	t.Logf("%d repeaters: max-repetitions=1 %.0f allocs, max-repetitions=100 %.0f allocs (ratio %.1fx)",
		repeaters, one, many, ratio)
	if ratio > 10 {
		t.Fatalf("GETBULK cost scales with max-repetitions: %.0f allocs at M=1 vs %.0f at M=100 (%.1fx); "+
			"the grid is still expanding past the response ceiling", one, many, ratio)
	}
}

// TestGetBulkBuildBoundedV3_6551 is the same guard for the SNMPv3 path, which
// shares buildBulkVarbinds but bounds against the manager-advertised
// msgMaxSize. An unbounded grid hurts more here: every trimToFit rebuild re-runs
// USM framing and HMAC over the whole varbind list.
func TestGetBulkBuildBoundedV3_6551(t *testing.T) {
	a, authKey, engineID, boots, tm := v3GetBulkAgent(t, manyIfData(50))

	// Pack the v3 request with as many minimal repeater OIDs as fit.
	var oids [][]int
	var req []byte
	for {
		cand := append(oids, []int{1, 3})
		next := buildV3GetBulkRequest(t, "sha", "alice", engineID, authKey, boots, tm,
			maxPacketSize, 0, 100, cand)
		if len(next) > maxPacketSize {
			break
		}
		oids, req = cand, next
	}
	if len(oids) < 100 {
		t.Fatalf("test is not exercising the defect: only %d v3 repeaters fit", len(oids))
	}

	maxSize := effectiveMaxSize(maxPacketSize)
	built := a.buildBulkVarbinds(oids, 0, 100, a.newIfSnapshot(), maxSize)
	hardCap := maxSize/minVarbindEncodedBytes + 1
	if len(built) > hardCap {
		t.Fatalf("v3 buildBulkVarbinds built %d varbinds for a %d-byte ceiling, cap %d (grid was %d cells)",
			len(built), maxSize, hardCap, len(oids)*100)
	}

	resp := a.handlePacketFrom(req, nil)
	if resp == nil {
		t.Fatal("nil v3 response")
	}
	if len(resp) > maxPacketSize {
		t.Fatalf("v3 response %d bytes exceeds %d", len(resp), maxPacketSize)
	}
	errStatus, returned := v3ResponseErrorStatus(t, resp)
	if errStatus != errNoError {
		t.Fatalf("v3 error-status = %d, want noError", errStatus)
	}
	if len(built) > len(returned)+16 {
		t.Fatalf("v3 built %d varbinds to return %d; grid not bounded by the ceiling",
			len(built), len(returned))
	}
	t.Logf("v3: grid %d cells -> built %d -> returned %d (%d-byte response)",
		len(oids)*100, len(built), len(returned), len(resp))
}

// v3MaxRepeaterBulkRequest builds the largest SNMPv3 authNoPriv GETBULK
// datagram that still fits in maxPacketSize, packing as many minimal repeater
// OIDs as the USM envelope leaves room for. It returns the datagram and the
// repeater count R that multiplies max-repetitions in the grid.
func v3MaxRepeaterBulkRequest(t *testing.T, engineID, authKey []byte, boots, tm, maxReps int) (req []byte, repeaters int) {
	t.Helper()
	var oids [][]int
	for {
		cand := append(oids, []int{1, 3})
		next := buildV3GetBulkRequest(t, "sha", "alice", engineID, authKey, boots, tm,
			maxPacketSize, 0, maxReps, cand)
		if len(next) > maxPacketSize {
			break
		}
		oids, req = cand, next
	}
	if len(oids) == 0 {
		t.Fatalf("no v3 repeater OID fits in %d bytes", maxPacketSize)
	}
	return req, len(oids)
}

// v3GetBulkAllocs returns the mean number of heap allocations the agent
// performs answering req end to end through the real v3 dispatcher.
//
// Allocations are the work proxy here rather than wall time. Every grid cell
// allocates — findNextOIDSnap returns a freshly built OID and getOIDValueSnap a
// freshly encoded value — and every trimToFit rebuild re-encodes the surviving
// prefix under USM, so the count rises with the number of cells actually
// walked. Unlike a duration it is a count: it cannot be moved by machine load,
// so the comparison below is deterministic rather than a timing race.
func v3GetBulkAllocs(t *testing.T, a *Agent, req []byte) float64 {
	t.Helper()
	return testing.AllocsPerRun(3, func() {
		if a.handlePacketFrom(req, nil) == nil {
			t.Fatal("nil v3 response")
		}
	})
}

// TestGetBulkCostDoesNotScaleWithMaxRepetitionsV3_6551 guards the SNMPv3 CALL
// SITE. It is deliberately NOT shared with the v2c sibling: the two entry
// points are separate surfaces that each compute and pass their own ceiling
// (handleGetBulk passes effectiveMaxSize(maxPacketSize), the v3 dispatcher
// effectiveMaxSize(msgMaxSize)), so a regression that unbounds one leaves the
// other correct and a single shared test re-masks the split.
//
// TestGetBulkBuildBoundedV3_6551 above cannot cover this: it calls
// buildBulkVarbinds itself with the real ceiling, so its built-count assertions
// hold no matter what budget v3.go passes. Everything it checks about the
// handlePacketFrom response — size, error-status, varbind count — is identical
// bounded or not, because trimToFit produces the same bytes either way. That is
// the whole point of the fix being output-neutral, and it is why only a COST
// assertion can see the difference.
//
// The pinned property is the v2c sibling's: once the response ceiling is
// reached, answering a GETBULK must cost the same whether the manager asked for
// 1 repetition or 100. With R repeaters filling the datagram, an unbounded grid
// walks R cells at M=1 and R*100 at M=100, while a bounded one stops at the
// same ~120 cells in both. The 10x threshold sits an order of magnitude below
// the ~100x an unbounded v3 call site produces and an order of magnitude above
// the ~1x a bounded one does.
func TestGetBulkCostDoesNotScaleWithMaxRepetitionsV3_6551(t *testing.T) {
	a, authKey, engineID, boots, tm := v3GetBulkAgent(t, manyIfData(50))
	oneRep, _ := v3MaxRepeaterBulkRequest(t, engineID, authKey, boots, tm, 1)
	manyRep, repeaters := v3MaxRepeaterBulkRequest(t, engineID, authKey, boots, tm, 100)
	if repeaters < 100 {
		t.Fatalf("test is not exercising the defect: only %d v3 repeaters fit", repeaters)
	}

	// Both requests must actually be answered; a v3 auth/timeliness reject
	// would make this a comparison of two report PDUs and prove nothing.
	for name, req := range map[string][]byte{"max-repetitions=1": oneRep, "max-repetitions=100": manyRep} {
		resp := a.handlePacketFrom(req, nil)
		if resp == nil {
			t.Fatalf("%s: nil v3 response", name)
		}
		if errStatus, returned := v3ResponseErrorStatus(t, resp); errStatus != errNoError || len(returned) == 0 {
			t.Fatalf("%s: error-status = %d with %d varbinds; want noError with a non-empty walk",
				name, errStatus, len(returned))
		}
	}

	one, many := v3GetBulkAllocs(t, a, oneRep), v3GetBulkAllocs(t, a, manyRep)
	if one <= 0 {
		t.Fatalf("no allocations measured at max-repetitions=1 (%v); the probe is not measuring the walk", one)
	}

	ratio := many / one
	t.Logf("v3 %d repeaters: max-repetitions=1 %.0f allocs, max-repetitions=100 %.0f allocs (ratio %.1fx)",
		repeaters, one, many, ratio)
	if ratio > 10 {
		t.Fatalf("v3 GETBULK cost scales with max-repetitions: %.0f allocs at M=1 vs %.0f at M=100 (%.1fx); "+
			"the v3 call site is not handing buildBulkVarbinds the response ceiling", one, many, ratio)
	}
}

// TestGetBulkBoundedMatchesUnbounded_6551 is the over-reach guard. Stopping the
// grid early must be output-neutral: for every shape, the response built from
// the bounded grid must be BYTE-IDENTICAL to the one built from the full
// (pre-fix) grid, because the cells the stop drops are exactly the ones
// trimToFit would have discarded.
//
// math.MaxInt as the budget reproduces the pre-fix expansion exactly — the
// budget never trips — so the comparison is against the real old behavior, not
// against a restatement of the new one.
//
// The walk start OIDs deliberately sit at or after sysUpTime in the static OID
// order, so no varbind in these responses carries the live TimeTicks counter,
// which would otherwise differ between the two builds for reasons unrelated to
// the bound.
func TestGetBulkBoundedMatchesUnbounded_6551(t *testing.T) {
	deepTail := []int{1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 18, 50}
	cases := []struct {
		name         string
		ifaces       int
		nonRepeaters int
		maxReps      int
		oids         [][]int
	}{
		// Ordinary small requests: must be untouched by the bound.
		{"small-one-repeater", 1, 0, 3, [][]int{oidSysUpTime}},
		{"small-three-columns", 4, 0, 5, [][]int{oidSysUpTime, oidIfTablePrefix, oidIfXTablePrefix}},
		{"small-with-nonrepeaters", 4, 2, 4, [][]int{oidSysUpTime, oidIfNumber, oidIfTablePrefix, oidIfXTablePrefix}},
		// MIB exhaustion: columns run off the end of the view and emit
		// endOfMibView placeholders; the bound must not disturb that.
		{"exhausted-columns", 2, 0, 40, [][]int{deepTail, oidIfXTablePrefix}},
		{"exhausted-nonrepeater", 2, 1, 20, [][]int{deepTail, oidIfTablePrefix}},
		// Oversized: the bound actually fires and the response is trimmed.
		{"oversized-single-column", 50, 0, 100, [][]int{oidIfTablePrefix}},
		{"oversized-deep-tail", 50, 0, 100, [][]int{deepTail}},
		{"oversized-many-columns", 50, 0, 100, repeatOID(oidIfTablePrefix, 60)},
		{"oversized-with-nonrepeaters", 50, 3, 100, repeatOID(oidIfXTablePrefix, 40)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := bulkTestAgent(tc.ifaces)
			maxSize := effectiveMaxSize(maxPacketSize)
			build := func(vbs []varbind) []byte {
				return a.buildResponse([]byte("public"), 42, errNoError, 0, vbs)
			}

			bounded := a.buildBulkVarbinds(tc.oids, tc.nonRepeaters, tc.maxReps, a.newIfSnapshot(), maxSize)
			unbounded := a.buildBulkVarbinds(tc.oids, tc.nonRepeaters, tc.maxReps, a.newIfSnapshot(), math.MaxInt)

			if len(bounded) > len(unbounded) {
				t.Fatalf("bounded build produced MORE varbinds (%d) than the unbounded one (%d)",
					len(bounded), len(unbounded))
			}
			// The bounded list must be a prefix of the unbounded one: same
			// cells, same order, just stopped early (RFC 3416 §4.2.3 removes
			// from the END of the ordered set).
			for i := range bounded {
				if !oidEqual(bounded[i].oid, unbounded[i].oid) ||
					bounded[i].tag != unbounded[i].tag ||
					!bytes.Equal(bounded[i].value, unbounded[i].value) {
					t.Fatalf("varbind[%d] differs: bounded {oid=%v tag=0x%02x} vs unbounded {oid=%v tag=0x%02x}",
						i, bounded[i].oid, bounded[i].tag, unbounded[i].oid, unbounded[i].tag)
				}
			}

			boundedResp, okB := trimToFit(bounded, maxSize, build)
			unboundedResp, okU := trimToFit(unbounded, maxSize, build)
			if okB != okU {
				t.Fatalf("trimToFit ok mismatch: bounded=%v unbounded=%v", okB, okU)
			}
			if !bytes.Equal(boundedResp, unboundedResp) {
				t.Fatalf("response differs from the unbounded build: %d bytes vs %d bytes",
					len(boundedResp), len(unboundedResp))
			}
			if len(boundedResp) > maxSize {
				t.Fatalf("response %d bytes exceeds ceiling %d", len(boundedResp), maxSize)
			}
			t.Logf("grid %d cells, built %d (unbounded %d), response %d bytes",
				len(tc.oids)*tc.maxReps, len(bounded), len(unbounded), len(boundedResp))
		})
	}
}

// repeatOID returns n copies of oid, for building wide repeater lists.
func repeatOID(oid []int, n int) [][]int {
	out := make([][]int, n)
	for i := range out {
		out[i] = oid
	}
	return out
}

// TestVarbindEncodedLenMatchesEncoder_6551 pins varbindEncodedLen to what the
// response encoder actually emits. The bound is only output-neutral while the
// accounted size is a true lower bound on the encoded message: an OVERestimate
// would stop the grid short of varbinds that would have fit and silently shrink
// every large GETBULK response. The expected value is read back off a real
// encoded response rather than recomputed, so this fails if the two encodings
// ever drift apart.
//
// #17055: every case runs through BOTH buildResponse (v2c) and
// buildV3Response (noAuthNoPriv, so the scopedPDU is on the wire in the
// clear). Before consolidation the v3 copy was a separate loop the old
// v2c-only pin could not see: a stray-element mutant inside every v3
// varbind SEQUENCE passed the whole package. The v3 leg extracts the
// varbind the same TLV-walking way and additionally decodes it with the
// tightened decodeVarbindsFull, which requires exactly two elements.
func TestVarbindEncodedLenMatchesEncoder_6551(t *testing.T) {
	a := bulkTestAgent(1)
	long := make([]byte, 300) // forces a multi-byte BER length header
	for i := range long {
		long[i] = 'x'
	}
	cases := []struct {
		name string
		vb   varbind
	}{
		{"short-oid-octet-string", varbind{oid: oidSysDescr, tag: tagOctetString, value: []byte("xpf")}},
		{"empty-value", varbind{oid: oidSysContact, tag: tagOctetString, value: nil}},
		{"long-value-multibyte-length", varbind{oid: oidSysLocation, tag: tagOctetString, value: long}},
		{"integer", varbind{oid: oidIfNumber, tag: tagInteger, value: berEncodeIntegerValue(42)}},
		{"counter64", varbind{oid: []int{1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 6, 1}, tag: tagCounter64,
			value: berEncodeCounter64(18000000000000000000)}},
		{"end-of-mib-view", varbind{oid: []int{1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 18, 50}, tag: tagEndOfMibView}},
		{"no-such-instance", varbind{oid: oidSysName, tag: tagNoSuchInstance}},
		{"no-such-object", varbind{oid: oidSysObjectID, tag: tagNoSuchObject}},
		{"large-subid-oid", varbind{oid: []int{1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 2097151}, tag: tagInteger,
			value: berEncodeIntegerValue(1)}},
		{"short-oid-no-body", varbind{oid: []int{1}, tag: tagEndOfMibView}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := a.buildResponse([]byte("public"), 1, errNoError, 0, []varbind{tc.vb})
			want := onlyVarbindEncodedLen(t, resp)
			if got := varbindEncodedLen(tc.vb); got != want {
				t.Fatalf("v2c: varbindEncodedLen = %d, encoder emitted %d bytes", got, want)
			}
		})
		t.Run("v3/"+tc.name, func(t *testing.T) {
			vbList := v3OnlyVarbindList17055(t, tc.vb)
			_, listBody, err := berDecodeHeader(vbList)
			if err != nil {
				t.Fatalf("v3: varbind list header: %v", err)
			}
			if got, want := varbindEncodedLen(tc.vb), berEncodedLen(listBody); got != want {
				t.Fatalf("v3: varbindEncodedLen = %d, encoder emitted %d bytes", got, want)
			}
			// Exactly-two-elements decode (kills the stray-element mutant).
			// Degenerate OIDs (fewer than two components encode to an empty
			// OID body) cannot be OID-decoded; those are covered by the
			// length check above, as in onlyVarbindEncodedLen.
			if len(tc.vb.oid) >= 2 {
				vbs := decodeVarbindsFull(t, vbList)
				if len(vbs) != 1 {
					t.Fatalf("v3: decoded %d varbinds, want 1", len(vbs))
				}
				if vbs[0].valTag != tc.vb.tag {
					t.Fatalf("v3: value tag = 0x%02x, want 0x%02x", vbs[0].valTag, tc.vb.tag)
				}
			}
		})
	}

	// A varbind can never encode to fewer than minVarbindEncodedBytes, which is
	// what the structural cap in TestGetBulkBuildBounded_6551 rests on.
	for _, tc := range cases {
		if n := varbindEncodedLen(tc.vb); n < minVarbindEncodedBytes {
			t.Fatalf("%s: varbindEncodedLen = %d < floor %d", tc.name, n, minVarbindEncodedBytes)
		}
	}
}

// v3OnlyVarbindList17055 builds a noAuthNoPriv SNMPv3 GetResponse carrying
// exactly vb and returns its varbind-list TLV bytes, walking the v3 envelope
// (version / headerData / securityParameters / scopedPDU) by TLV headers.
func v3OnlyVarbindList17055(t *testing.T, vb varbind) []byte {
	t.Helper()
	a := &Agent{
		engineID:    []byte{0x80, 0x00, 0x1f, 0x88, 0x80, 0x17, 0x05, 0x05},
		engineBoots: 1,
		v3Users:     map[string]*usmUser{},
	}
	user := &usmUser{name: "nobody"}
	resp := a.buildV3Response(7, 0, user, nil, 1, errNoError, 0, []varbind{vb})
	if resp == nil {
		t.Fatal("v3: buildV3Response returned nil")
	}
	_, body, err := berDecodeHeader(resp)
	if err != nil {
		t.Fatalf("v3: outer SEQUENCE: %v", err)
	}
	_, rest, err := berDecodeInteger(body) // version
	if err != nil {
		t.Fatalf("v3: version: %v", err)
	}
	// headerData SEQUENCE, then securityParameters OCTET STRING.
	for i := range 2 {
		n := berEncodedLen(rest)
		if n <= 0 || n > len(rest) {
			t.Fatalf("v3: envelope field %d length %d", i, n)
		}
		rest = rest[n:]
	}
	_, scopedBody, err := berDecodeHeader(rest) // scopedPDU SEQUENCE
	if err != nil {
		t.Fatalf("v3: scopedPDU: %v", err)
	}
	for i := range 2 { // contextEngineID, contextName OCTET STRINGs
		n := berEncodedLen(scopedBody)
		if n <= 0 || n > len(scopedBody) {
			t.Fatalf("v3: scoped field %d length %d", i, n)
		}
		scopedBody = scopedBody[n:]
	}
	pduTag, pduBody, err := berDecodeHeader(scopedBody)
	if err != nil || pduTag != pduGetResponse {
		t.Fatalf("v3: PDU tag=0x%02x err=%v", pduTag, err)
	}
	_, pduRest, err := berDecodeInteger(pduBody) // request-id
	if err != nil {
		t.Fatalf("v3: request-id: %v", err)
	}
	_, pduRest, err = berDecodeInteger(pduRest) // error-status
	if err != nil {
		t.Fatalf("v3: error-status: %v", err)
	}
	_, pduRest, err = berDecodeInteger(pduRest) // error-index
	if err != nil {
		t.Fatalf("v3: error-index: %v", err)
	}
	tag, _, err := berDecodeHeader(pduRest)
	if err != nil || tag != tagSequence {
		t.Fatalf("v3: varbind list tag=0x%02x err=%v", tag, err)
	}
	n := berEncodedLen(pduRest)
	if n <= 0 || n > len(pduRest) {
		t.Fatalf("v3: varbind list length %d", n)
	}
	return pduRest[:n]
}

// onlyVarbindEncodedLen returns the encoded byte length of the single varbind in
// a v2c GetResponse, read straight off the wire. It walks TLV headers only and
// never decodes the OID body, so it also measures degenerate shapes (an OID with
// fewer than two components encodes to an empty body, which berDecodeOID
// rejects) — buildBulkVarbinds echoes request OIDs verbatim in its endOfMibView
// cells, so such a varbind is reachable and must still be accounted correctly.
func onlyVarbindEncodedLen(t *testing.T, resp []byte) int {
	t.Helper()
	_, body, err := berDecodeHeader(resp)
	if err != nil {
		t.Fatalf("resp: outer SEQUENCE: %v", err)
	}
	_, rest, err := berDecodeInteger(body) // version
	if err != nil {
		t.Fatalf("resp: version: %v", err)
	}
	_, rest, err = berDecodeOctetString(rest) // community
	if err != nil {
		t.Fatalf("resp: community: %v", err)
	}
	_, pduBody, err := berDecodeHeader(rest)
	if err != nil {
		t.Fatalf("resp: PDU: %v", err)
	}
	_, pduRest, err := berDecodeInteger(pduBody) // request-id
	if err != nil {
		t.Fatalf("resp: request-id: %v", err)
	}
	_, pduRest, err = berDecodeInteger(pduRest) // error-status
	if err != nil {
		t.Fatalf("resp: error-status: %v", err)
	}
	_, pduRest, err = berDecodeInteger(pduRest) // error-index
	if err != nil {
		t.Fatalf("resp: error-index: %v", err)
	}
	tag, vbListBody, err := berDecodeHeader(pduRest)
	if err != nil || tag != tagSequence {
		t.Fatalf("resp: varbind list: %v", err)
	}
	n := berEncodedLen(vbListBody)
	if n <= 0 || n > len(vbListBody) {
		t.Fatalf("resp: varbind length %d out of range (list body %d)", n, len(vbListBody))
	}
	return n
}

// TestWireVarbindByteFloors_6551 binds the two wire-level facts the size
// arithmetic around minVarbindEncodedBytes rests on, so neither can decay into
// prose the decoder no longer supports.
//
//  1. RESPONSE side: a varbind whose OID came off the wire cannot reach the
//     6-byte floor. berDecodeOID rejects an empty body and turns any non-empty
//     one into at least two components, which berEncodeOID re-encodes to at
//     least one content byte, so 7 is the true minimum for a wire-derived
//     varbind. 6 remains a valid floor — that is why the structural cap is
//     sound — but it is a conservative one, not the reachable minimum.
//
//  2. REQUEST side: decodePDUFields does NOT require a varbind to carry a value
//     TLV, so the densest packing it accepts is a 5-byte varbind, not the
//     7-byte well-formed one. Any bound on how many OIDs a single datagram can
//     deliver — and therefore on how many GET/GETNEXT operations one request
//     can buy — has to use 5.
func TestWireVarbindByteFloors_6551(t *testing.T) {
	// (1) Every single-content-byte OID body decodes to two components and
	// re-encodes to a varbind of at least 7 bytes.
	for _, b := range []byte{0x00, 0x2b, 0x7f, 0xff} {
		oid, err := berDecodeOID([]byte{b})
		if err != nil {
			t.Fatalf("berDecodeOID(%#02x): %v", b, err)
		}
		if len(oid) < 2 {
			t.Fatalf("berDecodeOID(%#02x) = %v; a wire OID always yields >= 2 components", b, oid)
		}
		if n := varbindEncodedLen(varbind{oid: oid, tag: tagEndOfMibView}); n < 7 {
			t.Fatalf("wire-derived varbind for %v encodes to %d bytes; want >= 7 "+
				"(the %d-byte floor is only reachable with an empty OID body)",
				oid, n, minVarbindEncodedBytes)
		}
	}
	if _, err := berDecodeOID(nil); err == nil {
		t.Fatalf("berDecodeOID accepted an empty body; the %d-byte floor would then be wire-reachable",
			minVarbindEncodedBytes)
	}
	// The floor itself stays attainable through the encoder, which is what
	// keeps it a floor rather than an overestimate.
	if n := varbindEncodedLen(varbind{oid: []int{1}, tag: tagEndOfMibView}); n != minVarbindEncodedBytes {
		t.Fatalf("short-OID varbind encodes to %d bytes, floor is %d", n, minVarbindEncodedBytes)
	}

	// (2) A request varbind carrying no value TLV at all is accepted, and its
	// OID is delivered to the handler exactly like a well-formed one's.
	valueless := []byte{tagSequence, 0x03, tagObjectIdentifier, 0x01, 0x2b}
	wellFormed := berEncodeTLV(tagSequence,
		append(berEncodeTLV(tagObjectIdentifier, berEncodeOID([]int{1, 3})),
			berEncodeTLV(tagNull, nil)...))
	if len(valueless) != 5 || len(wellFormed) != 7 {
		t.Fatalf("varbind sizes changed: valueless %d bytes, well-formed %d bytes; want 5 and 7",
			len(valueless), len(wellFormed))
	}
	for name, vb := range map[string][]byte{"valueless": valueless, "well-formed": wellFormed} {
		pduBody := berEncodeIntegerTLV(1)                           // request-id
		pduBody = append(pduBody, berEncodeIntegerTLV(0)...)        // non-repeaters
		pduBody = append(pduBody, berEncodeIntegerTLV(0)...)        // max-repetitions
		pduBody = append(pduBody, berEncodeTLV(tagSequence, vb)...) // varbind list
		_, _, _, oids, err := decodePDUFields(pduBody)
		if err != nil {
			t.Fatalf("%s varbind: decodePDUFields: %v", name, err)
		}
		if len(oids) != 1 || !oidEqual(oids[0], []int{1, 3}) {
			t.Fatalf("%s varbind decoded to %v; want exactly one OID [1 3] "+
				"(a value TLV is not required, so 5 bytes is the densest accepted packing)",
				name, oids)
		}
	}

	// (3) The GET/GETNEXT operation ceiling that follows from (2): one
	// operation per decoded request OID, so the most a single datagram can buy
	// is however many varbinds fit the maxPacketSize read buffer. Packed with
	// value-less varbinds that is materially more than the well-formed packing,
	// which is exactly why the ceiling has to be derived from 5 bytes.
	valuelessOIDs := densestGetNextOIDs(t, valueless)
	wellFormedOIDs := densestGetNextOIDs(t, wellFormed)
	if valuelessOIDs <= wellFormedOIDs {
		t.Fatalf("value-less packing delivered %d OIDs, well-formed %d; the denser packing must win",
			valuelessOIDs, wellFormedOIDs)
	}
	if valuelessOIDs < 700 || valuelessOIDs > 900 {
		t.Fatalf("densest GETNEXT datagram delivers %d OIDs; README documents ~800 operations "+
			"as the per-datagram ceiling", valuelessOIDs)
	}
	t.Logf("max-size GETNEXT delivers %d OIDs packed value-less (%d bytes each) vs %d well-formed (%d bytes each)",
		valuelessOIDs, len(valueless), wellFormedOIDs, len(wellFormed))
}

// densestGetNextOIDs packs copies of one encoded request varbind into the
// largest v2c GETNEXT datagram that still fits maxPacketSize and returns how
// many OIDs the agent's decoder actually delivers from it — i.e. how many
// findNextOIDSnap operations that one datagram buys.
func densestGetNextOIDs(t *testing.T, vb []byte) int {
	t.Helper()
	var packed []byte
	for {
		cand := append(packed, vb...)
		pdu := berEncodeIntegerTLV(1)                         // request-id
		pdu = append(pdu, berEncodeIntegerTLV(0)...)          // error-status
		pdu = append(pdu, berEncodeIntegerTLV(0)...)          // error-index
		pdu = append(pdu, berEncodeTLV(tagSequence, cand)...) // varbind list
		msg := berEncodeIntegerTLV(snmpVersion2c)
		msg = append(msg, berEncodeTLV(tagOctetString, []byte("public"))...)
		msg = append(msg, berEncodeTLV(pduGetNextRequest, pdu)...)
		if len(berEncodeTLV(tagSequence, msg)) > maxPacketSize {
			break
		}
		packed = cand
	}
	pdu := berEncodeIntegerTLV(1)
	pdu = append(pdu, berEncodeIntegerTLV(0)...)
	pdu = append(pdu, berEncodeIntegerTLV(0)...)
	pdu = append(pdu, berEncodeTLV(tagSequence, packed)...)
	_, _, _, oids, err := decodePDUFields(pdu)
	if err != nil {
		t.Fatalf("densest GETNEXT PDU: decodePDUFields: %v", err)
	}
	return len(oids)
}

// TestGetBulkTrimmedTailIsWellFormed_6551 checks the truncated response is one a
// normal manager can act on, not merely a smaller one: the varbind list decodes
// cleanly, stays in repetition-major order (varbind index nonRepeaters+rep*R+col
// per RFC 3416 §4.2.3 / #5065), the tail is a complete varbind rather than a
// severed one, and any endOfMibView marker sits in its own column's cell.
func TestGetBulkTrimmedTailIsWellFormed_6551(t *testing.T) {
	const repeaters = 3
	a := bulkTestAgent(50)
	oids := [][]int{oidIfTablePrefix, oidIfXTablePrefix, []int{1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 18, 40}}
	req := buildV2cGetBulkRequest("public", 7, 0, 100, oids)

	resp := a.handlePacket(req)
	if resp == nil {
		t.Fatal("nil response")
	}
	if len(resp) > maxPacketSize {
		t.Fatalf("response %d bytes exceeds %d", len(resp), maxPacketSize)
	}
	// decodeVarbindOIDs fatals on any malformed varbind, so a clean decode is
	// itself the well-formedness check.
	errStatus, got := v2cResponseVarbinds(t, resp)
	if errStatus != errNoError {
		t.Fatalf("error-status = %d, want noError", errStatus)
	}
	if len(got) < repeaters {
		t.Fatalf("only %d varbinds returned; not even one full repetition", len(got))
	}

	// The response must be the leading prefix of the unbounded grid, so each
	// returned varbind still lands in its originating column.
	full := a.buildBulkVarbinds(oids, 0, 100, a.newIfSnapshot(), math.MaxInt)
	if len(got) > len(full) {
		t.Fatalf("returned %d varbinds, grid only has %d", len(got), len(full))
	}
	for i := range got {
		if !oidEqual(got[i], full[i].oid) {
			t.Fatalf("varbind[%d] OID %v is not the grid's cell %v (order or column alignment broken)",
				i, got[i], full[i].oid)
		}
	}

	// Column 2 starts at the ifXTable tail and exhausts almost immediately, so
	// its cells become endOfMibView while columns 0/1 keep returning data —
	// exactly the per-column placeholder contract. Verify the exhausted column's
	// cells carry endOfMibView and the others do not.
	sawExhausted := false
	for i := 0; i+repeaters <= len(got); i += repeaters {
		if full[i+2].tag == tagEndOfMibView {
			sawExhausted = true
		}
		for col := 0; col < 2; col++ {
			if full[i+col].tag == tagEndOfMibView {
				t.Fatalf("column %d cell at varbind %d is endOfMibView; it should still have data",
					col, i+col)
			}
		}
	}
	if !sawExhausted {
		t.Fatal("test did not exercise an exhausted column; endOfMibView placement unverified")
	}
}
