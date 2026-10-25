package logging

import (
	"encoding/binary"
	"testing"
)

// filter_log_generation_16775_test.go — #16775.
//
// The filter-term syslog gate held the previous config's positional map
// from the dataplane snapshot publish until apply-tail step 14b, and
// FILTER_LOG events carried no generation. During that window a
// `then log`-only hit whose new index collided with an old `then syslog`
// term was forwarded off-box, and a `then syslog` hit at a new index
// was suppressed.
//
// These cells drive stamped FILTER_LOG frames (GEN1 marker at [140:144],
// generation at [144:152]) through the real EventReader gate.

// rawFilterLogFrame16775 builds a FILTER_LOG frame stamped with gen.
func rawFilterLogFrame16775(filterID, termID uint32, generation uint64) []byte {
	data := make([]byte, rawEventFilterLogGenerationSize)
	copy(data, rawFilterLogFrame6859(filterID, termID))
	binary.LittleEndian.PutUint32(data[policyConfigGenerationMarkerOffset:policyConfigGenerationMarkerOffset+4], policyConfigGenerationMarker)
	binary.LittleEndian.PutUint64(data[rawEventFilterLogGenerationOffset:rawEventFilterLogGenerationOffset+8], generation)
	return data
}

func TestFilterLogGenerationStamps16775(t *testing.T) {
	frame := rawFilterLogFrame16775(0, 0, 42)
	got, stamped := filterLogConfigGeneration(frame)
	if !stamped || got != 42 {
		t.Fatalf("filterLogConfigGeneration = %d, %v; want 42, true", got, stamped)
	}
	if _, stamped := filterLogConfigGeneration(rawFilterLogFrame6859(0, 0)); stamped {
		t.Fatal("legacy 144-byte frame must be unstamped")
	}
	// A session frame with the marker must not be read as FILTER_LOG.
	sess := sessionPolicyGenerationFrame(eventTypeSessionOpen, 1, 42)
	if _, stamped := filterLogConfigGeneration(sess); stamped {
		t.Fatal("session frame misread as stamped FILTER_LOG")
	}
}

// TestFilterLogWindowCaseSuppresses16775 is the acceptance probe: the
// window case suppresses (0,0).
//
// Old generation 41 map: (0,0) is `then syslog` (forwarded).
// New generation 42 config: (0,0) is `then log`-only. The dataplane has
// published gen 42 and the reader now holds the gen-42 map (installed
// at publish via SetFilterTermSyslogForGeneration). A queued/backlogged
// gen-41 event at (0,0) — or, symmetrically, any stamped event whose
// generation mismatches the installed map — must NOT be forwarded
// under either map. Pre-fix (no generation), the gen-41 (0,0) event
// resolved against whichever map was installed and left the box.
func TestFilterLogWindowCaseSuppresses16775(t *testing.T) {
	const genOld, genNew = uint64(41), uint64(42)
	reader, _, pc := collectorReader6859(t)
	// New map: (0,0) absent (`then log`), (0,1) present (`then syslog`).
	reader.SetFilterTermSyslogForGeneration(genNew, map[uint64]bool{
		FilterTermSyslogKey(0, 1): true,
	})
	// Window case: stamped old-generation (0,0) hit.
	if ok := reader.ProcessRawEvent(rawFilterLogFrame16775(0, 0, genOld)); !ok {
		t.Fatal("ProcessRawEvent returned false")
	}
	if collectorReceived6859(t, pc) {
		t.Fatal("#16775 window case: a stale-generation (0,0) FILTER_LOG hit was forwarded off-box")
	}
	// Also: a stamped NEW-generation `then log` (0,0) hit is suppressed
	// by the map itself (control for the map half).
	if ok := reader.ProcessRawEvent(rawFilterLogFrame16775(0, 0, genNew)); !ok {
		t.Fatal("ProcessRawEvent returned false")
	}
	if collectorReceived6859(t, pc) {
		t.Fatal("same-generation `then log` (0,0) hit was forwarded")
	}
}

// TestFilterLogSameGenerationControlUnchanged16775 is the paired
// control: a same-generation `then syslog` hit still reaches the
// collector, and the local buffer still records suppressed hits.
func TestFilterLogSameGenerationControlUnchanged16775(t *testing.T) {
	const genNew = uint64(42)
	reader, buffer, pc := collectorReader6859(t)
	reader.SetFilterTermSyslogForGeneration(genNew, map[uint64]bool{
		FilterTermSyslogKey(0, 1): true,
	})
	if ok := reader.ProcessRawEvent(rawFilterLogFrame16775(0, 1, genNew)); !ok {
		t.Fatal("ProcessRawEvent returned false")
	}
	if !collectorReceived6859(t, pc) {
		t.Fatal("same-generation `then syslog` (0,1) hit did not reach the collector")
	}
	// Suppressed hit still visible locally.
	if ok := reader.ProcessRawEvent(rawFilterLogFrame16775(0, 0, genNew)); !ok {
		t.Fatal("ProcessRawEvent returned false")
	}
	recs := buffer.Latest(4)
	found := false
	for _, r := range recs {
		if r.Type == "FILTER_LOG" {
			found = true
		}
	}
	if !found {
		t.Fatal("suppressed FILTER_LOG hit missing from local buffer")
	}
}

// TestFilterLogStaleSyslogIndexSuppressed16775 covers the other window
// direction: a `then syslog` hit at a NEW index queued from the old
// generation must not be resolved under the new map when its stamp is
// stale, and a new-generation hit at that index forwards.
func TestFilterLogStaleGenerationMismatchSuppressesEvenSyslogIndex16775(t *testing.T) {
	const genOld, genNew = uint64(41), uint64(42)
	reader, _, pc := collectorReader6859(t)
	reader.SetFilterTermSyslogForGeneration(genNew, map[uint64]bool{
		FilterTermSyslogKey(0, 1): true,
	})
	// Stamped old-gen event at the new syslog index: generation mismatch
	// suppresses (transient missing record, fail-closed).
	if ok := reader.ProcessRawEvent(rawFilterLogFrame16775(0, 1, genOld)); !ok {
		t.Fatal("ProcessRawEvent returned false")
	}
	if collectorReceived6859(t, pc) {
		t.Fatal("stale-generation event at a syslog index was forwarded under the new map")
	}
}

// TestFilterLogUnstampedLegacyKeepsCurrentMap16775 pins rolling upgrade:
// an unstamped (legacy helper / eBPF) FILTER_LOG frame resolves against
// the current map exactly as pre-#16775.
func TestFilterLogUnstampedLegacyKeepsCurrentMap16775(t *testing.T) {
	const genNew = uint64(42)
	reader, _, pc := collectorReader6859(t)
	reader.SetFilterTermSyslogForGeneration(genNew, map[uint64]bool{
		FilterTermSyslogKey(0, 1): true,
	})
	if ok := reader.ProcessRawEvent(rawFilterLogFrame6859(0, 1)); !ok {
		t.Fatal("ProcessRawEvent returned false")
	}
	if !collectorReceived6859(t, pc) {
		t.Fatal("unstamped legacy `then syslog` hit was suppressed")
	}
	if ok := reader.ProcessRawEvent(rawFilterLogFrame6859(0, 0)); !ok {
		t.Fatal("ProcessRawEvent returned false")
	}
	if collectorReceived6859(t, pc) {
		t.Fatal("unstamped legacy `then log` hit was forwarded")
	}
}

// TestFilterLogUnversionedMapAcceptsStamped16775: a map installed via
// the legacy SetFilterTermSyslog (no generation) does not suppress
// stamped events — generation binding requires a versioned install.
func TestFilterLogUnversionedMapAcceptsStamped16775(t *testing.T) {
	reader, _, pc := collectorReader6859(t)
	reader.SetFilterTermSyslog(map[uint64]bool{FilterTermSyslogKey(0, 1): true})
	if ok := reader.ProcessRawEvent(rawFilterLogFrame16775(0, 1, 99)); !ok {
		t.Fatal("ProcessRawEvent returned false")
	}
	if !collectorReceived6859(t, pc) {
		t.Fatal("stamped hit suppressed under an unversioned map")
	}
	if gen, set := reader.FilterTermSyslogGeneration(); set || gen != 0 {
		t.Fatalf("FilterTermSyslogGeneration = %d,%v; want 0,false", gen, set)
	}
	reader.SetFilterTermSyslogForGeneration(42, map[uint64]bool{})
	if gen, set := reader.FilterTermSyslogGeneration(); !set || gen != 42 {
		t.Fatalf("FilterTermSyslogGeneration = %d,%v; want 42,true", gen, set)
	}
}
