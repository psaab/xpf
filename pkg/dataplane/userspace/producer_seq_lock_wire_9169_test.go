package userspace

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// #9169: the helper's process-global event-stream `producer_seq_lock` is the
// FOURTH #4800 new-flow contention site. Every session delta — Open as well as
// Close — allocates its wire sequence number and encodes its frame inside that
// mutex, because #3878 F-152 requires the allocation and the channel enqueue to
// be atomic together. `docs/userspace-newflow-ceiling.md` named three sites and
// not this one, so a run bound here reported a real plateau with every named
// site cold.
//
// This file pins the WIRE for the counter pair that closes that gap, in the
// same shape as the #6842 / #6929 guards: neither side is pinned to a literal.
// The Rust key is read out of the `#[serde(rename = ...)]` attribute, the Go key
// out of the struct tag by reflection, and the test asserts they AGREE. A
// literal would encode which of the two spellings is trusted, and the failure
// being guarded is that one plane moved and the other did not.
//
// WHY THIS PAIR NEEDS THE GUARD. Both fields are additive: `default` on the
// Rust side, `omitempty` on the Go side. A key mismatch therefore never fails a
// decode — the counter reads 0 forever. And 0 is not a suspicious reading here,
// it is the reading the #4800 analyzer prints as `ratio: None`, "never taken",
// for a mutex that is in fact taken on every single delta. The instrument would
// look present and say nothing, which is worse than its absence: absence at
// least left the site unnamed rather than exonerated.
func TestProducerSeqLockWireKeysLockstepWithRust9169(t *testing.T) {
	for _, tc := range []struct {
		rustField string
		goField   string
		probe     uint64
		read      func(ProcessStatus) uint64
		other     func(ProcessStatus) uint64
		otherName string
	}{
		{
			rustField: "event_stream_producer_seq_lock_acquisitions_total",
			goField:   "EventStreamProducerSeqLockAcquisitionsTotal",
			probe:     9169,
			read:      func(s ProcessStatus) uint64 { return s.EventStreamProducerSeqLockAcquisitionsTotal },
			other:     func(s ProcessStatus) uint64 { return s.EventStreamProducerSeqLockContendedTotal },
			otherName: "EventStreamProducerSeqLockContendedTotal",
		},
		{
			rustField: "event_stream_producer_seq_lock_contended_total",
			goField:   "EventStreamProducerSeqLockContendedTotal",
			probe:     41,
			read:      func(s ProcessStatus) uint64 { return s.EventStreamProducerSeqLockContendedTotal },
			other:     func(s ProcessStatus) uint64 { return s.EventStreamProducerSeqLockAcquisitionsTotal },
			otherName: "EventStreamProducerSeqLockAcquisitionsTotal",
		},
	} {
		// #7160: resolved by FIELD, not by file path — `ProcessStatus` moved out
		// of `control.rs` when that file crossed the modularity floor.
		rustKey := rustWireKeyInProtocolStruct(t, "ProcessStatus", tc.rustField, false)

		field, ok := reflect.TypeOf(ProcessStatus{}).FieldByName(tc.goField)
		if !ok {
			t.Fatalf("ProcessStatus has no field %s — the guard cannot run", tc.goField)
		}
		goKey, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if goKey != rustKey {
			t.Fatalf("wire-key drift: Go ProcessStatus.%s decodes %q, userspace-dp emits %q. "+
				"A mismatch does not fail a decode — the counter reads 0 forever, which the "+
				"#4800 analyzer prints as \"never taken\" for a mutex every session delta "+
				"passes through (#9169)", tc.goField, goKey, rustKey)
		}

		// The decode leg. Agreement between the two spellings does not prove the
		// Go struct reads that key into THIS field — a correctly spelled tag on
		// the wrong field would still pass the comparison above.
		var status ProcessStatus
		payload := []byte(`{"` + rustKey + `":` + itoa9169(tc.probe) + `}`)
		if err := json.Unmarshal(payload, &status); err != nil {
			t.Fatalf("unmarshal %s: %v", payload, err)
		}
		if got := tc.read(status); got != tc.probe {
			t.Fatalf("ProcessStatus.%s = %d after decoding %s, want %d — the Rust key does "+
				"not reach this field", tc.goField, got, payload, tc.probe)
		}
		// The SIBLING must not move. The pair is read as contended/acquisitions,
		// so a tag that aliased one onto the other would report a permanently
		// 100%-contended or permanently quiet site while satisfying every
		// assertion above.
		if got := tc.other(status); got != 0 {
			t.Fatalf("decoding %s also set %s to %d — the two halves of the site-4 pair are "+
				"aliased onto one field, and the analyzer divides one by the other",
				payload, tc.otherName, got)
		}

		// The byte-level leg: the committed wire fixture is the record of what
		// Rust actually writes, closing the loop Go tag -> Rust rename -> bytes.
		// Neither field has `skip_serializing_if`, so both are present (as 0) in
		// a default specimen by design.
		fixture := filepath.Join("..", "..", "..", "userspace-dp", "tests", "fixtures", "protocol_wire_v1.json")
		raw, err := os.ReadFile(fixture)
		if err != nil {
			t.Fatalf("read %s: %v", fixture, err)
		}
		if !strings.Contains(string(raw), `"`+rustKey+`"`) {
			t.Errorf("%s does not contain the key %q that ProcessStatus decodes. The fixture "+
				"is the byte-level record of this wire; a status specimen missing the key "+
				"means the specimen predates the counter or the key moved on one plane only",
				fixture, rustKey)
		}
	}
}

func itoa9169(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
