package userspace

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestWorkerCommandQueueDropsWireKeyLockstepWithRust6929 pins the JSON key of
// ProcessStatus.WorkerCommandQueueDrops to the key userspace-dp actually emits
// (#6929).
//
// NEITHER SIDE IS PINNED TO A LITERAL, following the #6842 guard: the Rust key
// is read out of the `#[serde(rename = ...)]` attribute on the Rust field, the
// Go key out of the struct tag by reflection, and the test asserts they AGREE.
// A literal would encode which of the two spellings is trusted, and the failure
// being guarded is exactly that one plane moved and the other did not.
//
// WHY THIS COUNTER NEEDS THE GUARD MORE THAN MOST. The field is additive and
// `default`-ed on the Rust side and `omitempty` on the Go side, so a key
// mismatch never fails a decode — it reads 0 forever. For most counters 0 is a
// suspicious value; for this one 0 is the EXPECTED steady state, because the
// worker drain takes the whole deque in a single `core::mem::take` and cannot
// be outrun by a sustained producer. So a broken wire here is not merely
// silent, it is indistinguishable from the healthy case on every operator
// surface, and it stays that way precisely until the condition the counter
// exists to report — a worker that stopped draining while its producers kept
// enqueueing — actually happens.
//
// FAIL-ON-REVERT: change the Go struct tag or the Rust rename without changing
// the other and this reds.
func TestWorkerCommandQueueDropsWireKeyLockstepWithRust6929(t *testing.T) {
	const rustField = "worker_command_queue_drops"
	const goField = "WorkerCommandQueueDrops"

	// #7160: resolved by FIELD, not by file path — `ProcessStatus` moved out
	// of `control.rs` when that file crossed the modularity floor.
	rustKey := rustWireKeyInProtocolStruct(t, "ProcessStatus", rustField, false)

	field, ok := reflect.TypeOf(ProcessStatus{}).FieldByName(goField)
	if !ok {
		t.Fatalf("ProcessStatus has no field %s — the guard cannot run", goField)
	}
	goKey, _, _ := strings.Cut(field.Tag.Get("json"), ",")
	if goKey != rustKey {
		t.Fatalf("wire-key drift: Go ProcessStatus.%s decodes %q, userspace-dp emits %q. "+
			"A mismatch does not fail a decode — the counter reads 0 forever, which is "+
			"also what a healthy firewall reports", goField, goKey, rustKey)
	}

	// The decode leg. Agreement between the two spellings does not prove the
	// Go struct reads that key into THIS field — a correctly spelled tag on
	// the wrong field would still pass the comparison above.
	var status ProcessStatus
	payload := []byte(`{"` + rustKey + `":7}`)
	if err := json.Unmarshal(payload, &status); err != nil {
		t.Fatalf("unmarshal %s: %v", payload, err)
	}
	if status.WorkerCommandQueueDrops != 7 {
		t.Fatalf("ProcessStatus.%s = %d after decoding %s, want 7 — the Rust key does not "+
			"reach this field", goField, status.WorkerCommandQueueDrops, payload)
	}

	// The neighbouring counter must NOT move. The whole argument for a second
	// counter is that a capacity DROP (a command was lost) and a poison
	// RECOVERY (the committed queue survived) are different events with
	// opposite remediations; a tag that aliased one onto the other would fold
	// them back together and satisfy every assertion above.
	if status.WorkerCommandQueuePoisonRecoveries != 0 {
		t.Fatalf("decoding %s also set WorkerCommandQueuePoisonRecoveries to %d — the "+
			"capacity-drop key is aliased onto the poison counter, which reports a "+
			"lossless recovery as a lost command", payload, status.WorkerCommandQueuePoisonRecoveries)
	}

	// The byte-level leg: the committed wire fixture is the record of what
	// Rust actually writes, closing the loop Go tag -> Rust rename -> bytes.
	// The field has no `skip_serializing_if`, so it is present (as 0) in a
	// default specimen by design.
	fixture := filepath.Join("..", "..", "..", "userspace-dp", "tests", "fixtures", "protocol_wire_v1.json")
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("read %s: %v", fixture, err)
	}
	if !strings.Contains(string(raw), `"`+rustKey+`"`) {
		t.Errorf("%s does not contain the key %q that ProcessStatus decodes. The fixture is "+
			"the byte-level record of this wire; a status specimen missing the key means "+
			"the specimen predates the counter or the key moved on one plane only",
			fixture, rustKey)
	}
}
