package userspace

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
)

// TestSessionDeltaRTFlowSessionIDWireKeyLockstepWithRust6312 pins the Go
// DECODER's JSON key for SessionDeltaInfo.RTFlowSessionID to the key the Rust
// producer actually emits.
//
// #6312 made the JSON session-delta leg carry the #5212 stable RT_FLOW session
// id, which the binary event-stream open frame had carried since #5212 while
// this leg silently dropped it. The Rust side declares the key with
// `#[serde(rename = ...)]` on `SessionDeltaInfo.rt_flow_session_id`
// (userspace-dp/src/protocol/binding.rs); this side reads it through a struct
// tag. Those are two spellings of one contract, and a mismatch is SILENT on both
// planes: the field is simply absent from the decoded struct, Go leaves it 0,
// and 0 is a legitimate value ("no id carried" — the peer allocates a fresh
// local id). That is exactly the pre-#6312 behaviour, so the fix would look
// applied and do nothing.
//
// The key is therefore parsed out of the Rust source rather than restated here:
// a constant written down twice is two constants. Reverting either side's
// spelling reds this.
func TestSessionDeltaRTFlowSessionIDWireKeyLockstepWithRust6312(t *testing.T) {
	// Test cwd is pkg/dataplane/userspace.
	rustKey := rustWireKeyInStruct(t, filepath.Join("..", "..", "..", "userspace-dp", "src", "protocol", "binding.rs"), "SessionDeltaInfo", "rt_flow_session_id", false)

	const want = uint64(7)<<48 | 0x1234_5678
	doc := fmt.Sprintf(`{"event":"open","addr_family":2,"protocol":6,`+
		`"src_ip":"10.0.61.102","dst_ip":"172.16.80.200","src_port":12345,"dst_port":5201,`+
		`%q:%d}`, rustKey, want)

	var info SessionDeltaInfo
	if err := json.Unmarshal([]byte(doc), &info); err != nil {
		t.Fatalf("unmarshal %s: %v", doc, err)
	}
	if info.RTFlowSessionID != want {
		t.Fatalf("RTFlowSessionID = %#x, want %#x. userspace-dp emits the id under the key %q "+
			"(`#[serde(rename = ...)]` in protocol/binding.rs); a Go struct tag that spells it "+
			"differently drops the id back to 0 on the JSON resync leg — the #6312 defect, "+
			"restored silently and with no version to notice it",
			info.RTFlowSessionID, want, rustKey)
	}
	// The tuple decoded too, so the assertion above is about the id key and not
	// about a document the decoder rejected wholesale.
	if info.SrcPort != 12345 || info.Event != "open" {
		t.Fatalf("delta decoded as %+v, want the seeded open tuple", info)
	}

	// An old helper omits the key entirely. That must leave the pre-existing
	// "no id carried" sentinel rather than failing the decode, which is what
	// makes the addition rolling-upgrade safe in the helper-older direction.
	var legacy SessionDeltaInfo
	if err := json.Unmarshal([]byte(`{"event":"open","src_port":12345}`), &legacy); err != nil {
		t.Fatalf("unmarshal legacy delta: %v", err)
	}
	if legacy.RTFlowSessionID != 0 {
		t.Fatalf("legacy delta RTFlowSessionID = %#x, want 0 (the no-id sentinel)",
			legacy.RTFlowSessionID)
	}
}
