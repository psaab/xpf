package userspace

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// #9714: the peer-delete mark is a new wire field, and Go and the helper must
// spell its key identically. If they do not, every marked delete reaches the
// helper unmarked and is applied authoritatively — the defect itself — while
// every other #9714 Go cell stays green, because those decode the request with
// the same Go struct that encoded it.
func TestThePeerDeleteWireKeyMatchesTheHelper9714(t *testing.T) {
	marked, err := json.Marshal(SessionSyncRequest{PeerDelete: true})
	if err != nil {
		t.Fatalf("marshal a marked delete: %v", err)
	}
	if !strings.Contains(string(marked), `"peer_delete":true`) {
		t.Errorf("a marked delete does not carry \"peer_delete\":true on the wire: %s", marked)
	}
	unmarked, err := json.Marshal(SessionSyncRequest{})
	if err != nil {
		t.Fatalf("marshal an unmarked delete: %v", err)
	}
	if strings.Contains(string(unmarked), "peer_delete") {
		t.Errorf("an unmarked delete carries the peer_delete key; omitempty is what keeps every "+
			"authoritative delete byte-identical to v15: %s", unmarked)
	}

	src, err := os.ReadFile("../../../userspace-dp/src/protocol/control.rs")
	if err != nil {
		t.Fatalf("read the helper source that decodes the field: %v", err)
	}
	// Strip line comments first: the v16 note quotes the key, and a gate its own
	// documentation can satisfy proves nothing.
	var stripped strings.Builder
	for _, line := range strings.Split(string(src), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			stripped.WriteString("\n")
			continue
		}
		stripped.WriteString(line)
		stripped.WriteString("\n")
	}
	code := stripped.String()
	for _, want := range []string{`#[serde(rename = "peer_delete", default)]`, "pub peer_delete: bool,"} {
		if !strings.Contains(code, want) {
			t.Errorf("the helper's SessionSyncRequest no longer contains %q; a marked Go delete would "+
				"decode as unmarked and delete a live local session (#9714)", want)
		}
	}
}
