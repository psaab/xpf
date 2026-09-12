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

// #9714 review F1: the refusal token Go matches is the one the helper sends. If the
// two drift, every refused peer delete reads as applied and Go deletes the mirror and
// DNAT rows of the flow the helper kept.
func TestThePeerDeleteRefusalTokenMatchesTheHelper9714(t *testing.T) {
	strip := func(path string) string {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		var out strings.Builder
		for _, line := range strings.Split(string(src), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				out.WriteString("\n")
				continue
			}
			out.WriteString(line)
			out.WriteString("\n")
		}
		return out.String()
	}
	const prefix = "synced-delete-refused:"
	importSrc := strip("../../../userspace-dp/src/afxdp/ha/session_import.rs")
	handlerSrc := strip("../../../userspace-dp/src/server/handlers/sync_session.rs")
	if !strings.Contains(importSrc, `pub const SYNCED_DELETE_REFUSED_PREFIX: &str = "`+prefix+`";`) {
		t.Errorf("the helper's SYNCED_DELETE_REFUSED_PREFIX is no longer %q", prefix)
	}
	if !strings.Contains(handlerSrc, `format!("{SYNCED_DELETE_REFUSED_PREFIX}peer-delete-local-owned")`) {
		t.Errorf("the sync_session handler no longer answers a refused peer delete with " +
			"{SYNCED_DELETE_REFUSED_PREFIX}peer-delete-local-owned")
	}
	if peerDeleteRefusedLocalOwned != prefix+"peer-delete-local-owned" {
		t.Errorf("Go matches %q, the helper sends %q", peerDeleteRefusedLocalOwned, prefix+"peer-delete-local-owned")
	}
}
