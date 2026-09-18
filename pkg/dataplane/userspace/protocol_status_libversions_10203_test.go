package userspace

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func linkedLibVersionSpecimenFields10203(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	path := filepath.Join("..", "..", "..", "userspace-dp", "tests", "fixtures",
		"protocol_wire_v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read Rust wire fixture %s: %v", path, err)
	}
	var fixture map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("parse Rust wire fixture %s: %v", path, err)
	}
	specimen, ok := fixture["process_status_linked_lib_versions"]
	if !ok {
		t.Fatalf("Rust wire fixture has no process_status_linked_lib_versions specimen")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(specimen, &fields); err != nil {
		t.Fatalf("parse linked-version Rust specimen: %v", err)
	}
	return fields
}

// #10203: the #9931 linked libelf/zlib/zstd versions recorded by the Rust
// ProcessStatus must survive a Go decode→encode round-trip. The input is the
// populated Rust serde specimen from protocol_wire_v1.json, not a parallel Go
// literal: a serde/json-tag rename must make this agreement cell fail.
func TestLinkedLibVersionsSurviveGoRoundTrip10203(t *testing.T) {
	rustFields := linkedLibVersionSpecimenFields10203(t)
	specimen, err := json.Marshal(rustFields)
	if err != nil {
		t.Fatalf("marshal Rust specimen fields: %v", err)
	}
	var st ProcessStatus
	if err := json.Unmarshal(specimen, &st); err != nil {
		t.Fatalf("decode Rust ProcessStatus specimen: %v", err)
	}
	out, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("re-encode status: %v", err)
	}
	var goFields map[string]json.RawMessage
	if err := json.Unmarshal(out, &goFields); err != nil {
		t.Fatalf("decode re-encoded status: %v", err)
	}
	for _, key := range []string{
		"linked_libelf_version",
		"linked_zlib_version",
		"linked_zstd_version",
	} {
		rustValue, ok := rustFields[key]
		if !ok {
			t.Fatalf("Rust specimen omits required %q", key)
		}
		var want string
		if err := json.Unmarshal(rustValue, &want); err != nil || want == "" {
			t.Fatalf("Rust specimen %q is not populated: %s", key, rustValue)
		}
		goValue, ok := goFields[key]
		if !ok {
			t.Errorf("Go re-encoding drops Rust specimen key %q", key)
			continue
		}
		var got string
		if err := json.Unmarshal(goValue, &got); err != nil {
			t.Fatalf("decode Go value for %q: %v", key, err)
		}
		if got != want {
			t.Errorf("Go %q = %q, Rust specimen = %q", key, got, want)
		}
	}
}

// TestLinkedLibVersionsKeepOldGoIgnoreCompatibility10203 proves both sides of
// the rolling upgrade: a new Go consumer accepts an old helper's payload with
// empty mirror fields, and an old consumer ignores the new keys by default.
func TestLinkedLibVersionsKeepOldGoIgnoreCompatibility10203(t *testing.T) {
	const oldJSON = `{"pid":99,"enabled":true}`
	var current ProcessStatus
	if err := json.Unmarshal([]byte(oldJSON), &current); err != nil {
		t.Fatalf("decode old helper payload: %v", err)
	}
	if current.LinkedLibelfVersion != "" || current.LinkedZlibVersion != "" || current.LinkedZstdVersion != "" {
		t.Fatalf("old helper payload populated linked versions: %#v", current)
	}

	type oldProcessStatus struct {
		PID     int  `json:"pid"`
		Enabled bool `json:"enabled"`
	}
	const newJSON = `{"pid":100,"enabled":true,"linked_libelf_version":"0.195",` +
		`"linked_zlib_version":"1.3.2","linked_zstd_version":"1.5.7"}`
	var old oldProcessStatus
	if err := json.Unmarshal([]byte(newJSON), &old); err != nil {
		t.Fatalf("old consumer must ignore new version keys: %v", err)
	}
	if old.PID != 100 || !old.Enabled {
		t.Fatalf("old consumer lost existing fields: %#v", old)
	}
}
