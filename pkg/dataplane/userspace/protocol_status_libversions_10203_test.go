package userspace

import (
	"encoding/json"
	"testing"
)

// #10203: the #9931 linked libelf/zlib/zstd versions recorded by the Rust
// ProcessStatus must survive a Go decode→encode round-trip. The fields use
// omitempty so helpers predating #9931 still decode with empty versions and
// retain their old wire shape when re-encoded.
func TestLinkedLibVersionsSurviveGoRoundTrip10203(t *testing.T) {
	const rustJSON = `{"pid":4242,` +
		`"linked_libxdp_version":"1.6.3",` +
		`"linked_libbpf_version":"1.6.3",` +
		`"build_host_libbpf_version":"1.7.0",` +
		`"linked_libelf_version":"0.195",` +
		`"linked_zlib_version":"1.3.2",` +
		`"linked_zstd_version":"1.5.7"}`
	var st ProcessStatus
	if err := json.Unmarshal([]byte(rustJSON), &st); err != nil {
		t.Fatalf("decode Rust-shaped status: %v", err)
	}
	if st.PID != 4242 {
		t.Fatalf("control: PID = %d, want 4242; the key assertions below would prove nothing", st.PID)
	}
	out, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("re-encode status: %v", err)
	}
	var round map[string]any
	if err := json.Unmarshal(out, &round); err != nil {
		t.Fatalf("decode re-encoded status: %v", err)
	}
	for key, want := range map[string]string{
		"linked_libelf_version": "0.195",
		"linked_zlib_version":   "1.3.2",
		"linked_zstd_version":   "1.5.7",
	} {
		got, ok := round[key]
		if !ok {
			t.Errorf("re-encoded status drops %q (want %q): Go has no mirror field", key, want)
			continue
		}
		if got != want {
			t.Errorf("re-encoded %q = %v, want %q", key, got, want)
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
