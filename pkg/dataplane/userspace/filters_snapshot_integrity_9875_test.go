package userspace

import (
	"encoding/json"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9875: the firewall-filter snapshot builder previously emitted a term whose
// `from` block carried a match leaf the dataplane does not enforce
// (term.UnknownFrom, #3307) or a value-bearing leaf written with NO operand
// (term.ValuelessFrom, #8480) as just the surviving match set — byte-identical
// to a term authored without the leaf — so an accept term over-permitted and
// a discard/reject term over-dropped with no signal past the boot warning.
// These guards pin the corrected FromUnrepresentable wire marker; reverting
// the builder change makes each assert FAIL.

// TestFilterSnapshotUnknownFromSetsMarker_9875 is the FAIL-ON-REVERT guard
// for the UnknownFrom half: a term carrying an unenforced `from` leaf must
// set the FromUnrepresentable wire marker so the Rust filter compiler fails
// the snapshot CLOSED.
func TestFilterSnapshotUnknownFromSetsMarker_9875(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
			Name:        "ttl-term",
			Action:      "accept",
			Protocols:   []string{"tcp"},
			UnknownFrom: []string{"ttl"},
		}}},
	}
	term := buildFirewallFilterSnapshots(cfg)[0].Terms[0]
	if !term.FromUnrepresentable {
		t.Error("an unenforced from leaf must set FromUnrepresentable (#9875 fail-open)")
	}
	// The surviving match still rides the wire — the Rust side rejects the
	// WHOLE snapshot on the marker, never a widened matcher.
	if len(term.Protocols) != 1 || term.Protocols[0] != "tcp" {
		t.Errorf("surviving match must be emitted alongside the marker, got %v", term.Protocols)
	}
}

// TestFilterSnapshotValuelessFromSetsMarker_9875 is the FAIL-ON-REVERT guard
// for the ValuelessFrom half: a term carrying a value-bearing leaf written
// with NO operand must set the FromUnrepresentable wire marker.
func TestFilterSnapshotValuelessFromSetsMarker_9875(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
			Name:          "empty-proto",
			Action:        "discard",
			ValuelessFrom: []string{"protocol"},
		}}},
	}
	term := buildFirewallFilterSnapshots(cfg)[0].Terms[0]
	if !term.FromUnrepresentable {
		t.Error("a valueless from leaf must set FromUnrepresentable (#9875 fail-open)")
	}
}

// TestFilterSnapshotRepresentableFromSetsNoMarker_9875 proves the marker is
// keyed on the recording lists, not on every from-scoped term: a fully
// representable term carries no marker.
func TestFilterSnapshotRepresentableFromSetsNoMarker_9875(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
			Name:             "ok",
			Action:           "accept",
			Protocols:        []string{"tcp"},
			DestinationPorts: []string{"22"},
		}}},
	}
	term := buildFirewallFilterSnapshots(cfg)[0].Terms[0]
	if term.FromUnrepresentable {
		t.Error("a fully representable term must carry no unrepresentable marker")
	}
}

// TestFilterSnapshotLenientUnknownFromSetsMarker_9875 is the end-to-end #9875
// guard for the UnknownFrom half: flat-set syntax through the TOLERANT
// compile path (CompileConfigLenient — the boot / HA peer-sync path the
// strict gate downgrades to a warning) to the wire snapshot. `from protocol
// tcp` + `from ttl 64` + `then accept` must produce the marker AND keep the
// surviving match on the wire.
func TestFilterSnapshotLenientUnknownFromSetsMarker_9875(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set firewall family inet filter f term t from protocol tcp",
		"set firewall family inet filter f term t from ttl 64",
		"set firewall family inet filter f term t then accept",
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	term := buildFirewallFilterSnapshots(cfg)[0].Terms[0]
	if !term.FromUnrepresentable {
		t.Error("a leniently-loaded term with an unenforced from leaf must set FromUnrepresentable (#9875)")
	}
	if len(term.Protocols) != 1 || term.Protocols[0] != "tcp" {
		t.Errorf("the surviving match must ride the wire alongside the marker, got %v", term.Protocols)
	}
}

// TestFilterSnapshotLenientValuelessFromSetsMarker_9875 is the end-to-end
// #9875 guard for the ValuelessFrom half: `from protocol` (no operand) +
// `then discard` through the tolerant compile path must produce the marker.
func TestFilterSnapshotLenientValuelessFromSetsMarker_9875(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set firewall family inet filter f term t from protocol",
		"set firewall family inet filter f term t then discard",
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	term := buildFirewallFilterSnapshots(cfg)[0].Terms[0]
	if !term.FromUnrepresentable {
		t.Error("a leniently-loaded term with a valueless from leaf must set FromUnrepresentable (#9875)")
	}
}

// TestFirewallTermSnapshotFromUnrepresentableWireKey_9875 is the Go-encode
// half of the cross-language wire contract: the exact JSON key the Rust
// consumer (userspace-dp protocol/security.rs, pinned by
// firewall_term_snapshot_from_unrepresentable_wire_key_9875) decodes. A key
// rename on this side fails this test instead of silently decoding to the
// default (false) on the Rust side — which would re-open the widening the
// marker closes.
func TestFirewallTermSnapshotFromUnrepresentableWireKey_9875(t *testing.T) {
	body, err := json.Marshal(FirewallTermSnapshot{
		Name:                "t",
		Action:              "discard",
		FromUnrepresentable: true,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded["from_unrepresentable"] != true {
		t.Errorf("wire key from_unrepresentable must be present and true, got %v (%s)",
			decoded["from_unrepresentable"], body)
	}

	// omitempty keeps the marker off the wire when clear — an older Rust
	// helper (serde default) and an older Go decoder both see the pre-#9875
	// shape (#1961 parity).
	clearBody, err := json.Marshal(FirewallTermSnapshot{Name: "t", Action: "accept"})
	if err != nil {
		t.Fatalf("marshal clear: %v", err)
	}
	var clearDecoded map[string]any
	if err := json.Unmarshal(clearBody, &clearDecoded); err != nil {
		t.Fatalf("unmarshal clear: %v", err)
	}
	if _, present := clearDecoded["from_unrepresentable"]; present {
		t.Errorf("a clear FromUnrepresentable must be omitted (omitempty), got %s", clearBody)
	}
}
