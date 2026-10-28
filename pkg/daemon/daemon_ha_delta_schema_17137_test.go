package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/wireschema"
)

// #17137: the production Go half of the #7194 fail-closed fingerprint
// gate must agree with production Rust output, not with itself.
//
// Before this cell, localSessionDeltaSchemaFingerprint() was derived
// from a pkg/daemon-only extractor (sessionDeltaWireNames) that no test
// compared with anything: the cross-language cells compared two
// test-only extractors. A one-token mutant (keeping ",omitempty" in the
// name) flipped the live gate to MISMATCH against every helper while
// every pkg/daemon test stayed green. The extraction is now the single
// wireschema.WireNamesOf consumed by both the daemon gate and
// the parity tests, and this cell pins the daemon's fingerprint to the
// keys of the #16132 fixture's session_delta_info specimen — bytes the
// Rust producer actually emitted (serde serialisation of
// SessionDeltaInfo), regenerated whenever the Rust struct changes.
//
// FAIL-ON-REVERT: break wireschema.WireNamesOf (e.g. keep the
// ",omitempty" suffix, or mishandle `json:"-"`) and this cell reds
// because the daemon fingerprint no longer matches the fingerprint of
// the Rust-emitted key set. Break the Rust side instead (e.g.
// #[serde(skip_serializing)] on one SessionDeltaInfo field, fixture
// regenerated) and the fixture key set shrinks while the Go struct
// still carries the field, so this cell reds the other way.
func TestProductionDeltaSchemaMatchesRustFixture17137(t *testing.T) {
	path := filepath.Join("..", "..", "userspace-dp", "tests", "fixtures",
		"protocol_wire_v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("wire fixture must exist (no skip-on-missing): %s: %v", path, err)
	}
	var fixture map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	specimen, ok := fixture["session_delta_info"]
	if !ok {
		t.Fatalf("%s no longer carries a session_delta_info specimen; "+
			"the production fingerprint has no Rust oracle to compare with", path)
	}
	var emitted map[string]json.RawMessage
	if err := json.Unmarshal(specimen, &emitted); err != nil {
		t.Fatalf("session_delta_info specimen is not a JSON object: %v", err)
	}
	names := make([]string, 0, len(emitted))
	for name := range emitted {
		names = append(names, name)
	}
	sort.Strings(names)
	// Anti-vacuity floor: a truncated or renamed specimen must not let
	// this pass over a near-empty set. Mirrors the #7194 parity floor.
	if len(names) < 35 {
		t.Fatalf("session_delta_info specimen carries only %d keys (floor 35); "+
			"the fixture extraction is broken, so a clean result here would certify nothing",
			len(names))
	}

	rustFP := dpuserspace.SessionDeltaSchemaFingerprintOf(names)
	local := localSessionDeltaSchemaFingerprint()
	if local != rustFP {
		t.Errorf("production session-delta fingerprints disagree:\n"+
			"  daemon (wireschema over Go struct): %#x\n"+
			"  rust fixture (serde-emitted keys):  %#x\n"+
			"  daemon schema: %v\n  rust keys:     %v\n"+
			"A drift here flips the #7194 gate to MISMATCH against every "+
			"helper and withholds all HA session sync (#17137)",
			local, rustFP,
			dpuserspace.SessionDeltaSchemaCanonicalOf(wireschema.WireNamesOf(dpuserspace.SessionDeltaInfo{})),
			dpuserspace.SessionDeltaSchemaCanonicalOf(names))
	}
	if local == 0 {
		t.Error("production fingerprint must never be 0 — 0 is reserved for not-advertised")
	}
}
