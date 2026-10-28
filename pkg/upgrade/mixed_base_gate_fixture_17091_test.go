package upgrade

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestMixedBaseGateFixture17091 pins the single Go mixed-base rule
// (GateProtocolCompat) against the SHARED cross-language fixture
// scripts/deploy/mixed_base_gate_fixture.json (#17091), following the
// version_fixture_16190 pattern. The Python executor
// (_gate_mixed_base in scripts/deploy/xpf-deploy.py, the LANE-2 gate)
// consumes the same file in MixedBaseFixture17091Tests, so the two
// bodies can no longer drift behind retyped vector tables.
//
// RED on mutation: flip the unknown-wire leg (peerWire == 0 under
// RefuseUnknownWire returns Compatible) and the
// unknown-wire-refuse-policy row fails; drop the exact-match leg
// (peerWire != target.SessionSyncProtocol) and sync-mismatch fails;
// widen the HA window and peer-below-floor / peer-newer-than-target
// fail. In Python, the same mutations red MixedBaseFixture17091Tests.
//
// The negative-peer-wire row is python_only: Go's peer wire is a uint16
// (parsed fail-closed upstream), so only the Python string-dict executor
// can represent it; Go's parse-side rejection stays pinned by
// TestParseImageVersions_NegativeSessionSync_FailsClosed.
func TestMixedBaseGateFixture17091(t *testing.T) {
	path := filepath.Join("..", "..", "scripts", "deploy",
		"mixed_base_gate_fixture.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	var fx struct {
		Cases []struct {
			Name   string `json:"name"`
			Target *struct {
				HA    uint16 `json:"ha"`
				Floor uint16 `json:"floor"`
				Sync  int    `json:"sync"`
			} `json:"target"`
			Missing    []string `json:"missing"`
			PeerHA     uint16   `json:"peer_ha"`
			PeerWire   int      `json:"peer_wire"`
			Policy     string   `json:"policy"`
			Expected   string   `json:"expected"`
			PythonOnly bool     `json:"python_only"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("parse fixture %s: %v", path, err)
	}
	if len(fx.Cases) == 0 {
		t.Fatalf("fixture %s has no cases", path)
	}
	ran := 0
	for _, c := range fx.Cases {
		if c.PythonOnly {
			continue
		}
		if c.PeerWire < 0 || c.PeerWire > 0xFFFF {
			t.Errorf("fixture %q: peer_wire %d not representable in Go uint16 and not python_only", c.Name, c.PeerWire)
			continue
		}
		ran++
		var target *ImageVersions
		if c.Target != nil {
			target = &ImageVersions{
				HAProtocol:          c.Target.HA,
				HAProtocolMinCompat: c.Target.Floor,
				SessionSyncProtocol: c.Target.Sync,
				present: map[string]bool{
					"ha-protocol-version":           true,
					"ha-protocol-min-compat":        true,
					"session-sync-protocol-version": true,
				},
			}
			for _, k := range c.Missing {
				delete(target.present, k)
			}
		}
		var policy UnknownWirePolicy
		switch c.Policy {
		case "refuse":
			policy = RefuseUnknownWire
		case "permit":
			policy = PermitUnknownWire
		default:
			t.Errorf("fixture %q: policy %q, want refuse|permit", c.Name, c.Policy)
			continue
		}
		v := GateProtocolCompat(target, c.PeerHA, uint16(c.PeerWire), policy)
		switch c.Expected {
		case "survive":
			if v.Err != nil || !v.Compatible {
				t.Errorf("fixture %q: got compatible=%v err=%v (%s), want survive", c.Name, v.Compatible, v.Err, v.Reason)
			}
		case "refuse":
			if v.Err != nil || v.Compatible {
				t.Errorf("fixture %q: got compatible=%v err=%v (%s), want refuse without error", c.Name, v.Compatible, v.Err, v.Reason)
			}
			if v.Reason == "" {
				t.Errorf("fixture %q: refusal returned no reason", c.Name)
			}
		case "error":
			if v.Err == nil || v.Compatible {
				t.Errorf("fixture %q: got compatible=%v err=%v (%s), want target error", c.Name, v.Compatible, v.Err, v.Reason)
			}
		default:
			t.Errorf("fixture %q: expected %q, want survive|refuse|error", c.Name, c.Expected)
		}
		// The LANE-1 adapter must agree on every permit-policy row (it is
		// GateProtocolCompat with PermitUnknownWire): a second skeleton
		// creeping back into targetWireVerdict reds here.
		if c.Policy == "permit" && c.Target != nil {
			ok, _, aerr := targetWireVerdict(target, uint16(c.PeerWire), c.PeerHA)
			wantOK := c.Expected == "survive"
			if ok != wantOK || (aerr != nil) != (c.Expected == "error") {
				t.Errorf("fixture %q: targetWireVerdict ok=%v err=%v, want ok=%v (GateProtocolCompat adapter drift)", c.Name, ok, aerr, wantOK)
			}
		}
	}
	if ran == 0 {
		t.Fatal("fixture had no Go-runnable cases (all python_only?)")
	}
}
