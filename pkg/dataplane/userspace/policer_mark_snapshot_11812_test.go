package userspace

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)
// RED on revert: these config-to-snapshot cells catch the single-rate fields
// disappearing after compileFirewall, and require warnings for the runtime
// semantics that remain unsupported.
func TestPolicerMarkingAndLogicalInterfaceSnapshotRetention11812(t *testing.T) {
	cfg := compilePolicerCfg8429(t, []string{
		"set firewall policer loss-priority-pol if-exceeding bandwidth-limit 1m",
		"set firewall policer loss-priority-pol if-exceeding burst-size-limit 15k",
		"set firewall policer loss-priority-pol then loss-priority high",
		"set firewall policer forwarding-class-pol if-exceeding bandwidth-limit 1m",
		"set firewall policer forwarding-class-pol if-exceeding burst-size-limit 15k",
		"set firewall policer forwarding-class-pol then forwarding-class af11",
		"set firewall policer logical-pol if-exceeding bandwidth-limit 1m",
		"set firewall policer logical-pol if-exceeding burst-size-limit 15k",
		"set firewall policer logical-pol logical-interface-policer",
		"set firewall policer logical-pol then discard",
		"set firewall policer discard-pol if-exceeding bandwidth-limit 1m",
		"set firewall policer discard-pol if-exceeding burst-size-limit 15k",
		"set firewall policer discard-pol then discard",
	})
	warnings := config.ValidateConfig(cfg)

	snapshots := make(map[string]PolicerSnapshot)
	for _, snap := range buildPolicerSnapshots(cfg) {
		snapshots[snap.Name] = snap
	}
	if len(snapshots) != 4 {
		t.Fatalf("policer snapshots = %d, want 4: %+v", len(snapshots), snapshots)
	}

	for _, tc := range []struct {
		name   string
		action string
	}{
		{name: "loss-priority-pol", action: "loss-priority high"},
		{name: "forwarding-class-pol", action: "forwarding-class af11"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snap, ok := snapshots[tc.name]
			if !ok {
				t.Fatalf("snapshot for %q missing", tc.name)
			}
			if snap.ThenAction != tc.action {
				t.Errorf("snapshot ThenAction = %q, want %q", snap.ThenAction, tc.action)
			}
			if snap.DiscardExcess {
				t.Error("marking action must retain meter-only behavior, not discard excess")
			}
			matching := 0
			for _, warning := range warnings {
				if strings.Contains(warning, `firewall policer "`+tc.name+`"`) &&
					strings.Contains(warning, "requested loss-priority marking or forwarding-class selection is not applied") &&
					strings.Contains(warning, "excess traffic remains forwarded") {
					matching++
				}
			}
			if matching != 1 {
				t.Errorf("marking warning count = %d, want 1; warnings: %q", matching, warnings)
			}
		})
	}

	t.Run("logical-interface-policer", func(t *testing.T) {
		snap, ok := snapshots["logical-pol"]
		if !ok {
			t.Fatal("snapshot for logical-pol missing")
		}
		if !snap.LogicalInterfacePolicer {
			t.Error("LogicalInterfacePolicer was lost before the snapshot")
		}
		if !snap.DiscardExcess {
			t.Error("then discard must remain set in the snapshot")
		}
		if snap.ThenAction != "" {
			t.Errorf("discard policer unexpectedly retained ThenAction %q", snap.ThenAction)
		}
		matching := 0
		for _, warning := range warnings {
			if strings.Contains(warning, `firewall policer "logical-pol"`) &&
				strings.Contains(warning, "logical-interface-policer") &&
				strings.Contains(warning, "not shared across protocol families on the interface") {
				matching++
			}
		}
		if matching != 1 {
			t.Errorf("logical-interface-policer warning count = %d, want 1; warnings: %q", matching, warnings)
		}
	})

	t.Run("default-discard-json-omits-retention-keys", func(t *testing.T) {
		snap, ok := snapshots["discard-pol"]
		if !ok {
			t.Fatal("snapshot for discard-pol missing")
		}
		wire, err := json.Marshal(snap)
		if err != nil {
			t.Fatalf("marshal discard snapshot: %v", err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(wire, &fields); err != nil {
			t.Fatalf("unmarshal discard snapshot: %v", err)
		}
		for _, key := range []string{"then_action", "logical_interface_policer"} {
			if _, present := fields[key]; present {
				t.Errorf("discard snapshot unexpectedly emitted %q: %s", key, wire)
			}
		}
	})
}

// These optional fields are part of the Go snapshot JSON, but default snapshots
// omit them and the current Rust DTO ignores them until runtime consumers exist.
func TestPolicerSnapshotRetentionJSONIsAdditive11812(t *testing.T) {
	var defaults map[string]json.RawMessage
	defaultJSON, err := json.Marshal(PolicerSnapshot{})
	if err != nil {
		t.Fatalf("marshal default snapshot: %v", err)
	}
	if err := json.Unmarshal(defaultJSON, &defaults); err != nil {
		t.Fatalf("unmarshal default snapshot: %v", err)
	}
	for _, key := range []string{"then_action", "logical_interface_policer"} {
		if _, ok := defaults[key]; ok {
			t.Errorf("default snapshot unexpectedly emitted %q: %s", key, defaultJSON)
		}
	}

	snapshot := PolicerSnapshot{
		ThenAction:              "loss-priority high",
		LogicalInterfacePolicer: true,
	}
	wire, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal populated snapshot: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(wire, &fields); err != nil {
		t.Fatalf("unmarshal populated snapshot: %v", err)
	}
	actionRaw, ok := fields["then_action"]
	if !ok {
		t.Fatalf("populated snapshot omitted then_action: %s", wire)
	}
	var action string
	if err := json.Unmarshal(actionRaw, &action); err != nil {
		t.Fatalf("decode then_action: %v", err)
	}
	if action != snapshot.ThenAction {
		t.Errorf("wire then_action = %q, want %q", action, snapshot.ThenAction)
	}
	logicalRaw, ok := fields["logical_interface_policer"]
	if !ok {
		t.Fatalf("populated snapshot omitted logical_interface_policer: %s", wire)
	}
	var logical bool
	if err := json.Unmarshal(logicalRaw, &logical); err != nil {
		t.Fatalf("decode logical_interface_policer: %v", err)
	}
	if !logical {
		t.Error("wire logical_interface_policer = false, want true")
	}
}
