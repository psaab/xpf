package configstore

import (
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func eventPolicyPlantClass9984(t *testing.T, cfg *config.Config, name string) string {
	t.Helper()
	for _, policy := range cfg.EventOptions {
		if policy != nil && policy.Name == name {
			return policy.PlantClass
		}
	}
	return ""
}

func TestEventPlantClassPersistsReloadsAndRollback9984(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInputAsPlantClass("", config.EventPlantClassSuperuser, `event-options policy p events ping_test_failed`); err != nil {
		t.Fatalf("seed event trigger: %v", err)
	}
	if err := s.SetFromInputAsPlantClass("", config.EventPlantClassSuperuser, `event-options policy p then change-configuration commands "set system host-name stamped"`); err != nil {
		t.Fatalf("seed event command: %v", err)
	}
	candidate, err := s.CompileCandidate()
	if err != nil {
		t.Fatalf("CompileCandidate: %v", err)
	}
	if got := eventPolicyPlantClass9984(t, candidate, "p"); got != config.EventPlantClassSuperuser {
		t.Fatalf("candidate PlantClass=%q, want %q", got, config.EventPlantClassSuperuser)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("first commit: %v", err)
	}
	s.ExitConfigure()

	if err := s.Load(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := eventPolicyPlantClass9984(t, s.ActiveConfig(), "p"); got != config.EventPlantClassSuperuser {
		t.Fatalf("reloaded PlantClass=%q, want %q", got, config.EventPlantClassSuperuser)
	}

	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure trigger handoff: %v", err)
	}
	if err := s.SetFromInputAsPlantClass("", "planter", `event-options policy p events link_down`); err != nil {
		t.Fatalf("trigger-only handoff: %v", err)
	}
	triggerOnly, err := s.CompileCandidate()
	if err != nil {
		t.Fatalf("CompileCandidate trigger handoff: %v", err)
	}
	if got := eventPolicyPlantClass9984(t, triggerOnly, "p"); got != "planter" {
		t.Fatalf("trigger-only PlantClass=%q, want planter", got)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("trigger-only commit: %v", err)
	}
	s.ExitConfigure()

	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure second: %v", err)
	}
	if err := s.SetFromInputAsPlantClass("", "operator", `event-options policy p then change-configuration commands "set system host-name changed"`); err != nil {
		t.Fatalf("second event command: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("second commit: %v", err)
	}
	if err := s.RollbackAsPlantClass("", "rollbacker", 1); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	rolledBack, err := s.CompileCandidate()
	if err != nil {
		t.Fatalf("CompileCandidate after rollback: %v", err)
	}
	if got := eventPolicyPlantClass9984(t, rolledBack, "p"); got != "rollbacker" {
		t.Fatalf("rollback PlantClass=%q, want rollbacker", got)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("rollback commit: %v", err)
	}
	s.ExitConfigure()
	if got := eventPolicyPlantClass9984(t, s.ActiveConfig(), "p"); got != "rollbacker" {
		t.Fatalf("active rollback PlantClass=%q, want rollbacker", got)
	}
	synced := `event-options {
    policy p {
        events link_down;
        plant-class rollbacker;
        then {
            change-configuration {
                commands "set system host-name changed";
            }
        }
    }
}`
	if _, err := s.SyncApply(synced, nil); err != nil {
		t.Fatalf("SyncApply: %v", err)
	}
	if got := eventPolicyPlantClass9984(t, s.ActiveConfig(), "p"); got != "rollbacker" {
		t.Fatalf("synced PlantClass=%q, want rollbacker", got)
	}
}

func TestFlatSetCannotForgeSuperuserPlantClass9984(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, input := range []string{
		`event-options policy p events ping_test_failed`,
		`event-options policy p then change-configuration commands "set system host-name flat-stamped"`,
	} {
		if err := s.SetFromInputAsPlantClass("", "alice", input); err != nil {
			t.Fatalf("alice seed %q: %v", input, err)
		}
	}
	seeded, err := s.CompileCandidate()
	if err != nil {
		t.Fatalf("CompileCandidate after alice seed: %v", err)
	}
	if got := eventPolicyPlantClass9984(t, seeded, "p"); got != "alice" {
		t.Fatalf("flat seed PlantClass=%q, want alice", got)
	}
	if err := s.SetFromInputAsPlantClass("", "mallory", `event-options policy p plant-class super-user`); err != nil {
		t.Fatalf("mallory forged flat marker: %v", err)
	}
	forged, err := s.CompileCandidate()
	if err != nil {
		t.Fatalf("CompileCandidate after flat forgery: %v", err)
	}
	if got := eventPolicyPlantClass9984(t, forged, "p"); got != "mallory" {
		t.Fatalf("flat forgery persisted PlantClass=%q, want mallory", got)
	}
	if err := s.DeleteFromInputAsPlantClass("", "mallory", `event-options policy p plant-class`); err != nil {
		t.Fatalf("mallory deleted flat marker: %v", err)
	}
	deleted, err := s.CompileCandidate()
	if got := eventPolicyPlantClass9984(t, deleted, "p"); got != "" {
		t.Fatalf("flat marker delete left PlantClass=%q, want empty quarantine marker", got)
	}
}
