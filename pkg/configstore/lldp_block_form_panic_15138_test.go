package configstore

import (
	"strings"
	"testing"
)

// #15138 store probe: the nameless LLDP interface block spellings must
// never panic the store paths. Strict commit-check (the path behind
// the authenticated load-override + commit flow) rejects them naming
// the missing name; the tolerant HA-sync ingress warns and drops the
// nameless entry instead of crashing xpfd.
//
// FAIL-ON-REVERT: restoring the nodeVal-based LLDP read in
// compileProtocols reintroduces the [2:1] panic and these probes fail
// with it (SyncApply/CommitCheck panic rather than returning).

var lldpNamelessBodies15138 = []string{
	`protocols { lldp { interface { disable; } } }`,
	`protocols { lldp { interface { ge-0/0/1; } } }`,
	`protocols { lldp { interface { ge-0/0/1 { disable; } } } }`,
}

func TestLLDPNamelessBlockCommitCheckRejects15138(t *testing.T) {
	for _, body := range lldpNamelessBodies15138 {
		s := newTestStore(t)
		if err := s.EnterConfigure(); err != nil {
			t.Fatalf("EnterConfigure: %v", err)
		}
		if err := s.LoadOverrideAsPlantClass("", "", body); err != nil {
			t.Fatalf("LoadOverrideAsPlantClass(%q): %v", body, err)
		}
		if _, err := s.CommitCheck(); err == nil {
			t.Fatalf("CommitCheck accepted nameless LLDP body %q, want rejection", body)
		} else if !strings.Contains(err.Error(), "interface") {
			t.Fatalf("CommitCheck error for %q = %v, want naming the interface", body, err)
		}
		// Commit must refuse the same way (never panic, never apply).
		if _, err := s.Commit(); err == nil {
			t.Fatalf("Commit accepted nameless LLDP body %q, want rejection", body)
		}
	}
}

func TestLLDPNamelessBlockSyncApplyTolerates15138(t *testing.T) {
	for _, body := range lldpNamelessBodies15138 {
		s := newTestStore(t)
		cfg, err := s.SyncApply(body, nil)
		if err != nil {
			t.Fatalf("SyncApply must tolerate nameless LLDP body %q, got: %v", body, err)
		}
		if cfg == nil || cfg.Protocols.LLDP == nil {
			t.Fatalf("SyncApply(%q): LLDP is nil", body)
		}
		if len(cfg.Protocols.LLDP.Interfaces) != 0 {
			t.Fatalf("SyncApply(%q) compiled phantom interfaces %+v, want dropped", body, cfg.Protocols.LLDP.Interfaces)
		}
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "interface name is required") {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("SyncApply(%q) warnings = %v, want one naming the missing interface name", body, cfg.Warnings)
		}
	}
}

// Named control through the same store paths stays green.
func TestLLDPNamedBlockStoreControl15138(t *testing.T) {
	s := newTestStore(t)
	cfg, err := s.SyncApply(`protocols { lldp { interface ge-0/0/0 { disable; } } }`, nil)
	if err != nil {
		t.Fatalf("SyncApply named control: %v", err)
	}
	if got := cfg.Protocols.LLDP.Interfaces; len(got) != 1 || got[0].Name != "ge-0/0/0" || !got[0].Disable {
		t.Fatalf("SyncApply named control interfaces = %+v, want [{ge-0/0/0 true}]", got)
	}

	s2 := newTestStore(t)
	if err := s2.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s2.LoadOverrideAsPlantClass("", "", `protocols { lldp { interface ge-0/0/0 { disable; } } }`); err != nil {
		t.Fatalf("LoadOverride named control: %v", err)
	}
	checked, err := s2.CommitCheck()
	if err != nil {
		t.Fatalf("CommitCheck named control: %v", err)
	}
	if got := checked.Protocols.LLDP.Interfaces; len(got) != 1 || got[0].Name != "ge-0/0/0" || !got[0].Disable {
		t.Fatalf("CommitCheck named control interfaces = %+v, want [{ge-0/0/0 true}]", got)
	}
}
