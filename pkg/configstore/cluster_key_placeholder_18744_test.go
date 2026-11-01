package configstore

import (
	"strings"
	"testing"
)

// #18744 at the Store boundary: the strict candidate pipeline supplies the
// active config, so Commit / CommitCheck (and rollback and load override,
// which only stage) refuse a published placeholder the candidate introduces,
// keep one the active config already holds, and leave an empty store (the
// bootstrap import is an ordinary commit on one) and the tolerant sync
// ingress warning-only.

const placeholder18744 = "xpf-lab-ha-psk-cluster-22-CHANGE-ME"

func placeholderWarned18744(warnings []string, leaf string) bool {
	for _, w := range warnings {
		if strings.Contains(w, "chassis cluster "+leaf+" matches a published placeholder") {
			return true
		}
	}
	return false
}

func TestStorePlaceholderIntroducedRefused18744(t *testing.T) {
	s := newTestStore(t)
	commitCluster16858(t, s, transitionKeyA16858, "")

	stageCluster16858(t, s, transitionKeyA16858, placeholder18744)
	for name, commit := range map[string]func() error{
		"CommitCheck": func() error { _, err := s.CommitCheck(); return err },
		"Commit":      func() error { _, err := s.Commit(); return err },
	} {
		err := commit()
		if err == nil {
			t.Fatalf("%s accepted a placeholder staged over active {A} (#18744)", name)
		}
		if !strings.Contains(err.Error(), "would introduce a published placeholder") {
			t.Fatalf("%s refused, but not by the #18744 gate: %v", name, err)
		}
		if strings.Contains(strings.ToLower(err.Error()), "change-me") ||
			strings.Contains(err.Error(), transitionKeyA16858) {
			t.Fatalf("%s refusal leaked key material: %v", name, err)
		}
	}
	s.ExitConfigure()
	// The active config is untouched: it still signs A with nothing staged.
	active := s.ActiveConfig()
	if got := active.Chassis.Cluster.ControlLinkAuthKeyAlt.Reveal(); got != "" {
		t.Fatal("the refused placeholder reached the active config")
	}
}

// The bootstrap import commits onto an empty store. A placeholder there warns
// and commits, so a reimaged node bootstrapping a placeholder conf still gets
// an active config.
func TestStoreFirstCommitPlaceholderWarnsOnly18744(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, line := range []string{
		"chassis cluster cluster-id 1",
		"chassis cluster authentication-key " + placeholder18744,
	} {
		if err := s.SetFromInput(line); err != nil {
			t.Fatalf("SetFromInput %q: %v", line, err)
		}
	}
	cfg, err := s.Commit()
	if err != nil {
		t.Fatalf("first commit of a placeholder on an empty store refused: %v", err)
	}
	if !placeholderWarned18744(cfg.Warnings, "authentication-key") {
		t.Fatalf("first commit dropped the placeholder warning: %q", cfg.Warnings)
	}
	s.ExitConfigure()
}

// Rotating off a placeholder through the #6630 overlap commits at every step,
// on a clustered store so the #9619 peer pipeline judges it too. Once
// finalized, bringing the placeholder back is introducing it again.
func TestStoreRotationOffPlaceholderCommits18744(t *testing.T) {
	s := newTestStore(t)
	s.SetNodeID(0)
	commitCluster16858(t, s, placeholder18744, "")                  // fresh: warns
	commitCluster16858(t, s, placeholder18744, "")                  // routine
	commitCluster16858(t, s, placeholder18744, transitionKeyA16858) // stage A
	commitCluster16858(t, s, transitionKeyA16858, placeholder18744) // swap, keep P accepted
	commitCluster16858(t, s, transitionKeyA16858, "")               // finalize
	if placeholderWarned18744(s.ActiveConfig().Warnings, "authentication-key") ||
		placeholderWarned18744(s.ActiveConfig().Warnings, "additional-authentication-key") {
		t.Fatalf("finalized config still warns about a placeholder: %q", s.ActiveConfig().Warnings)
	}

	stageCluster16858(t, s, transitionKeyA16858, placeholder18744)
	if _, err := s.Commit(); err == nil {
		t.Fatal("re-staging the retired placeholder after finalize committed (#18744)")
	}
	s.ExitConfigure()
}

// The sync ingress is tolerant (#1960 no-brick): a peer-pushed config carrying
// a placeholder installs, with the warning.
func TestStoreSyncApplyPlaceholderBoots18744(t *testing.T) {
	s := newTestStore(t)
	commitCluster16858(t, s, transitionKeyA16858, "")
	text := "chassis {\n cluster {\n  cluster-id 1;\n  authentication-key " + transitionKeyA16858 +
		";\n  additional-authentication-key " + placeholder18744 + ";\n }\n}\n"
	cfg, err := s.SyncApply(text, nil)
	if err != nil {
		t.Fatalf("SyncApply refused a peer-pushed placeholder (no-brick violated): %v", err)
	}
	if !placeholderWarned18744(cfg.Warnings, "additional-authentication-key") {
		t.Fatalf("SyncApply installed the placeholder without its warning: %q", cfg.Warnings)
	}
}
