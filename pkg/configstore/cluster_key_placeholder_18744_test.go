package configstore

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #18744 at the Store boundary. The store decides whether the placeholder
// gate judges a commit (placeholderJudgedLocked):
//   - a store that has committed judges every committer against its active
//     config;
//   - a store that never committed judges every committer except the
//     bootstrap import, against an empty accepted set;
//   - a committed config that no longer compiles (#1960) is not judged.
// Commit, CommitCheck, rollback and load override (which only stage) all go
// through it; the tolerant sync ingress never judges.

const placeholder18744 = "xpf-lab-ha-psk-cluster-22-CHANGE-ME"

const placeholderConf18744 = "chassis {\n cluster {\n  cluster-id 1;\n  authentication-key " +
	placeholder18744 + ";\n }\n}\n"

func placeholderWarned18744(warnings []string, leaf string) bool {
	for _, w := range warnings {
		if strings.Contains(w, "chassis cluster "+leaf+" matches a published placeholder") {
			return true
		}
	}
	return false
}

func requireRefusal18744(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: committed a newly introduced placeholder (#18744)", what)
	}
	if !strings.Contains(err.Error(), "would introduce a published placeholder") {
		t.Fatalf("%s: refused, but not by the #18744 gate: %v", what, err)
	}
	if strings.Contains(strings.ToLower(err.Error()), "change-me") {
		t.Fatalf("%s: refusal leaked key material: %v", what, err)
	}
}

// bootstrapImport18744 drives the daemon's bootstrapFromFile sequence:
// LoadOverride, the pre-flight compile, then the commit, both as the
// bootstrap authority.
func bootstrapImport18744(t *testing.T, s *Store, text string) (*config.Config, error) {
	t.Helper()
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	defer s.ExitConfigure()
	if err := s.LoadOverride(text); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	bootstrap := InternalCommitterAs(BootstrapPrincipal)
	if _, _, err := s.CompileCandidateGenAs(bootstrap); err != nil {
		// The pre-flight must see the same decision as the commit, or the
		// daemon silently skips its device-map check.
		t.Fatalf("bootstrap pre-flight compile refused what its commit accepts: %v", err)
	}
	_, gen, _ := s.CompileCandidateGenAs(bootstrap)
	return s.CommitWithDescriptionGenAs(bootstrap, "", gen)
}

func TestStorePlaceholderIntroducedRefused18744(t *testing.T) {
	s := newTestStore(t)
	commitCluster16858(t, s, transitionKeyA16858, "")

	stageCluster16858(t, s, transitionKeyA16858, placeholder18744)
	_, err := s.CommitCheck()
	requireRefusal18744(t, "CommitCheck", err)
	_, err = s.Commit()
	requireRefusal18744(t, "Commit", err)
	s.ExitConfigure()
	if got := s.ActiveConfig().Chassis.Cluster.ControlLinkAuthKeyAlt.Reveal(); got != "" {
		t.Fatal("the refused placeholder reached the active config")
	}
}

// An interactive first commit on a store that never committed is the likeliest
// way a placeholder gets in (a reference config pasted on a fresh box), and
// it would count as pre-existing afterwards. It is judged against an empty
// accepted set, so it is refused — by every commit entry point, including one
// that merely names the bootstrap principal as a string.
func TestStoreFirstInteractiveCommitPlaceholderRefused18744(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.LoadOverride(placeholderConf18744); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	_, err := s.CommitCheck()
	requireRefusal18744(t, "CommitCheck", err)
	_, err = s.Commit()
	requireRefusal18744(t, "Commit", err)
	_, err = s.CommitWithDescriptionAs(BootstrapPrincipal, "")
	requireRefusal18744(t, "CommitWithDescriptionAs(system:bootstrap)", err)
	_, gen, _ := s.CompileCandidateGen()
	_, err = s.CommitWithDescriptionGenAs(InternalCommitterAs("system:other"), "", gen)
	requireRefusal18744(t, "another internal committer", err)
	s.ExitConfigure()
	if s.EverCommitted() {
		t.Fatal("a refused first commit marked the store committed")
	}
}

// The bootstrap import onto a store that never committed only warns, so a
// reimaged node bootstrapping a placeholder conf still gets an active config.
func TestStoreBootstrapImportPlaceholderWarnsOnly18744(t *testing.T) {
	s := newTestStore(t)
	cfg, err := bootstrapImport18744(t, s, placeholderConf18744)
	if err != nil {
		t.Fatalf("bootstrap import of a placeholder conf refused: %v", err)
	}
	if !placeholderWarned18744(cfg.Warnings, "authentication-key") {
		t.Fatalf("bootstrap import dropped the placeholder warning: %q", cfg.Warnings)
	}
	// Once the store has committed, even the bootstrap authority is judged.
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.LoadOverride(strings.Replace(placeholderConf18744, "CHANGE-ME", "change-me-2", 1)); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	_, gen, _ := s.CompileCandidateGen()
	_, err = s.CommitWithDescriptionGenAs(InternalCommitterAs(BootstrapPrincipal), "", gen)
	requireRefusal18744(t, "bootstrap authority on a committed store", err)
	s.ExitConfigure()
}

// AC F1: after a #1922 Item 1b first-commit-confirmed rollback and a restart,
// the store has never committed but compiles the empty tree (s.compiled is
// non-nil). The daemon still runs the bootstrap import there, and it must not
// be judged. Keying the decision on s.compiled refused it.
func TestStoreBootstrapImportAfterItem1bRestart18744(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")
	st1, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st1.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := st1.LoadOverride("system { host-name box; }"); err != nil {
		t.Fatal(err)
	}
	if _, err := st1.CommitConfirmed(1); err != nil {
		t.Fatal(err)
	}
	st1.ExitConfigure()
	if _, ok := st1.PromoteRollback(st1.ConfirmGenForTesting()); !ok {
		t.Fatal("PromoteRollback: ok=false, want the first-commit revert")
	}
	st2, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st2.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if st2.EverCommitted() || st2.ActiveConfig() == nil {
		t.Fatalf("fixture: everCommitted=%v active=%v, want false and non-nil (the Item 1b state)",
			st2.EverCommitted(), st2.ActiveConfig() != nil)
	}
	cfg, err := bootstrapImport18744(t, st2, placeholderConf18744)
	if err != nil {
		t.Fatalf("Item 1b store: bootstrap import refused: %v", err)
	}
	if !placeholderWarned18744(cfg.Warnings, "authentication-key") {
		t.Fatalf("Item 1b store: bootstrap import dropped the warning: %q", cfg.Warnings)
	}
}

// Rotating off a placeholder through the #6630 overlap commits at every step,
// on a clustered store so the #9619 peer pipeline judges it too. The node was
// keyed with the placeholder by its bootstrap import. Two extra rows sit in
// the overlap: a routine commit at steps 3-4 and backing out of them, both
// judged against an active config that holds the placeholder as the
// ADDITIONAL key. Once finalized, bringing the placeholder back is
// introducing it again.
func TestStoreRotationOffPlaceholderCommits18744(t *testing.T) {
	s := newTestStore(t)
	s.SetNodeID(0)
	if _, err := bootstrapImport18744(t, s, placeholderConf18744); err != nil {
		t.Fatalf("bootstrap import: %v", err)
	}
	commitCluster16858(t, s, placeholder18744, "")                  // routine
	commitCluster16858(t, s, placeholder18744, transitionKeyA16858) // steps 1-2: stage A
	commitCluster16858(t, s, transitionKeyA16858, placeholder18744) // steps 3-4: swap
	commitCluster16858(t, s, transitionKeyA16858, placeholder18744) // routine at 3-4
	commitCluster16858(t, s, placeholder18744, transitionKeyA16858) // back out
	commitCluster16858(t, s, transitionKeyA16858, placeholder18744) // swap again
	commitCluster16858(t, s, transitionKeyA16858, "")               // step 5: finalize
	active := s.ActiveConfig()
	if placeholderWarned18744(active.Warnings, "authentication-key") ||
		placeholderWarned18744(active.Warnings, "additional-authentication-key") {
		t.Fatalf("finalized config still warns about a placeholder: %q", active.Warnings)
	}

	stageCluster16858(t, s, transitionKeyA16858, placeholder18744)
	_, err := s.Commit()
	requireRefusal18744(t, "re-staging the retired placeholder after finalize", err)
	s.ExitConfigure()
}

// The tolerant sync ingress never judges (#1960 no-brick): a peer-pushed
// config carrying a placeholder installs, with the warning.
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

// The decision table, including the documented residual: a committed config
// that no longer compiles (#1960) is not judged, because its accepted set is
// unknown.
func TestPlaceholderJudgedDecision18744(t *testing.T) {
	compiled := &config.Config{}
	for _, tc := range []struct {
		name          string
		everCommitted bool
		compiled      *config.Config
		bootstrap     bool
		want          bool
	}{
		{"committed store, interactive", true, compiled, false, true},
		{"committed store, bootstrap authority", true, compiled, true, true},
		{"#1960 compile-failed load, repair commit (residual)", true, nil, false, false},
		{"fresh store, interactive", false, nil, false, true},
		{"fresh store, bootstrap import", false, nil, true, false},
		{"Item 1b store, interactive", false, compiled, false, true},
		{"Item 1b store, bootstrap import", false, compiled, true, false},
	} {
		s := &Store{everCommitted: tc.everCommitted, compiled: tc.compiled}
		if got := s.placeholderJudgedLocked(tc.bootstrap); got != tc.want {
			t.Errorf("%s: judged=%v, want %v", tc.name, got, tc.want)
		}
	}
}
