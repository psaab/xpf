package configstore

import (
	"errors"
	"testing"
)

// #3893: clusterReadOnly was enforced ONLY at EnterConfigure*. Once a config
// session was already open (entered before the node became a cluster
// secondary, or via a path that did not re-check), Set/Delete/Commit/Load/
// Rollback only verified candidate!=nil — so an open session could Set+Commit
// on the read-only secondary and diverge its active config from the RG0
// primary. These tests pin the store-level enforcement of the read-only gate
// on every user-session mutating op. On revert of the fix, the "rejected"
// assertions go RED (the edit commits and diverges the secondary).

// TestClusterReadOnly_OpenSessionMutationsRejected reproduces the exact bug:
// a session opened BEFORE the node became secondary must not be able to mutate
// or commit once the node is read-only.
func TestClusterReadOnly_OpenSessionMutationsRejected(t *testing.T) {
	s := newTestStore(t)

	// Session opened while the node is still the RG0 primary (writable).
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure (primary): %v", err)
	}

	// The node now fails over to secondary while the session is still open.
	s.SetClusterReadOnly(true)

	// Every candidate-mutating op must now be rejected with ErrClusterReadOnly.
	if err := s.Set([]string{"system", "host-name", "evil"}); !errors.Is(err, ErrClusterReadOnly) {
		t.Fatalf("Set on read-only secondary: want ErrClusterReadOnly, got %v", err)
	}
	if err := s.SetFromInput("system host-name evil"); !errors.Is(err, ErrClusterReadOnly) {
		t.Fatalf("SetFromInput on read-only secondary: want ErrClusterReadOnly, got %v", err)
	}
	if err := s.Delete([]string{"system", "host-name"}); !errors.Is(err, ErrClusterReadOnly) {
		t.Fatalf("Delete on read-only secondary: want ErrClusterReadOnly, got %v", err)
	}
	if err := s.DeleteFromInput("system host-name"); !errors.Is(err, ErrClusterReadOnly) {
		t.Fatalf("DeleteFromInput on read-only secondary: want ErrClusterReadOnly, got %v", err)
	}
	if err := s.DeactivateFromInput("system host-name"); !errors.Is(err, ErrClusterReadOnly) {
		t.Fatalf("DeactivateFromInput on read-only secondary: want ErrClusterReadOnly, got %v", err)
	}
	if err := s.ActivateFromInput("system host-name"); !errors.Is(err, ErrClusterReadOnly) {
		t.Fatalf("ActivateFromInput on read-only secondary: want ErrClusterReadOnly, got %v", err)
	}
	if err := s.Copy([]string{"system"}, []string{"system2"}); !errors.Is(err, ErrClusterReadOnly) {
		t.Fatalf("Copy on read-only secondary: want ErrClusterReadOnly, got %v", err)
	}
	if err := s.Rename([]string{"system"}, []string{"system2"}); !errors.Is(err, ErrClusterReadOnly) {
		t.Fatalf("Rename on read-only secondary: want ErrClusterReadOnly, got %v", err)
	}
	if err := s.Insert([]string{"a"}, []string{"b"}, true); !errors.Is(err, ErrClusterReadOnly) {
		t.Fatalf("Insert on read-only secondary: want ErrClusterReadOnly, got %v", err)
	}
	if err := s.Annotate([]string{"system"}, "note"); !errors.Is(err, ErrClusterReadOnly) {
		t.Fatalf("Annotate on read-only secondary: want ErrClusterReadOnly, got %v", err)
	}
	if err := s.LoadOverride("system { host-name evil; }"); !errors.Is(err, ErrClusterReadOnly) {
		t.Fatalf("LoadOverride on read-only secondary: want ErrClusterReadOnly, got %v", err)
	}
	if err := s.LoadMerge("set system host-name evil"); !errors.Is(err, ErrClusterReadOnly) {
		t.Fatalf("LoadMerge on read-only secondary: want ErrClusterReadOnly, got %v", err)
	}
	if _, err := s.LoadSet("set system host-name evil"); !errors.Is(err, ErrClusterReadOnly) {
		t.Fatalf("LoadSet on read-only secondary: want ErrClusterReadOnly, got %v", err)
	}
	if err := s.Rollback(0); !errors.Is(err, ErrClusterReadOnly) {
		t.Fatalf("Rollback on read-only secondary: want ErrClusterReadOnly, got %v", err)
	}

	// The commit paths — the divergence-causing step — must be rejected too.
	if _, err := s.Commit(); !errors.Is(err, ErrClusterReadOnly) {
		t.Fatalf("Commit on read-only secondary: want ErrClusterReadOnly, got %v", err)
	}
	if _, err := s.CommitWithDescription("x"); !errors.Is(err, ErrClusterReadOnly) {
		t.Fatalf("CommitWithDescription on read-only secondary: want ErrClusterReadOnly, got %v", err)
	}
	if _, err := s.CommitConfirmed(1); !errors.Is(err, ErrClusterReadOnly) {
		t.Fatalf("CommitConfirmed on read-only secondary: want ErrClusterReadOnly, got %v", err)
	}
}

// TestClusterReadOnly_EnterConfigureRejected keeps pinning the original gate:
// on a read-only secondary a fresh session cannot even be opened.
func TestClusterReadOnly_EnterConfigureRejected(t *testing.T) {
	s := newTestStore(t)
	s.SetClusterReadOnly(true)
	if err := s.EnterConfigure(); !errors.Is(err, ErrClusterReadOnly) {
		t.Fatalf("EnterConfigure on read-only secondary: want ErrClusterReadOnly, got %v", err)
	}
	if err := s.EnterConfigureExclusive("h"); !errors.Is(err, ErrClusterReadOnly) {
		t.Fatalf("EnterConfigureExclusive on read-only secondary: want ErrClusterReadOnly, got %v", err)
	}
}

// TestClusterReadOnly_PrimaryCanCommit confirms the RG0 primary path is
// untouched: a writable node can Set + Commit normally.
func TestClusterReadOnly_PrimaryCanCommit(t *testing.T) {
	s := newTestStore(t)
	// Default is writable; be explicit for the transition contract.
	s.SetClusterReadOnly(false)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure (primary): %v", err)
	}
	if err := s.SetFromInput("system host-name primary"); err != nil {
		t.Fatalf("Set (primary): %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit (primary): %v", err)
	}
}

// TestClusterReadOnly_SyncApplyBypassesGate confirms the internal HA-sync
// ingress still applies config on a read-only secondary — the secondary
// APPLIES config authored by the primary, which is exactly how it converges.
func TestClusterReadOnly_SyncApplyBypassesGate(t *testing.T) {
	s := newTestStore(t)
	s.SetClusterReadOnly(true)

	if _, err := s.SyncApply("system { host-name synced; }", nil); err != nil {
		t.Fatalf("SyncApply on read-only secondary must succeed (internal sync), got %v", err)
	}
	if got := s.active.FormatSet(); got == "" {
		t.Fatalf("SyncApply did not update active config on the secondary")
	}
}

// TestClusterReadOnly_PromotedNodeCanCommit confirms the flag transition is
// correct: a node promoted from secondary to RG0 primary can then commit.
func TestClusterReadOnly_PromotedNodeCanCommit(t *testing.T) {
	s := newTestStore(t)

	// Secondary: config is blocked.
	s.SetClusterReadOnly(true)
	if err := s.EnterConfigure(); !errors.Is(err, ErrClusterReadOnly) {
		t.Fatalf("EnterConfigure (secondary): want ErrClusterReadOnly, got %v", err)
	}

	// Promotion to RG0 primary.
	s.SetClusterReadOnly(false)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure (promoted primary): %v", err)
	}
	if err := s.SetFromInput("system host-name promoted"); err != nil {
		t.Fatalf("Set (promoted primary): %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit (promoted primary): %v", err)
	}
}

// TestClusterReadOnly_ZeroValueStoreIsWritable_6896 pins the Store's default,
// not the daemon's post-reconcile behavior. `clusterReadOnly` is a plain bool
// with no constructor initialisation, so a newly constructed store is
// writable. The daemon derives the gate from RG0 state during reconciliation;
// the daemon-layer tests bind that startup/recovery path.
//
// This isolated Store test asserts the default only. It does not claim that an
// RG0 secondary remains writable after the daemon's first reconcile.
func TestClusterReadOnly_ZeroValueStoreIsWritable_6896(t *testing.T) {
	s := newTestStore(t)

	// No SetClusterReadOnly call anywhere in this isolated Store test; it does
	// not construct the daemon or run RG0 reconciliation.
	if s.ClusterReadOnly() {
		t.Fatalf("a freshly constructed Store reports ClusterReadOnly()=true; " +
			"the docs' arming precondition (#6896) assumes the zero value is " +
			"false. If this is now armed by construction, #6890 may be closed " +
			"and pkg/configstore/README.md, docs/feature-coverage.md and " +
			"docs/phases.md must be re-stated")
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure on an unarmed store: %v", err)
	}
	if err := s.SetFromInput("system host-name cold-start-standby"); err != nil {
		t.Fatalf("Set on an unarmed store: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit on an unarmed store: %v", err)
	}
}
