package daemon

import (
	"errors"
	"path/filepath"
	"testing"

	"golang.org/x/sync/semaphore"
)

// #16171: the two …UnderSem stamp helpers are the single source of the
// convergence gate for shape-(a) active stamps and the syncAndApply
// captured-digest stamp. Each helper gets the full 8-combination truth
// table over (store=nil, apply error, policy debt, publish-landed),
// asserted under a held applySem, plus a negative control proving the
// test would catch a stamp on a non-converged apply: with every gate term
// satisfied except one, ActiveApplied must stay false, and flipping that
// last term must stamp. The digest helper additionally covers
// digest=="" as a no-op even when every other term is satisfied.
//
// Fail-on-revert: dropping any single term from either helper's gate
// (err, debt, or PublishLanded) turns the corresponding table row red;
// dropping the nil-store check panics the nil-store row; dropping the
// empty-digest check is caught by the digest=="" row only if the store
// would otherwise record it — MarkAppliedDigest("") is itself a no-op,
// so that row also asserts the helper's bool return.

func stampHelperDaemon16171(t *testing.T) (*Daemon, string) {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if _, err := store.SyncApply("system { host-name stamp-16171; }", nil); err != nil {
		t.Fatalf("SyncApply: %v", err)
	}
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		store:    store,
	}
	return d, store.ActiveDigest()
}

func TestStampActiveAppliedIfConvergedUnderSemTruthTable16171(t *testing.T) {
	applyErr := errors.New("apply failed 16171")
	cases := []struct {
		name      string
		nilStore  bool
		err       error
		debt      bool
		landed    bool
		wantStamp bool
	}{
		{name: "all converged", landed: true, wantStamp: true},
		{name: "nil store", nilStore: true, landed: true, wantStamp: false},
		{name: "apply error", err: applyErr, landed: true, wantStamp: false},
		{name: "policy debt", debt: true, landed: true, wantStamp: false},
		{name: "not landed", landed: false, wantStamp: false},
		{name: "nil store and error", nilStore: true, err: applyErr, landed: true, wantStamp: false},
		{name: "debt and not landed", debt: true, landed: false, wantStamp: false},
		{name: "error debt not landed", err: applyErr, debt: true, landed: false, wantStamp: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, _ := stampHelperDaemon16171(t)
			if err := d.applySem.Acquire(t.Context(), 1); err != nil {
				t.Fatalf("acquire applySem: %v", err)
			}
			defer d.applySem.Release(1)
			if tc.nilStore {
				d.store = nil
			}
			if tc.debt {
				d.policyInvalidationDebt = &policyInvalidationDebt{}
			}
			d.policyInvalidationPublishLanded = tc.landed

			// Negative control: pre-arm nothing; a stamp is observable
			// only via ActiveApplied on a non-nil store.
			if got := d.stampActiveAppliedIfConvergedUnderSem(tc.err); got != tc.wantStamp {
				t.Fatalf("stampActiveAppliedIfConvergedUnderSem = %v, want %v", got, tc.wantStamp)
			}
			if tc.nilStore {
				return
			}
			if got := d.store.ActiveApplied(); got != tc.wantStamp {
				t.Fatalf("ActiveApplied = %v, want %v", got, tc.wantStamp)
			}
		})
	}

	// Negative control / flip: with debt outstanding the stamp is withheld;
	// clearing the debt (and nothing else) under the same hold stamps.
	t.Run("flip debt to stamp", func(t *testing.T) {
		d, _ := stampHelperDaemon16171(t)
		if err := d.applySem.Acquire(t.Context(), 1); err != nil {
			t.Fatalf("acquire applySem: %v", err)
		}
		defer d.applySem.Release(1)
		d.policyInvalidationDebt = &policyInvalidationDebt{}
		d.policyInvalidationPublishLanded = true
		if d.stampActiveAppliedIfConvergedUnderSem(nil) {
			t.Fatal("stamped with policy debt outstanding")
		}
		if d.store.ActiveApplied() {
			t.Fatal("ActiveApplied with policy debt outstanding")
		}
		d.policyInvalidationDebt = nil
		if !d.stampActiveAppliedIfConvergedUnderSem(nil) {
			t.Fatal("did not stamp after debt cleared under same hold")
		}
		if !d.store.ActiveApplied() {
			t.Fatal("ActiveApplied false after converged stamp")
		}
	})
}

func TestStampDigestIfConvergedUnderSemTruthTable16171(t *testing.T) {
	applyErr := errors.New("apply failed 16171")
	cases := []struct {
		name      string
		nilStore  bool
		err       error
		debt      bool
		landed    bool
		emptyDig  bool
		wantStamp bool
	}{
		{name: "all converged", landed: true, wantStamp: true},
		{name: "nil store", nilStore: true, landed: true, wantStamp: false},
		{name: "apply error", err: applyErr, landed: true, wantStamp: false},
		{name: "policy debt", debt: true, landed: true, wantStamp: false},
		{name: "not landed", landed: false, wantStamp: false},
		{name: "nil store and error", nilStore: true, err: applyErr, landed: true, wantStamp: false},
		{name: "debt and not landed", debt: true, landed: false, wantStamp: false},
		{name: "error debt not landed", err: applyErr, debt: true, landed: false, wantStamp: false},
		{name: "empty digest", landed: true, emptyDig: true, wantStamp: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, digest := stampHelperDaemon16171(t)
			if err := d.applySem.Acquire(t.Context(), 1); err != nil {
				t.Fatalf("acquire applySem: %v", err)
			}
			defer d.applySem.Release(1)
			if tc.nilStore {
				d.store = nil
			}
			if tc.debt {
				d.policyInvalidationDebt = &policyInvalidationDebt{}
			}
			d.policyInvalidationPublishLanded = tc.landed
			if tc.emptyDig {
				digest = ""
			}
			if got := d.stampDigestIfConvergedUnderSem(tc.err, digest); got != tc.wantStamp {
				t.Fatalf("stampDigestIfConvergedUnderSem = %v, want %v", got, tc.wantStamp)
			}
			if tc.nilStore {
				return
			}
			if got := d.store.ActiveApplied(); got != tc.wantStamp {
				t.Fatalf("ActiveApplied = %v, want %v", got, tc.wantStamp)
			}
		})
	}

	t.Run("flip landed to stamp", func(t *testing.T) {
		d, digest := stampHelperDaemon16171(t)
		if err := d.applySem.Acquire(t.Context(), 1); err != nil {
			t.Fatalf("acquire applySem: %v", err)
		}
		defer d.applySem.Release(1)
		d.policyInvalidationPublishLanded = false
		if d.stampDigestIfConvergedUnderSem(nil, digest) {
			t.Fatal("stamped before publication landed")
		}
		if d.store.ActiveApplied() {
			t.Fatal("ActiveApplied before publication landed")
		}
		d.policyInvalidationPublishLanded = true
		if !d.stampDigestIfConvergedUnderSem(nil, digest) {
			t.Fatal("did not stamp after publication landed under same hold")
		}
		if !d.store.ActiveApplied() {
			t.Fatal("ActiveApplied false after converged digest stamp")
		}
	})

	// The digest helper stamps the CAPTURED digest, not the current
	// active: stamp a digest for a different text and ActiveApplied
	// (keyed on current active) must stay false.
	t.Run("captured digest keys captured tree", func(t *testing.T) {
		d, _ := stampHelperDaemon16171(t)
		if err := d.applySem.Acquire(t.Context(), 1); err != nil {
			t.Fatalf("acquire applySem: %v", err)
		}
		defer d.applySem.Release(1)
		d.policyInvalidationPublishLanded = true
		other := newConfigStore(t, filepath.Join(t.TempDir(), "other.db"))
		if _, err := other.SyncApply("system { host-name other-16171; }", nil); err != nil {
			t.Fatalf("SyncApply other: %v", err)
		}
		if !d.stampDigestIfConvergedUnderSem(nil, other.ActiveDigest()) {
			t.Fatal("did not stamp captured digest")
		}
		if d.store.ActiveApplied() {
			t.Fatal("ActiveApplied true for a digest of a different tree")
		}
	})
}
