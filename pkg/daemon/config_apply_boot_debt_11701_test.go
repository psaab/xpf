package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// TestBootConfigApplyFailureIsRetriedUntilConverged11701 drives the real boot
// apply site: a failed active-config apply must become retry debt, and the
// always-on owner must re-apply the active config and clear the debt on success.
func TestBootConfigApplyFailureIsRetriedUntilConverged11701(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if _, err := store.SyncApply("system { host-name boot-debt-11701; }", nil); err != nil {
		t.Fatalf("SyncApply active boot config: %v", err)
	}
	transient := errors.New("boot apply: simulated dataplane publish failure")
	applies := 0
	d := &Daemon{
		applySem:  semaphore.NewWeighted(1),
		store:     store,
		daemonCtx: context.Background(),
		buildRuntimeDataPlaneForTest: func(string) (dataplane.RuntimeDataPlane, error) {
			return &runtimeOnlyApplyTestDP{}, nil
		},
		applyBodyForTest: func(*config.Config) { applies++ },
		applyErrForTest:  transient,
	}

	if err := d.setupDataplaneAndInitialConfig(); err != nil {
		t.Fatalf("setupDataplaneAndInitialConfig: %v", err)
	}
	if applies != 1 {
		t.Fatalf("boot applied active config %d times, want exactly once", applies)
	}
	owed, failures, lastErr := d.ConfigApplyDebt()
	if !owed || failures != 1 || !strings.Contains(lastErr, "simulated dataplane publish failure") {
		t.Fatalf("boot apply debt = (%v, %d, %q), want (true, 1, boot apply error)", owed, failures, lastErr)
	}

	// Keep the fault in place for one owner pass: the failure count must rise,
	// demonstrating that the retry actually ran rather than merely preserving
	// the debt status.
	d.reassertConfigApplyOnce(context.Background())
	if applies != 2 {
		t.Fatalf("after failed retry, apply count = %d, want 2", applies)
	}
	if owed, failures, _ := d.ConfigApplyDebt(); !owed || failures != 2 {
		t.Fatalf("after failed retry, debt = (%v, %d), want (true, 2)", owed, failures)
	}

	d.applyErrForTest = nil
	d.reassertConfigApplyOnce(context.Background())
	if applies != 3 {
		t.Fatalf("after converging retry, apply count = %d, want 3", applies)
	}
	if owed, failures, lastErr := d.ConfigApplyDebt(); owed || failures != 2 || lastErr != "" {
		t.Fatalf("after successful retry, debt = (%v, %d, %q), want (false, 2, empty)", owed, failures, lastErr)
	}
}
