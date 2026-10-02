package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

func TestBootSuccessStampDoesNotTransferToFailedPromotion11928(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if _, err := store.SyncApply("system { host-name boot-stamp-race-a; }", nil); err != nil {
		t.Fatalf("SyncApply initial active config: %v", err)
	}
	store.InvalidateAppliedDigest()

	competingFailure := errors.New("competing promotion apply failed")
	var appliedHosts []string
	d := &Daemon{
		applySem:  semaphore.NewWeighted(1),
		store:     store,
		daemonCtx: context.Background(),
		buildRuntimeDataPlaneForTest: func(string) (dataplane.RuntimeDataPlane, error) {
			return &runtimeOnlyApplyTestDP{}, nil
		},
		applyBodyForTest: func(cfg *config.Config) {
			appliedHosts = append(appliedHosts, cfg.System.HostName)
		},
	}
	d.afterActiveConfigApplyForTest = func() {
		if !store.ActiveApplied() {
			t.Error("successful boot apply was not stamped before returning its result")
		}

		competingDone := make(chan error, 1)
		go func() {
			if err := d.applySem.Acquire(context.Background(), 1); err != nil {
				competingDone <- err
				return
			}
			defer d.applySem.Release(1)

			if _, err := store.SyncApply("system { host-name boot-stamp-race-b; }", nil); err != nil {
				competingDone <- err
				return
			}
			d.applyErrForTest = competingFailure
			competingDone <- d.applyConfigLocked(context.Background(), store.ActiveConfig())
		}()

		select {
		case err := <-competingDone:
			if err != competingFailure {
				t.Errorf("competing apply error = %v, want %v", err, competingFailure)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("competing promotion did not finish")
		}
		if store.ActiveConfig().System.HostName != "boot-stamp-race-b" {
			t.Errorf("active config host = %q, want competing promotion", store.ActiveConfig().System.HostName)
		}
		if store.ActiveApplied() {
			t.Error("failed competing promotion was marked applied")
		}
	}

	if err := d.setupDataplaneAndInitialConfig(); err != nil {
		t.Fatalf("setupDataplaneAndInitialConfig: %v", err)
	}
	if store.ActiveApplied() {
		t.Fatal("boot success stamp was transferred to the failed competing promotion")
	}
	if len(appliedHosts) != 2 || appliedHosts[0] != "boot-stamp-race-a" || appliedHosts[1] != "boot-stamp-race-b" {
		t.Fatalf("applied host sequence = %v, want [boot-stamp-race-a boot-stamp-race-b]", appliedHosts)
	}
}
