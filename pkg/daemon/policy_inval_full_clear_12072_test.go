package daemon

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

type fullClearSurfaceDP12072 struct {
	*dataplane.Manager
	applied *config.Config
	clear   func() (int, int, error)
}

func (d *fullClearSurfaceDP12072) PolicyReadConfig() *config.Config { return d.applied }
func (d *fullClearSurfaceDP12072) ClearAllSessions() (int, int, error) {
	return d.clear()
}
func policySetFullClearConfigText12072(host string, names []string) string {
	var policies strings.Builder
	for _, name := range names {
		fmt.Fprintf(&policies, `
            policy %s {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }`, name)
	}
	return fmt.Sprintf(`system { host-name %s; }
security {
    zones { security-zone trust; security-zone untrust; }
    policies {
        from-zone trust to-zone untrust {%s
        }
    }
}`, host, policies.String())
}

func newPublishedScanFailure12072(t *testing.T) (*convergenceRun12072, *config.Config, *config.Config) {
	t.Helper()
	r, _ := newConvergenceRun12072(t, []string{"p-first", "a", "b", "web"})
	c0, err := r.h.d.store.SyncApply(policySetFullClearConfigText12072(
		"clear-c0", []string{"p-first", "a", "b", "web"}), nil)
	if err != nil {
		t.Fatalf("promote C0: %v", err)
	}
	r.h.d.store.MarkActiveApplied()
	c1, err := r.h.d.store.SyncApply(policySetFullClearConfigText12072(
		"clear-c1", []string{"p-first", "b", "web"}), nil)
	if err != nil {
		t.Fatalf("promote C1: %v", err)
	}
	r.dp.applied, r.dp.helperCfg = c0, c0
	ids := dpuserspace.PolicyIDsByStableKey(c0)
	for i := range r.dp.rows {
		row := &r.dp.rows[i]
		row.PolicyID = ids[r.dp.ruleBySession[row.ExpectedRTFlowSessionID]]
	}
	r.dp.incompleteNext = 1
	if err := r.h.d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	_, applyErr := r.h.d.applyAndSyncCommitted(c0, c1, peerSyncNever)
	r.h.d.applySem.Release(1)
	if applyErr == nil {
		t.Fatal("published incomplete policy scan did not surface its error")
	}
	debt := r.h.d.policyInvalidationDebt
	if debt == nil || debt.scanFailure == nil || debt.newCfg != c1 || r.dp.PolicyReadConfig() != c1 {
		t.Fatalf("premise: published scan failure debt=%+v authority=%p, want C1 debt under known C1 authority", debt, r.dp.PolicyReadConfig())
	}
	if r.h.d.store.ActiveApplied() {
		t.Fatal("premise: incompletely invalidated C1 was marked applied")
	}
	return r, c0, c1
}

func TestPolicyInvalidationFullSessionClearRetiresPublishedScanFailure12072(t *testing.T) {
	r, c0, c1 := newPublishedScanFailure12072(t)
	originalRows := len(r.dp.rows)
	clearDP := &fullClearSurfaceDP12072{
		Manager: dataplane.New(),
		applied: c1,
		clear: func() (int, int, error) {
			cleared := len(r.dp.rows)
			r.dp.rows = nil
			return cleared, 0, nil
		},
	}
	r.h.d.setDataplane(clearDP)
	adapter := liveDataPlane{daemon: r.h.d}
	v4, v6, err := adapter.ClearAllSessions()
	if err != nil || v4 != originalRows || v6 != 0 {
		t.Fatalf("full session clear = (%d,%d,%v), want (%d,0,nil)", v4, v6, err, originalRows)
	}
	if len(r.dp.rows) != 0 || r.h.d.policyInvalidationDebt != nil || !r.h.d.store.ActiveApplied() {
		t.Fatalf("successful full clear did not retire published scan debt: live=%d debt=%+v activeApplied=%v",
			len(r.dp.rows), r.h.d.policyInvalidationDebt, r.h.d.store.ActiveApplied())
	}

	// Continue through same-text retry and two later config transitions: a
	// settled full clear must not leave a latch that can reappear on retries.
	r.h.d.setDataplane(r.dp)
	c1Retry, err := r.h.d.store.SyncApply(policySetFullClearConfigText12072(
		"clear-c1", []string{"p-first", "b", "web"}), nil)
	if err != nil {
		t.Fatalf("re-promote C1: %v", err)
	}
	if err := r.h.d.applyActiveConfigResult(); err != nil {
		t.Fatalf("same-text background retry: %v", err)
	}

	// Exercise the immediate background apply path and two settled worker
	// ticks after the authoritative clear; none may recreate the retired debt.
	if err := r.h.d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	r.h.d.applyConfigUnderSem(c1Retry)
	r.h.d.applySem.Release(1)
	if r.h.d.policyInvalidationDebt != nil || !r.h.d.store.ActiveApplied() ||
		r.dp.helperCfg != c1Retry {
		t.Fatalf("immediate retry after clear: debt=%+v activeApplied=%v helper=%p want=%p",
			r.h.d.policyInvalidationDebt, r.h.d.store.ActiveApplied(), r.dp.helperCfg, c1Retry)
	}
	for _, generation := range []uint64{8, 9} {
		r.h.d.dischargePolicyInvalidationAfterPublish(generation)
		if r.h.d.policyInvalidationDebt != nil || !r.h.d.store.ActiveApplied() {
			t.Fatalf("settled tick %d recreated scan debt: debt=%+v activeApplied=%v",
				generation, r.h.d.policyInvalidationDebt, r.h.d.store.ActiveApplied())
		}
	}

	c1Retry = r.h.d.store.ActiveConfig()
	if r.h.d.policyInvalidationDebt != nil || !r.h.d.store.ActiveApplied() {
		t.Fatalf("same-text retry reintroduced scan debt: debt=%+v activeApplied=%v",
			r.h.d.policyInvalidationDebt, r.h.d.store.ActiveApplied())
	}

	for _, tc := range []struct {
		host     string
		policies []string
	}{
		{"clear-c2", []string{"p-first", "web"}},
		{"clear-c3", []string{"p-first"}},
	} {
		old := c1Retry
		next, err := r.h.d.store.SyncApply(policySetFullClearConfigText12072(tc.host, tc.policies), nil)
		if err != nil {
			t.Fatalf("promote %s: %v", tc.host, err)
		}
		if err := r.h.d.applySem.Acquire(context.Background(), 1); err != nil {
			t.Fatal(err)
		}
		_, applyErr := r.h.d.applyAndSyncCommitted(old, next, peerSyncNever)
		r.h.d.applySem.Release(1)
		if applyErr != nil {
			t.Fatalf("commit %s after full clear: %v", tc.host, applyErr)
		}
		if r.h.d.policyInvalidationDebt != nil || !r.h.d.store.ActiveApplied() {
			t.Fatalf("%s retained prior scan debt: debt=%+v activeApplied=%v",
				tc.host, r.h.d.policyInvalidationDebt, r.h.d.store.ActiveApplied())
		}
		c1Retry = next
	}
	if len(r.dp.rows) != 0 || r.dp.helperCfg == c0 {
		t.Fatalf("post-clear transitions failed to converge: rows=%d helper=%p", len(r.dp.rows), r.dp.helperCfg)
	}
}

func TestPolicyInvalidationFullSessionClearRequiresSuccessAndKnownAuthority12072(t *testing.T) {
	for _, tc := range []struct {
		name       string
		clearErr   error
		unknown    bool
		staleStore bool
		wantDebt   bool
		wantRows   int
	}{
		{name: "failed clear", clearErr: errors.New("helper clear failed"), wantDebt: true, wantRows: -1},
		{name: "unknown authority", unknown: true, wantDebt: true},
		{name: "store moved away", staleStore: true, wantDebt: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, _, c1 := newPublishedScanFailure12072(t)
			if tc.staleStore {
				if _, err := r.h.d.store.SyncApply(policySetFullClearConfigText12072(
					"clear-store-c0", []string{"p-first", "a", "b", "web"}), nil); err != nil {
					t.Fatalf("move store away from published target: %v", err)
				}
			}
			originalRows := len(r.dp.rows)
			applied := c1
			if tc.unknown {
				applied = nil
			}
			clearDP := &fullClearSurfaceDP12072{
				Manager: dataplane.New(),
				applied: applied,
				clear: func() (int, int, error) {
					if tc.clearErr != nil {
						return 0, 0, tc.clearErr
					}
					cleared := len(r.dp.rows)
					r.dp.rows = nil
					return cleared, 0, nil
				},
			}
			r.h.d.setDataplane(clearDP)
			v4, _, err := (liveDataPlane{daemon: r.h.d}).ClearAllSessions()
			if tc.clearErr != nil && !errors.Is(err, tc.clearErr) {
				t.Fatalf("failed clear error = %v, want %v", err, tc.clearErr)
			}
			if tc.clearErr == nil && err != nil {
				t.Fatalf("successful helper clear: %v", err)
			}
			if (r.h.d.policyInvalidationDebt != nil) != tc.wantDebt {
				t.Fatalf("debt retained = %v, want %v", r.h.d.policyInvalidationDebt != nil, tc.wantDebt)
			}
			if tc.wantRows >= 0 && len(r.dp.rows) != tc.wantRows {
				t.Fatalf("rows after refused clear = %d, want %d", len(r.dp.rows), tc.wantRows)
			}
			if tc.clearErr == nil && !tc.unknown && v4 != originalRows {
				t.Fatalf("clear count = %d, want %d", v4, originalRows)
			}
			if r.h.d.store.ActiveApplied() {
				t.Fatal("non-retirable clear case marked config applied")
			}
		})
	}
}
func TestPolicyInvalidationFullSessionClearWaitsForApplySerialization12072(t *testing.T) {
	r, _, c1 := newPublishedScanFailure12072(t)
	clearEntered := make(chan struct{}, 1)
	clearDP := &fullClearSurfaceDP12072{
		Manager: dataplane.New(),
		applied: c1,
		clear: func() (int, int, error) {
			clearEntered <- struct{}{}
			return len(r.dp.rows), 0, nil
		},
	}
	r.h.d.setDataplane(clearDP)
	adapter := liveDataPlane{daemon: r.h.d}
	if err := r.h.d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	released := false
	defer func() {
		if !released {
			r.h.d.applySem.Release(1)
		}
	}()

	started := make(chan struct{})
	clearDone := make(chan error, 1)
	go func() {
		close(started)
		_, _, err := adapter.ClearAllSessions()
		clearDone <- err
	}()
	<-started
	select {
	case <-clearEntered:
		r.h.d.applySem.Release(1)
		released = true
		<-clearDone
		t.Fatal("full clear reached the helper while config apply held applySem")
	case <-time.After(100 * time.Millisecond):
	}
	if r.h.d.policyInvalidationDebt == nil {
		t.Fatal("published scan debt retired before the serialized clear ran")
	}
	r.h.d.applySem.Release(1)
	released = true
	select {
	case err := <-clearDone:
		if err != nil {
			t.Fatalf("serialized full clear: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("full clear did not finish after applySem was released")
	}
	select {
	case <-clearEntered:
	default:
		t.Fatal("full clear did not reach the helper after applySem was released")
	}
	if r.h.d.policyInvalidationDebt != nil || !r.h.d.store.ActiveApplied() {
		t.Fatalf("serialized successful clear did not retire debt: debt=%+v activeApplied=%v",
			r.h.d.policyInvalidationDebt, r.h.d.store.ActiveApplied())
	}
}
