package userspace

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// #6675: this package's tests must not depend on being allowed to dump the
// kernel ip-rule table.
//
// buildRouteSnapshots enumerates ip-rules through ruleListFn and, since #3772
// (M9), deliberately does NOT swallow a dump failure — a snapshot missing a
// family's route-leak routes would blackhole or policy-bypass inter-VRF
// traffic. That is correct for production and it is what makes the test
// surface fragile: in a sandbox without CAP_NET_ADMIN the dump returns EPERM,
// buildRouteSnapshots returns (nil, err), buildSnapshot propagates it, and the
// ~45 test call sites that discard the error dereference a nil
// *ConfigSnapshot.
//
// The cost is not one failed test. A nil dereference is a SIGSEGV that aborts
// the whole test BINARY, so the first one takes every remaining test in the
// package down with it and the run reports a crash with no diagnostic rather
// than a skip. That is what made an unrelated PR's review look like a
// regression (a Codex hostile review of #6670, whose sandbox could not
// enumerate route rules).
//
// The fix is hermeticity rather than detection. Skipping on EPERM — the
// obvious reading — would trade a crash for silence and leave the package with
// NO coverage in exactly the reduced-capability environments where reviews run.
// Stubbing the enumerator instead lets every one of those tests actually RUN
// there. No test in this package wants real kernel rules: the three that care
// about rule CONTENT (routes_6467*, manager_fabric_writeback_5306,
// manager_overlay_scheduler_5328) already install their own stub, and they
// still work — they capture the current ruleListFn and restore it on cleanup,
// which now restores to this stub rather than to netlink.RuleList.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "userspace-nat-generation")
	if err != nil {
		panic(err)
	}
	persistentNatLeaseGenerationPath11486 = filepath.Join(dir, "generation.json")
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, nil }
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// TestPackageIsHermeticWrtKernelIPRules_6675 binds the WIRING above, not the
// behaviour of the stub. Deleting the assignment in TestMain is the exact
// regression this guards, and without a check on the live value that deletion
// is invisible on any machine that happens to have CAP_NET_ADMIN — which is
// every developer laptop and most CI runners, i.e. everywhere except the
// sandbox this was filed for.
//
// Comparing code pointers is what makes it detectable: it asks "is the
// enumerator still the real netlink one?" rather than "does calling it
// happen to work here?", so the guard fails on a capable machine too.
func TestPackageIsHermeticWrtKernelIPRules_6675(t *testing.T) {
	live := reflect.ValueOf(ruleListFn).Pointer()
	real := reflect.ValueOf(netlink.RuleList).Pointer()

	// Vacuity: if these two ever compared equal for a reason other than the
	// one under test, the assertion below would be meaningless. A nil
	// ruleListFn would panic in reflect, so pin that it is set at all.
	if ruleListFn == nil {
		t.Fatal("ruleListFn is nil; the package cannot build a route snapshot at all")
	}

	if live == real {
		t.Fatal("ruleListFn is still netlink.RuleList: this package's tests will " +
			"dump the kernel ip-rule table, and in a sandbox without CAP_NET_ADMIN " +
			"that EPERM becomes a nil *ConfigSnapshot dereference that SIGSEGVs the " +
			"whole test binary. Restore the stub in TestMain (#6675).")
	}
}

// TestSnapshotBuildsWithoutKernelIPRules_6675 is the end-to-end half: it proves
// the property the stub exists to provide, so the guard above cannot be
// satisfied by a stub that is installed but does not actually make snapshot
// building work.
func TestSnapshotBuildsWithoutKernelIPRules_6675(t *testing.T) {
	snap, err := buildSnapshot(&config.Config{}, config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot failed with the hermetic ip-rule enumerator: %v", err)
	}
	if snap == nil {
		t.Fatal("buildSnapshot returned a nil snapshot with a nil error")
	}
}
