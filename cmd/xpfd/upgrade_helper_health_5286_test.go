package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/upgrade"
)

// wiringBudget9502 is the HelperHealthy deadline for the cells that assert
// WIRING or a HEALTHY verdict (#9502). Their fakes answer instantly, and a wired
// probe returns as soon as one evaluation sees armed+forwarding on the target,
// so a generous budget costs nothing when the code is right. It only has to
// outlast scheduling latency. The old 50 ms / 200 ms budgets could expire under
// load BEFORE the probe's first evaluation, which then never reached the swapped
// status query and reported "not wired" about correct wiring. A reverted site
// still fails: the is-active-only fallback never consults the status seam.
const wiringBudget9502 = 10 * time.Second

// installProbeSeams9502 points every #5286 probe seam at fakes: the unit is
// active (after an optional stall), the helper is up and armed only when
// forwarding is true, and it executes the target version's binary. The returned
// pointer reports whether the control-socket status query was consulted. Seams
// are restored when the test ends.
func installProbeSeams9502(t *testing.T, versions, target string, forwarding bool, unitActiveStall time.Duration) *bool {
	t.Helper()
	called := new(bool)
	t.Cleanup(swapHelperStatus(func(string, time.Duration) (bool, bool, int, error) {
		*called = true
		return true, forwarding, 555, nil
	}))
	t.Cleanup(swapUnitActive(func(context.Context, string) (bool, error) {
		if unitActiveStall > 0 {
			time.Sleep(unitActiveStall)
		}
		return true, nil
	}))
	t.Cleanup(swapHelperExe(func(int) (string, error) {
		return filepath.Join(versions, target, "xpf-userspace-dp"), nil
	}))
	t.Cleanup(swapControlSock(func(string) string { return "/unused-in-test.sock" }))
	return called
}

// TestBuildUpgradeSystem_WiresHelperProbe_5286 proves the production upgrade
// System construction site actually WIRES the helper-readiness probe
// (NewSystemWithHelperHealth), not the pre-fix is-active-only NewSystem whose
// realSystem.HelperHealthy ignored expectVersion and admitted a non-forwarding
// daemon.
//
// It asserts ONE property: the REAL production Config assembly
// (newUpgradeConfig -> Sys) consults the control-socket status seam. The fake
// reports the helper armed+forwarding on the target, so a wired System returns
// healthy right after that query. If the site is reverted to
// upgrade.NewSystem(flags.unit), the status seam is never called -> RED.
//
// #9502: this cell used to ALSO assert fail-closed on a not-forwarding helper
// inside one 50 ms window. That window could expire under load before the first
// evaluation, so the cell reported "not wired" about correct wiring. Fail-closed
// is now its own cell below, and this one runs on wiringBudget9502.
func TestBuildUpgradeSystem_WiresHelperProbe_5286(t *testing.T) {
	versions := t.TempDir()
	const target = "3.1.4"
	statusCalled := installProbeSeams9502(t, versions, target, true, 0)

	cfg := newUpgradeConfig(upgradeFlags{unit: "xpfd", versionsDir: versions, configDBDir: t.TempDir()})
	err := cfg.Sys.HelperHealthy(target, wiringBudget9502)
	if !*statusCalled {
		t.Fatalf("production System did NOT consult the control-socket helper status query within a %s "+
			"budget (HelperHealthy returned: %v). NewSystemWithHelperHealth is not wired: newUpgradeConfig "+
			"regressed to the is-active-only upgrade.NewSystem. Scheduling latency cannot explain a missed "+
			"query at this budget (#9502).", wiringBudget9502, err)
	}
	if err != nil {
		t.Fatalf("the wired System must report healthy for an armed+forwarding helper on the target: %v", err)
	}
}

// TestBuildUpgradeSystem_FailsClosedWhenNotForwarding_5286: the wired System
// must refuse a helper that is up but NOT forwarding. The assertion cannot flake
// under load (#9502): a starved probe that never evaluates also returns an
// error. When the probe DID evaluate, the refusal must name the not-forwarding
// cause rather than some other failure. The budget stays short on purpose: a
// not-forwarding helper polls until the deadline by design, so a long budget
// would only slow the cell.
func TestBuildUpgradeSystem_FailsClosedWhenNotForwarding_5286(t *testing.T) {
	versions := t.TempDir()
	const target = "3.1.4"
	statusCalled := installProbeSeams9502(t, versions, target, false, 0)

	sys := buildUpgradeSystem(upgradeFlags{unit: "xpfd", versionsDir: versions, configDBDir: t.TempDir()})
	err := sys.HelperHealthy(target, 50*time.Millisecond)
	if err == nil {
		t.Fatal("production System must FAIL CLOSED when the helper is up but not forwarding")
	}
	if *statusCalled && !strings.Contains(err.Error(), "helper not forwarding") {
		t.Fatalf("the status query answered not-forwarding, but the refusal names another cause: %v", err)
	}
}

// TestBuildUpgradeSystem_WiringAbsorbsAStall_9502 is the load control for the
// wiring cell. A unit-active probe that stalls for three times the old 50 ms
// budget must still leave the status query consulted within wiringBudget9502.
// With the old budget this exact sequence skipped the query and produced the
// false "not wired" failure.
func TestBuildUpgradeSystem_WiringAbsorbsAStall_9502(t *testing.T) {
	versions := t.TempDir()
	const target = "3.1.4"
	const stall = 150 * time.Millisecond
	statusCalled := installProbeSeams9502(t, versions, target, true, stall)

	sys := buildUpgradeSystem(upgradeFlags{unit: "xpfd", versionsDir: versions, configDBDir: t.TempDir()})
	err := sys.HelperHealthy(target, wiringBudget9502)
	if !*statusCalled || err != nil {
		t.Fatalf("a %s stall before the first evaluation must not starve the status query at a %s budget: "+
			"statusCalled=%v err=%v", stall, wiringBudget9502, *statusCalled, err)
	}
}

// TestBuildUpgradeSystem_ArmedForwardingTarget_Healthy: the wired System reports
// healthy when the helper is armed+forwarding and executing the target version.
func TestBuildUpgradeSystem_ArmedForwardingTarget_Healthy(t *testing.T) {
	versions := t.TempDir()
	const target = "3.1.4"

	restoreStatus := swapHelperStatus(func(string, time.Duration) (bool, bool, int, error) {
		return true, true, 777, nil // armed + forwarding
	})
	defer restoreStatus()
	restoreActive := swapUnitActive(func(context.Context, string) (bool, error) { return true, nil })
	defer restoreActive()
	restoreExe := swapHelperExe(func(int) (string, error) {
		return filepath.Join(versions, target, "xpf-userspace-dp"), nil
	})
	defer restoreExe()
	restoreSock := swapControlSock(func(string) string { return "/unused-in-test.sock" })
	defer restoreSock()

	sys := buildUpgradeSystem(upgradeFlags{unit: "xpfd", versionsDir: versions, configDBDir: t.TempDir()})
	if err := sys.HelperHealthy(target, wiringBudget9502); err != nil {
		t.Fatalf("armed+forwarding on the target version must be healthy: %v", err)
	}
}

// swap helpers save/restore the package-level probe seams.

func swapHelperStatus(f upgrade.HelperStatusFunc) func() {
	old := upgradeHelperStatus
	upgradeHelperStatus = f
	return func() { upgradeHelperStatus = old }
}

func swapHelperExe(f upgrade.HelperExeFunc) func() {
	old := upgradeHelperExe
	upgradeHelperExe = f
	return func() { upgradeHelperExe = old }
}

func swapUnitActive(f func(context.Context, string) (bool, error)) func() {
	old := upgradeUnitActive
	upgradeUnitActive = f
	return func() { upgradeUnitActive = old }
}

func swapControlSock(f func(string) string) func() {
	old := upgradeControlSock
	upgradeControlSock = f
	return func() { upgradeControlSock = old }
}
