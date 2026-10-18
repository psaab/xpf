package daemon

// sshd_reload_debt_14693_test.go — #14693 (D11-03): applySSHConfig's
// update-path reload-failure revert plus the reload-only re-assert
// permanently enforces the reverted permissive policy and falsely
// discharges the reload debt.
//
// Mechanism, verified in source at origin/master:
//   1. Hardening apply writes the new drop-in, `sshd -t` passes, then
//      `systemctl reload sshd` fails transiently. applySSHConfig calls
//      noteSSHDReloadResult(err) (latching sshdReload) AND
//      revertDropIn("reload-failed"), restoring the prior, more
//      permissive bytes (or deleting the drop-in when there was none).
//   2. It then issues a best-effort second reload whose outcome is only
//      logged — its result is never noted — so the debt stays latched.
//   3. The background retry owner, reassertServiceReloadDebtOnce,
//      validates and reloads whatever is ON DISK — the reverted file —
//      and on success calls noteSSHDReloadResult(nil), clearing the debt
//      and logging "sshd reload re-asserted". It never re-renders the
//      desired config, so the running sshd now enforces the reverted
//      permissive policy with no debt recorded anywhere.
//   4. A later identical apply takes the no-change early return
//      (prior == content) without checking sshdReloadOwed(), so even
//      the apply path stops trying.
//
// RED-on-revert: reverting either production arm makes a cell below
// fail —
//   - revert the re-assert re-drive (reload-only reassert): the
//     re-assert cell sees the reverted bytes still on disk and the
//     debt already cleared by the reload of the reverted file;
//   - revert the !sshdReloadOwed() guard on the no-change early
//     return: the no-change-with-debt cell sees no reload issued.

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// commitSSHD14693 commits an ssh stanza through a real config store so
// liveConfig12169() (the store's ActiveConfig) carries the desired
// config — the same authority the background re-assert consults.
func commitSSHD14693(t *testing.T, d *Daemon, rootLogin string) *config.Config {
	t.Helper()
	if err := d.store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := d.store.SetFromInput("system services ssh root-login " + rootLogin); err != nil {
		t.Fatalf("SetFromInput root-login %s: %v", rootLogin, err)
	}
	if _, err := d.store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil || cfg.System.Services == nil || cfg.System.Services.SSH == nil {
		t.Fatalf("fixture premise broken: committed config has no ssh stanza: %+v", cfg)
	}
	return cfg
}

// TestSSHDUpdateReloadFailureReassertRestoresDesired14693 is the
// headline cell: a transient reload failure during a hardening commit
// must not permanently revert the hardening.
//
//	prior on disk:  PermitRootLogin yes   (allow)
//	desired:        PermitRootLogin no    (deny)
//	apply:          write desired, validate OK, reload #1 fails ->
//	                revert to prior, best-effort reload #2 succeeds
//	                (its result is logged only; the debt stays latched)
//	re-assert:      must RE-DRIVE the desired config (rewrite the
//	                drop-in from the live config, validate, reload) and
//	                only then discharge the debt.
func TestSSHDUpdateReloadFailureReassertRestoresDesired14693(t *testing.T) {
	d, r := sshdDebtDaemon6800(t)
	d.store = newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))

	denyCfg := commitSSHD14693(t, d, "deny")
	desired := buildSSHDConfig(denyCfg.System.Services.SSH)
	prior := buildSSHDConfig(&config.SSHServiceConfig{RootLogin: "allow"})
	if desired == "" || prior == "" || desired == prior {
		t.Fatalf("fixture premise broken: desired=%q prior=%q", desired, prior)
	}
	r.present = []byte(prior)

	// Reload #1 (the apply's) fails transiently; every later reload succeeds.
	r.reloadErr = errors.New("simulated transient reload failure")
	r.failNthReload = 1

	if err := d.applySSHConfig(denyCfg); err == nil {
		t.Fatal("the hardening apply must surface the failed reload")
	}
	if string(r.present) != prior {
		t.Fatalf("fixture premise broken: reload failure must revert the drop-in to the prior bytes (#2062)\n got: %q\nwant: %q", r.present, prior)
	}
	if !d.sshdReloadOwed() {
		t.Fatal("setup: the failed apply reload must latch the reload debt")
	}

	// The background retry owner ticks. Pre-fix it validates + reloads
	// the REVERTED file and discharges the debt, leaving the permissive
	// policy enforced forever.
	d.reassertServiceReloadDebtOnce(context.Background())

	if string(r.present) != desired {
		t.Errorf("after the re-assert the drop-in = %q, want the desired hardening %q — "+
			"the re-assert reloaded the reverted permissive file and discharged the "+
			"debt without ever re-rendering the desired config, so sshd permanently "+
			"enforces the pre-hardening policy with no reload owed anywhere (#14693)",
			r.present, desired)
	}
	if d.sshdReloadOwed() {
		t.Error("a successful re-assert of the desired config must discharge the debt")
	}
	if r.reloads < 3 {
		t.Errorf("reloads = %d, want >= 3 (apply, post-revert best-effort, re-assert of the desired config)", r.reloads)
	}

	// Convergence is real: a further re-assert tick is a no-op.
	reloads := r.reloads
	d.reassertServiceReloadDebtOnce(context.Background())
	if r.reloads != reloads {
		t.Errorf("a debt-free re-assert reloaded sshd again (%d -> %d)", reloads, r.reloads)
	}
}

// TestSSHDNoChangeApplyWithOwedReloadReloads14693 is the issue's
// named decisive regression: the no-change early return at the
// `prior == content` guard must include !d.sshdReloadOwed() (the
// removal branch's guard already does).
//
// Scenario: a successful hardening apply leaves desired == disk, then
// a later reload failure latches the debt while the file stays
// converged (the removal-branch shape). The operator re-applies the
// identical config: prior == content, so without the guard the apply
// returns nil without reloading and sshd keeps enforcing the old
// runtime config despite the recorded debt.
func TestSSHDNoChangeApplyWithOwedReloadReloads14693(t *testing.T) {
	d, r := sshdDebtDaemon6800(t)
	cfg := managedSSHCfg6800()
	assertRendersADropIn6800(t, cfg)
	desired := buildSSHDConfig(cfg.System.Services.SSH)

	if err := d.applySSHConfig(cfg); err != nil {
		t.Fatalf("setup apply: %v", err)
	}
	if string(r.present) != desired {
		t.Fatalf("setup: drop-in = %q, want %q", r.present, desired)
	}
	if d.sshdReloadOwed() {
		t.Fatal("setup: a clean apply must owe nothing")
	}

	// A debt latched by some other path while the file is converged.
	d.noteSSHDReloadResult(errors.New("simulated reload failure"))
	if !d.sshdReloadOwed() {
		t.Fatal("setup: the debt must be outstanding")
	}
	reloadsBefore := r.reloads

	if err := d.applySSHConfig(cfg); err != nil {
		t.Fatalf("no-change apply with an owed reload: %v", err)
	}
	if r.reloads != reloadsBefore+1 {
		t.Fatalf("the no-change apply issued %d reloads, want 1 — prior == content "+
			"took the early return without checking sshdReloadOwed(), so the owed "+
			"reload is never re-driven on the apply path and sshd keeps enforcing "+
			"its previous runtime config (#14693)", r.reloads-reloadsBefore)
	}
	if string(r.present) != desired {
		t.Errorf("the no-change apply rewrote the drop-in to %q, want it untouched at %q", r.present, desired)
	}
	if d.sshdReloadOwed() {
		t.Error("the re-issued reload succeeded, so the debt must be discharged")
	}
}

// TestSSHDNoChangeApplyWithoutDebtDoesNotReload14693 is the paired
// negative for the guard: a converged apply with NO debt must still
// take the early return and never SIGHUP sshd. A guard widened past
// the debt would reload sshd on every commit.
func TestSSHDNoChangeApplyWithoutDebtDoesNotReload14693(t *testing.T) {
	d, r := sshdDebtDaemon6800(t)
	cfg := managedSSHCfg6800()
	assertRendersADropIn6800(t, cfg)

	if err := d.applySSHConfig(cfg); err != nil {
		t.Fatalf("setup apply: %v", err)
	}
	reloadsBefore := r.reloads
	writesBefore := r.writeN

	if err := d.applySSHConfig(cfg); err != nil {
		t.Fatalf("no-change apply: %v", err)
	}
	if r.reloads != reloadsBefore {
		t.Errorf("a debt-free no-change apply reloaded sshd (%d -> %d), want no reload", reloadsBefore, r.reloads)
	}
	if r.writeN != writesBefore {
		t.Errorf("a debt-free no-change apply rewrote the drop-in (%d -> %d writes)", writesBefore, r.writeN)
	}
}

// TestSSHDReassertRemovalDebtWithLiveConfigReRemoves14693 pins the
// removal-debt shape under a live config. A failed removal apply
// deletes the drop-in and latches the debt; a later update apply whose
// reload fails REVERTS a drop-in back onto disk before failing. When
// the live config desires no drop-in, the re-assert must re-drive the
// removal (delete + reload), not reload the restored drop-in and
// discharge — sshd would keep enforcing a policy the operator deleted.
func TestSSHDReassertRemovalDebtWithLiveConfigReRemoves14693(t *testing.T) {
	d, r := sshdDebtDaemon6800(t)
	d.store = newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	// Commit a config with no ssh stanza: the live desired state is
	// "no managed drop-in".
	if err := d.store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := d.store.SetFromInput("system host-name no-ssh-14693"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := d.store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if live := d.liveConfig12169(); live == nil {
		t.Fatal("fixture premise broken: no live config")
	}

	// A drop-in is back on disk (restored by a failed update apply's
	// revert) and a reload debt is outstanding.
	r.present = []byte(buildSSHDConfig(&config.SSHServiceConfig{RootLogin: "allow"}))
	d.noteSSHDReloadResult(errors.New("simulated reload failure"))
	if !d.sshdReloadOwed() {
		t.Fatal("setup: the debt must be outstanding")
	}

	d.reassertServiceReloadDebtOnce(context.Background())

	if r.present != nil {
		t.Errorf("after the re-assert the drop-in = %q, want absent — the live config "+
			"desires no drop-in, so the re-assert must re-drive the removal, not "+
			"reload the restored drop-in and discharge (#14693)", r.present)
	}
	if d.sshdReloadOwed() {
		t.Error("a successful removal re-drive must discharge the debt")
	}
}
