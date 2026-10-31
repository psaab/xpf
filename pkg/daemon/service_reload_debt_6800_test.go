package daemon

// service_reload_debt_6800_test.go — #6800 RETRY-OWNER regression.
//
// The two managed-service-file appliers converge an on-disk configuration and
// then gate a RUNTIME reload on "did the on-disk set change". The gate is what
// keeps a steady-state commit from bouncing rsyslog/chrony — but it also erased
// the debt of a FAILED reload: the write half had already converged the files,
// so every later apply compared desired against the converged set, saw no
// change, skipped the reload, and the daemon kept serving the PREVIOUS ruleset
// until an unrelated syslog/NTP edit or a reboot.
//
// Every cell below reverts to green under exactly one reverted production
// line; the pairings (fires / does-not-fire, sources-leg / threshold-leg) are
// what stop the fix from becoming "reload on every commit" and what keep a
// compound mutation from masking half of itself.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
)

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

// syslogDaemon6800 points the rsyslog drop-in reconcile at a temp dir and
// installs a restart spy. It returns the daemon, a pointer to the restart
// count, and a pointer to the error the spy returns (flip it between applies).
// Both counters are read through mutex-guarded ACCESSORS rather than returned
// as pointers: the re-assert loop calls the spy from its own goroutine, so a
// raw `*restarts` read in the test body is a data race (`-race` reports it),
// and a racy read is exactly the "reading of the machine rather than of the
// subject" shape docs/engineering-style.md #7563 warns about.
func syslogDaemon6800(t *testing.T) (d *Daemon, restarts func() int, setFail func(error)) {
	t.Helper()

	dir := t.TempDir()
	origDir := rsyslogConfDir
	rsyslogConfDir = dir
	t.Cleanup(func() { rsyslogConfDir = origDir })

	var mu sync.Mutex
	n := 0
	var fail error
	var onCall func()
	origFn := rsyslogRestartFn
	rsyslogRestartFn = func() ([]byte, error) {
		mu.Lock()
		n++
		err, hook := fail, onCall
		mu.Unlock()
		if hook != nil {
			hook()
		}
		return nil, err
	}
	t.Cleanup(func() { rsyslogRestartFn = origFn })

	d = &Daemon{}
	restarts = func() int {
		mu.Lock()
		defer mu.Unlock()
		return n
	}
	setFail = func(e error) {
		mu.Lock()
		defer mu.Unlock()
		fail = e
	}
	syslogSpyHook6800 = func(h func()) {
		mu.Lock()
		defer mu.Unlock()
		onCall = h
	}
	return d, restarts, setFail
}

// syslogSpyHook6800 installs a callback the rsyslog spy runs (outside its own
// lock) on every restart. It is how the interleave cell below observes that the
// re-assert is provably INSIDE the semaphore, instead of racing a sleep.
var syslogSpyHook6800 func(func())

// syslogFileCfg6800 builds a config with one `system syslog file` destination.
func syslogFileCfg6800(name string) *config.Config {
	cfg := &config.Config{}
	cfg.System.Syslog = &config.SystemSyslogConfig{
		Files: []*config.SyslogFileConfig{
			{Name: name, Selectors: []config.SyslogFacility{{Facility: "any", Severity: "info"}}},
		},
	}
	return cfg
}

// chronyDaemon6800 points the two managed chrony files at a temp dir and
// installs a reload spy that records the exact (sources, threshold) request it
// was issued. The returned outcome pointer decides what the spy reports back.
func chronyDaemon6800(t *testing.T) (d *Daemon, calls func() [][2]bool, setOutcome func(chronyReloadOutcome)) {
	t.Helper()

	dir := t.TempDir()
	origSrc, origThr, origAcq := chronySourcesPath, chronyThresholdPath, chronyAcquisitionPath
	chronySourcesPath = filepath.Join(dir, "xpf.sources")
	chronyThresholdPath = filepath.Join(dir, "xpf-threshold.conf")
	chronyAcquisitionPath = filepath.Join(dir, "xpf-acquisition.conf")
	t.Cleanup(func() { chronySourcesPath, chronyThresholdPath, chronyAcquisitionPath = origSrc, origThr, origAcq })
	// #18584: the owed-restart flag is process-wide, like chronyRunCmd.
	chronyAcqRestartOwed.Store(false)
	t.Cleanup(func() { chronyAcqRestartOwed.Store(false) })

	var mu sync.Mutex
	var got [][2]bool
	var out chronyReloadOutcome
	origFn := chronyReloadFn
	chronyReloadFn = func(sources, threshold bool) chronyReloadOutcome {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, [2]bool{sources, threshold})
		return out
	}
	t.Cleanup(func() { chronyReloadFn = origFn })

	d = &Daemon{}
	calls = func() [][2]bool {
		mu.Lock()
		defer mu.Unlock()
		return append([][2]bool(nil), got...)
	}
	setOutcome = func(o chronyReloadOutcome) {
		mu.Lock()
		defer mu.Unlock()
		out = o
	}
	return d, calls, setOutcome
}

// ntpCfg6800 builds a `system ntp` config with the given servers and threshold.
func ntpCfg6800(servers []string, threshold int) *config.Config {
	cfg := &config.Config{}
	cfg.System.NTPServers = servers
	if threshold > 0 {
		cfg.System.NTPThreshold = threshold
		cfg.System.NTPThresholdAction = "accept"
	}
	return cfg
}

// ---------------------------------------------------------------------------
// rsyslog: the debt is latched, discharged, and consulted by the next apply
// ---------------------------------------------------------------------------

// TestSyslogRestartOutcomeLatchesAndDischargesTheDebt6800 is the PAIRED
// outcome cell: the same apply, two restart results, opposite debt states.
//
// The FAILURE leg reds if noteRsyslogRestartResult is dropped from the apply
// path — the #6800 defect itself, which loses the only record that rsyslog
// never re-read the converged drop-ins.
//
// The SUCCESS leg reds if the note only ever LATCHES (`if err != nil { … =
// true }`) and never clears. Without the discharge the re-assert loop would
// bounce a healthy rsyslog every 30s forever after one transient failure —
// turning the retry owner into a new outage.
func TestSyslogRestartOutcomeLatchesAndDischargesTheDebt6800(t *testing.T) {
	d, restarts, setFail := syslogDaemon6800(t)
	cfg := syslogFileCfg6800("audit")

	setFail(errors.New("simulated: Job for rsyslog.service failed"))
	d.applySyslogFiles(cfg)
	if restarts() != 1 {
		t.Fatalf("setup: the first apply must issue the restart (writes a new "+
			"drop-in, so changed=true); got %d restarts", restarts())
	}
	if !d.rsyslogRestartOwed() {
		t.Fatal("a FAILED `systemctl restart rsyslog` must latch the restart debt. " +
			"The drop-ins are already converged on disk, so the next apply's " +
			"`changed` flag is false and this debt is the ONLY record that " +
			"rsyslog is still serving the previous ruleset (#6800)")
	}

	setFail(nil)
	d.applySyslogFiles(cfg)
	if d.rsyslogRestartOwed() {
		t.Fatal("a SUCCESSFUL restart must DISCHARGE the debt — leaving it latched " +
			"makes the always-on re-assert bounce a healthy rsyslog every tick " +
			"forever (#6800)")
	}
}

// TestSteadyStateApplyRetriesTheOwedSyslogRestart6800 is the headline cell.
//
// Apply #1 writes the drop-in and its restart FAILS. Apply #2 presents the
// SAME config: the reconcile finds the files already converged and reports
// changed=false — which is precisely the state in which the pre-#6800 gate
// (`if changed`) skipped the restart and stranded rsyslog on the old ruleset.
// The retained debt must re-issue it.
//
// The fixture premise is guarded explicitly: a third reconcile against the
// identical desired set must report NO change, or apply #2 would have restarted
// for an ordinary content change and this cell would prove nothing.
func TestSteadyStateApplyRetriesTheOwedSyslogRestart6800(t *testing.T) {
	d, restarts, setFail := syslogDaemon6800(t)
	cfg := syslogFileCfg6800("audit")

	setFail(errors.New("simulated restart failure"))
	d.applySyslogFiles(cfg)

	// Premise: the drop-in set is now CONVERGED, so a further reconcile with
	// the same desired set is a no-op. Without this the cell could pass on a
	// content change rather than on the retained debt.
	desired := syslogDropinContents(cfg, "10-xpf-")
	if len(desired) == 0 {
		t.Fatal("fixture rendered ZERO drop-ins, so no apply could ever restart " +
			"rsyslog and every assertion here would be vacuous")
	}
	if reconcileSyslogDropins(rsyslogConfDir, "10-xpf-", desired) {
		t.Fatal("fixture premise broken: the drop-ins are not converged after the " +
			"first apply, so apply #2 would restart for a content change rather " +
			"than for the retained debt")
	}

	setFail(nil)
	before := restarts()
	d.applySyslogFiles(cfg)
	if restarts() != before+1 {
		t.Fatalf("a steady-state apply issued %d restarts (want %d): the managed "+
			"drop-ins converged on disk, so `changed` is false and only the "+
			"retained debt can re-drive the restart. Without it rsyslog keeps "+
			"serving the PREVIOUS ruleset — records still flowing to a removed "+
			"destination — until an unrelated syslog edit or a reboot (#6800)",
			restarts()-before, 1)
	}
	if d.rsyslogRestartOwed() {
		t.Fatal("the re-issued restart succeeded, so the debt must be discharged")
	}
}

// TestSteadyStateApplyWithNoDebtDoesNotRestartRsyslog6800 is the PAIRED
// negative, and it is what keeps the fix from being a regression of its own.
//
// An apply that changes nothing and owes nothing must NOT touch rsyslog. A
// gate widened to `if true` (or to something that never clears) would restart
// the logging pipeline on every single commit — the exact behaviour the
// `changed` gate exists to prevent.
func TestSteadyStateApplyWithNoDebtDoesNotRestartRsyslog6800(t *testing.T) {
	d, restarts, setFail := syslogDaemon6800(t)
	cfg := syslogFileCfg6800("audit")

	setFail(nil)
	d.applySyslogFiles(cfg) // converges + restarts once, successfully
	if restarts() != 1 {
		t.Fatalf("setup: want 1 restart from the first apply, got %d", restarts())
	}

	d.applySyslogFiles(cfg)
	d.applySyslogFiles(cfg)
	if restarts() != 1 {
		t.Fatalf("a converged, debt-free apply restarted rsyslog (%d total, want 1) "+
			"— the `changed` gate must still suppress the steady state (#6800)",
			restarts())
	}
}

// ---------------------------------------------------------------------------
// chrony: per-leg outcomes
// ---------------------------------------------------------------------------

// TestChronySourcesLegReportsItsOwnOutcome6800 is the PAIRED cell for the
// SOURCES leg of reloadChronyRuntime, driven through the real function.
//
// It is deliberately separate from the threshold cell: a compound mutation
// that broke both legs would be masked by a single combined cell, and the two
// legs drive different commands.
func TestChronySourcesLegReportsItsOwnOutcome6800(t *testing.T) {
	orig := chronyRunCmd
	t.Cleanup(func() { chronyRunCmd = orig })

	var seen []string
	fail := true
	chronyRunCmd = func(_ context.Context, name string, args ...string) ([]byte, error) {
		seen = append(seen, name+" "+strings.Join(args, " "))
		if fail {
			return []byte("simulated"), errors.New("simulated chronyc failure")
		}
		return nil, nil
	}

	out := reloadChronyRuntime(true, false)
	if !out.sourcesFailed {
		t.Fatal("a failing `chronyc reload sources` must be REPORTED as a failed " +
			"sources leg. reconcileManagedFile has already written xpf.sources, " +
			"so the next apply computes changed=false against the converged file " +
			"and this outcome is the only thing that can carry the owed reload " +
			"forward (#6800)")
	}
	if out.thresholdFailed {
		t.Fatal("a sources-only request must never report a threshold failure — " +
			"the caller assigns the outcome straight onto the retained debt, so a " +
			"spurious threshold failure would latch a reload nobody asked for")
	}
	if len(seen) != 1 || !strings.HasPrefix(seen[0], "chronyc reload sources") {
		t.Fatalf("sources leg ran %v, want exactly [chronyc reload sources]", seen)
	}

	fail = false
	if out := reloadChronyRuntime(true, false); out.sourcesFailed {
		t.Fatal("a SUCCESSFUL sources reload must not report a failure — it would " +
			"latch a permanent debt and re-drive chronyc every 30s forever")
	}
}

// TestChronyThresholdLegReportsItsOwnOutcome6800 is the PAIRED cell for the
// THRESHOLD leg: it must report failure only after ALL FOUR fallback commands
// have failed, and must report success as soon as one of them works.
func TestChronyThresholdLegReportsItsOwnOutcome6800(t *testing.T) {
	orig := chronyRunCmd
	t.Cleanup(func() { chronyRunCmd = orig })

	failAll := true
	var attempts int
	chronyRunCmd = func(_ context.Context, name string, args ...string) ([]byte, error) {
		attempts++
		if failAll || attempts < 2 {
			return []byte("simulated"), errors.New("simulated systemctl failure")
		}
		return nil, nil
	}

	out := reloadChronyRuntime(false, true)
	if !out.thresholdFailed {
		t.Fatal("every chrony reload/restart fallback failed, so the threshold leg " +
			"must be REPORTED as owed. xpf-threshold.conf is already on disk, so " +
			"the next apply sees changed=false and without this outcome the " +
			"running chrony keeps the previous logchange/maxchange (#6800)")
	}
	if out.sourcesFailed {
		t.Fatal("a threshold-only request must never report a sources failure")
	}
	if attempts != 4 {
		t.Fatalf("threshold leg made %d attempts, want all 4 fallbacks", attempts)
	}

	failAll = false
	attempts = 0
	if out := reloadChronyRuntime(false, true); out.thresholdFailed {
		t.Fatal("a fallback that SUCCEEDED must clear the threshold leg — reporting " +
			"failure anyway latches a permanent debt on a healthy chrony")
	}
}

// TestChronySourcesLegCannotStarveTheThresholdFallbacks6800 binds the sources
// leg's OWN deadline.
//
// Before this, one 15s context covered `chronyc reload sources` and all four
// threshold fallbacks. A single hung chronyc consumed the whole budget, so
// every fallback ran against an already-expired context and failed instantly —
// 15 seconds of apply latency buying no convergence on either leg, and a
// threshold reload that was never really attempted. (opus-review-001 R61 raised
// this alongside the erased debt.)
//
// Two assertions, because they fail for different reasons. The DEADLINE check
// is instant and reds the moment the sources leg goes back to sharing the
// aggregate context. The BEHAVIOURAL check drives the actual starvation: the
// sources stub burns its whole budget, and the fallbacks must still find time
// left on the clock.
func TestChronySourcesLegCannotStarveTheThresholdFallbacks6800(t *testing.T) {
	origRun, origTimeout := chronyRunCmd, chronySourcesReloadTimeout
	t.Cleanup(func() { chronyRunCmd, chronySourcesReloadTimeout = origRun, origTimeout })
	chronySourcesReloadTimeout = 20 * time.Millisecond

	type call struct {
		name     string
		deadline time.Time
		expired  bool
	}
	var calls []call
	chronyRunCmd = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		dl, _ := ctx.Deadline()
		c := call{name: name, deadline: dl, expired: ctx.Err() != nil}
		if name == "chronyc" {
			// Simulate a hung chronyc: consume the ENTIRE budget it was given.
			<-ctx.Done()
			c.expired = true
			calls = append(calls, c)
			return nil, ctx.Err()
		}
		calls = append(calls, c)
		return nil, errors.New("simulated systemctl failure")
	}

	out := reloadChronyRuntime(true, true)

	if len(calls) != 5 {
		t.Fatalf("got %d commands, want 5 (chronyc + four systemctl fallbacks): %v",
			len(calls), calls)
	}
	if calls[0].name != "chronyc" {
		t.Fatalf("first command = %q, want chronyc", calls[0].name)
	}
	for _, c := range calls[1:] {
		if !c.deadline.After(calls[0].deadline) {
			t.Errorf("fallback %q shares the sources leg's deadline (%v vs %v); a "+
				"hung chronyc then consumes the whole aggregate budget and every "+
				"fallback runs against an expired context — the threshold reload "+
				"is never really attempted (#6800, R61)",
				c.name, c.deadline, calls[0].deadline)
		}
		if c.expired {
			t.Errorf("fallback %q ran against an ALREADY-EXPIRED context after the "+
				"sources leg burned its budget; bounding the sources leg "+
				"separately is what guarantees the fallbacks a share", c.name)
		}
	}
	if !out.sourcesFailed || !out.thresholdFailed {
		t.Errorf("outcome = %+v; both legs failed here, and both must be reported "+
			"so the retry owner replays them", out)
	}
}

// ---------------------------------------------------------------------------
// chrony: the debt is retained per-leg and REPLAYED, not re-derived
// ---------------------------------------------------------------------------

// TestOwedChronySourcesLegSurvivesAThresholdOnlyApply6800 binds the retained
// SOURCES leg.
//
// This is the "retain the exact owed request" property. Apply #1 changes only
// the sources file and its reload fails. Apply #2 changes only the THRESHOLD
// file. Re-deriving the request from apply #2's own change flags would issue
// (sources=false, threshold=true) and silently drop the sources debt — chrony
// would keep polling the OLD server set forever. The apply must fold the
// retained leg in.
func TestOwedChronySourcesLegSurvivesAThresholdOnlyApply6800(t *testing.T) {
	d, calls, setOutcome := chronyDaemon6800(t)

	setOutcome(chronyReloadOutcome{sourcesFailed: true})
	d.applySystemNTP(ntpCfg6800([]string{"10.0.0.1"}, 0))
	if len(calls()) != 1 || (calls())[0] != [2]bool{true, false} {
		t.Fatalf("setup: apply #1 must request the sources leg only, got %v", calls())
	}
	if s, th := d.chronyReloadOwed(); !s || th {
		t.Fatalf("setup: want debt (sources=true, threshold=false), got (%v, %v)", s, th)
	}

	// Apply #2: same servers (sources file converged), NEW threshold.
	setOutcome(chronyReloadOutcome{})
	d.applySystemNTP(ntpCfg6800([]string{"10.0.0.1"}, 120))
	if len(calls()) != 2 {
		t.Fatalf("apply #2 issued %d reloads, want 2", len(calls()))
	}
	if (calls())[1] != [2]bool{true, true} {
		t.Fatalf("apply #2 requested %v, want [sources=true threshold=true]: the "+
			"owed SOURCES leg must be folded into the request. Re-deriving it "+
			"from this apply's own change flags drops it — the sources file is "+
			"already converged, so nothing else can see that chrony never "+
			"re-read it (#6800)", (calls())[1])
	}
	if s, th := d.chronyReloadOwed(); s || th {
		t.Fatalf("both legs succeeded, so the debt must be discharged; got (%v, %v)", s, th)
	}
}

// TestOwedChronyThresholdLegSurvivesASourcesOnlyApply6800 is the SYMMETRIC
// cell for the THRESHOLD leg. Symmetry is where a compound mutation bites: a
// single cell covering one direction stays green when the other direction's
// fold is reverted.
func TestOwedChronyThresholdLegSurvivesASourcesOnlyApply6800(t *testing.T) {
	d, calls, setOutcome := chronyDaemon6800(t)

	setOutcome(chronyReloadOutcome{thresholdFailed: true})
	d.applySystemNTP(ntpCfg6800([]string{"10.0.0.1"}, 120))
	if len(calls()) != 1 || (calls())[0] != [2]bool{true, true} {
		t.Fatalf("setup: apply #1 must request both legs, got %v", calls())
	}
	if s, th := d.chronyReloadOwed(); s || !th {
		t.Fatalf("setup: want debt (sources=false, threshold=true), got (%v, %v)", s, th)
	}

	// Apply #2: NEW server list, same threshold (threshold file converged).
	setOutcome(chronyReloadOutcome{})
	d.applySystemNTP(ntpCfg6800([]string{"10.0.0.1", "10.0.0.2"}, 120))
	if len(calls()) != 2 {
		t.Fatalf("apply #2 issued %d reloads, want 2", len(calls()))
	}
	if (calls())[1] != [2]bool{true, true} {
		t.Fatalf("apply #2 requested %v, want [sources=true threshold=true]: the "+
			"owed THRESHOLD leg must be folded into the request (#6800)",
			(calls())[1])
	}
}

// TestSteadyStateNTPApplyRetriesTheOwedChronyReload6800 binds the ORDER of the
// fold against the early return.
//
// The two cells above both present an apply that changes SOMETHING, so they
// stay green even if the fold were placed after `if !sourcesChanged &&
// !thresholdChanged { return }`. This one presents the identical config twice:
// both files are converged, both change flags are false, and the early return
// is the thing that would swallow the retry.
func TestSteadyStateNTPApplyRetriesTheOwedChronyReload6800(t *testing.T) {
	d, calls, setOutcome := chronyDaemon6800(t)
	cfg := ntpCfg6800([]string{"10.0.0.1"}, 120)

	setOutcome(chronyReloadOutcome{sourcesFailed: true, thresholdFailed: true})
	d.applySystemNTP(cfg)
	if len(calls()) != 1 {
		t.Fatalf("setup: want 1 reload from the first apply, got %d", len(calls()))
	}

	setOutcome(chronyReloadOutcome{})
	d.applySystemNTP(cfg)
	if len(calls()) != 2 {
		t.Fatalf("a steady-state apply issued %d reloads, want 2: both managed "+
			"chrony files are converged so both change flags are false, and only "+
			"the retained debt — folded in BEFORE the no-change early return — "+
			"can re-drive the reload (#6800)", len(calls()))
	}
	if (calls())[1] != [2]bool{true, true} {
		t.Fatalf("the retry requested %v, want both owed legs replayed", (calls())[1])
	}
	if s, th := d.chronyReloadOwed(); s || th {
		t.Fatalf("the retry succeeded, so the debt must be discharged; got (%v, %v)", s, th)
	}
}

// TestSteadyStateNTPApplyWithNoDebtDoesNotReload6800 is the PAIRED negative:
// a converged, debt-free apply must leave chrony alone. `systemctl restart
// chrony` is one of the fallbacks, so a gate that fired every commit would
// periodically bounce time sync.
func TestSteadyStateNTPApplyWithNoDebtDoesNotReload6800(t *testing.T) {
	d, calls, setOutcome := chronyDaemon6800(t)
	cfg := ntpCfg6800([]string{"10.0.0.1"}, 120)

	setOutcome(chronyReloadOutcome{})
	d.applySystemNTP(cfg)
	if len(calls()) != 1 {
		t.Fatalf("setup: want 1 reload from the first apply, got %d", len(calls()))
	}

	d.applySystemNTP(cfg)
	d.applySystemNTP(cfg)
	if len(calls()) != 1 {
		t.Fatalf("a converged, debt-free apply reloaded chrony (%d total, want 1) "+
			"— the change gate must still suppress the steady state (#6800)",
			len(calls()))
	}
}

// TestSteadyStateDisabledNTPApplyRetriesTheOwedChronyReload6800 binds the fold
// on the `system processes ntp disable` branch, which has its own copy of it.
//
// The sequence is the ordinary one for a disabled NTP stanza: the first apply
// after the operator disables NTP REMOVES the two managed files (changed=true)
// and its reload fails; every later apply finds them already absent, so both
// change flags are false. Without the fold on this branch the owed reload is
// dropped and chrony keeps the removed sources loaded — the deleted-destination
// shape #5111 fixed for rsyslog, reached through the reload instead of the file.
func TestSteadyStateDisabledNTPApplyRetriesTheOwedChronyReload6800(t *testing.T) {
	d, calls, setOutcome := chronyDaemon6800(t)

	// Seed the files a previously-enabled apply would have left behind.
	if err := os.WriteFile(chronySourcesPath, []byte("server 10.0.0.1 iburst\n"), 0644); err != nil {
		t.Fatalf("seed sources: %v", err)
	}
	if err := os.WriteFile(chronyThresholdPath, []byte("logchange 120\n"), 0644); err != nil {
		t.Fatalf("seed threshold: %v", err)
	}

	cfg := ntpCfg6800(nil, 0)
	cfg.System.DisabledProcesses = []string{"ntp"}

	setOutcome(chronyReloadOutcome{sourcesFailed: true, thresholdFailed: true})
	d.applySystemNTP(cfg)
	if len(calls()) != 1 || (calls())[0] != [2]bool{true, true} {
		t.Fatalf("setup: the disabling apply must remove both files and request "+
			"both legs, got %v", calls())
	}
	if _, err := os.Stat(chronySourcesPath); !os.IsNotExist(err) {
		t.Fatalf("setup: the managed sources file must be removed, stat err = %v", err)
	}

	setOutcome(chronyReloadOutcome{})
	d.applySystemNTP(cfg)
	if len(calls()) != 2 {
		t.Fatalf("a steady-state DISABLED apply issued %d reloads, want 2: the "+
			"managed files are already gone so both change flags are false, and "+
			"only the retained debt can re-drive the reload that tells chrony to "+
			"drop the removed sources (#6800)", len(calls()))
	}
	if (calls())[1] != [2]bool{true, true} {
		t.Fatalf("the retry requested %v, want both owed legs replayed", (calls())[1])
	}

	// PAIRED negative: now that the debt is discharged, a further disabled apply
	// must not touch chrony at all.
	d.applySystemNTP(cfg)
	if len(calls()) != 2 {
		t.Fatalf("a converged, debt-free DISABLED apply reloaded chrony (%d total, "+
			"want 2) — the change gate must still suppress the steady state", len(calls()))
	}
}

// ---------------------------------------------------------------------------
// the always-on re-assert loop
// ---------------------------------------------------------------------------

// TestReassertRedrivesOwedReloadsAndDischargesThem6800 binds the loop BODY for
// both services at once, with the paired no-op cell below.
//
// This is the half that matters most on a real box: a boot-time apply whose
// restart failed has NO further apply coming. Nothing else on the daemon
// re-drives either reload, so without this loop the recovery window is "until
// the operator next edits syslog or NTP" — potentially never.
func TestReassertRedrivesOwedReloadsAndDischargesThem6800(t *testing.T) {
	d, restarts, setFail := syslogDaemon6800(t)
	chronyD, calls, setOutcome := chronyDaemon6800(t)
	_ = chronyD // the chrony seams are package-level; drive them through d
	d.applySem = semaphore.NewWeighted(1)

	// Latch both debts through the apply path, so the fixture owes exactly what
	// a failed apply would owe.
	setFail(errors.New("simulated restart failure"))
	d.applySyslogFiles(syslogFileCfg6800("audit"))
	setOutcome(chronyReloadOutcome{sourcesFailed: true})
	d.applySystemNTP(ntpCfg6800([]string{"10.0.0.1"}, 0))
	if !d.serviceReloadDebtOutstanding() {
		t.Fatal("setup: both debts must be outstanding before the re-assert")
	}
	restartsAfterApply, callsAfterApply := restarts(), len(calls())

	setFail(nil)
	setOutcome(chronyReloadOutcome{})
	d.reassertServiceReloadDebtOnce(context.Background())

	if restarts() != restartsAfterApply+1 {
		t.Fatalf("the re-assert issued %d rsyslog restarts, want 1 — a boot-time "+
			"apply whose restart failed has no further apply coming, so this loop "+
			"is the only retry owner (#6800)", restarts()-restartsAfterApply)
	}
	if len(calls()) != callsAfterApply+1 {
		t.Fatalf("the re-assert issued %d chrony reloads, want 1", len(calls())-callsAfterApply)
	}
	if got := (calls())[len(calls())-1]; got != [2]bool{true, false} {
		t.Fatalf("the re-assert requested %v, want [sources=true threshold=false]: "+
			"it must REPLAY the exact owed leg, not re-derive a request. Reloading "+
			"the threshold too would gratuitously `systemctl restart chrony` for a "+
			"leg that never failed (#6800)", got)
	}
	if d.serviceReloadDebtOutstanding() {
		t.Fatal("a successful re-assert must discharge the debt, or the loop " +
			"re-drives forever")
	}
}

// TestReassertIsANoOpWhenNothingIsOwed6800 is the PAIRED negative for the
// loop: with no debt it must not touch either service. An always-on loop that
// reloaded unconditionally would bounce rsyslog and chrony every 30s on a
// perfectly healthy firewall.
func TestReassertIsANoOpWhenNothingIsOwed6800(t *testing.T) {
	d, restarts, _ := syslogDaemon6800(t)
	_, calls, _ := chronyDaemon6800(t)
	d.applySem = semaphore.NewWeighted(1)

	if d.serviceReloadDebtOutstanding() {
		t.Fatal("setup: a fresh daemon must owe nothing")
	}
	d.reassertServiceReloadDebtOnce(context.Background())

	if restarts() != 0 || len(calls()) != 0 {
		t.Fatalf("a debt-free re-assert touched the services (%d rsyslog restarts, "+
			"%d chrony reloads, want 0/0) — a 30s unconditional bounce of the "+
			"logging and time-sync pipelines would be worse than the bug (#6800)",
			restarts(), len(calls()))
	}
}

// TestReassertRechecksTheDebtInsideTheSemaphore6800 binds the INNER gate: the
// per-service debt read taken UNDER applySem, after the tick has queued.
//
// The check before applySem is only an optimisation — it avoids queueing behind
// a commit for nothing — and its answer is STALE by the time the tick is let
// through. A tick that blocked behind an in-flight commit may find the commit
// already re-issued the reload and discharged the debt; reloading again then is
// a gratuitous bounce of a healthy service.
//
// The construction is deliberately NOT "start a goroutine, discharge, release".
// That version depends on the tick reaching its outer gate before the main
// goroutine discharges — a reading of the scheduler, not of the subject
// (docs/engineering-style.md #7563). Here the ordering is enforced by the
// fixture: BOTH debts are outstanding, the re-assert drives rsyslog FIRST, and
// the rsyslog spy blocks. When it fires, the tick is provably inside the
// semaphore and past its own outer gate. The "commit" then discharges the
// CHRONY debt and lets the tick continue. If the chrony leg trusted the outer
// snapshot instead of re-reading under the semaphore, it would reload a chrony
// whose debt was already paid.
func TestReassertRechecksTheDebtInsideTheSemaphore6800(t *testing.T) {
	d, _, setFail := syslogDaemon6800(t)
	_, calls, setOutcome := chronyDaemon6800(t)
	d.applySem = semaphore.NewWeighted(1)

	// Latch BOTH debts through the apply path.
	setFail(errors.New("simulated restart failure"))
	d.applySyslogFiles(syslogFileCfg6800("audit"))
	setOutcome(chronyReloadOutcome{sourcesFailed: true})
	d.applySystemNTP(ntpCfg6800([]string{"10.0.0.1"}, 0))
	if !d.rsyslogRestartOwed() {
		t.Fatal("setup: the rsyslog debt must be outstanding")
	}
	if s, th := d.chronyReloadOwed(); !s || th {
		t.Fatalf("setup: want chrony debt (sources=true, threshold=false), got (%v, %v)", s, th)
	}
	callsBefore := len(calls())

	// The rsyslog spy is the synchronisation point: it runs INSIDE the
	// semaphore, so a commit simulated from it is a commit that lands while the
	// tick is queued on its remaining work.
	setFail(nil)
	syslogSpyHook6800(func() {
		d.noteChronyReloadResult(chronyReloadOutcome{}) // a commit paid the chrony debt
	})
	t.Cleanup(func() { syslogSpyHook6800(nil) })

	d.reassertServiceReloadDebtOnce(context.Background())

	if got := len(calls()) - callsBefore; got != 0 {
		t.Fatalf("the re-assert reloaded chrony %d times after a commit had "+
			"already discharged that debt, want 0 — the outer gate's answer is "+
			"stale once the tick queues, so each service must RE-READ its debt "+
			"inside the semaphore or a healthy chrony gets a gratuitous "+
			"`systemctl restart chrony` (#6800)", got)
	}
}

// TestReassertWaitsForTheApplySemaphore6800 binds the applySem ACQUISITION,
// which the inner-gate cell above cannot: that one still passes if the
// semaphore is never taken and the tick simply runs earlier.
//
// The semaphore is held by a "commit" that never releases, and the tick is
// given a short-lived context. Correct code blocks in Acquire until the context
// expires and then declines to reload at all. Dropping the Acquire makes the
// tick fire a `systemctl restart rsyslog` straight into the middle of a commit
// — reconcileSyslogDropins is mid-way through removing and rewriting
// /etc/rsyslog.d/10-xpf-*, so the restart would load a HALF-CONVERGED drop-in
// set and then latch a success for it (#4001, #6800).
func TestReassertWaitsForTheApplySemaphore6800(t *testing.T) {
	d, restarts, setFail := syslogDaemon6800(t)
	d.applySem = semaphore.NewWeighted(1)

	setFail(errors.New("simulated restart failure"))
	d.applySyslogFiles(syslogFileCfg6800("audit"))
	if !d.rsyslogRestartOwed() {
		t.Fatal("setup: the restart debt must be outstanding")
	}
	before := restarts()

	// A commit takes the semaphore and does not give it back.
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("Acquire: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	d.reassertServiceReloadDebtOnce(ctx)

	if restarts() != before {
		t.Fatalf("the re-assert restarted rsyslog %d times while a commit held "+
			"applySem, want 0 — it must queue behind the in-flight apply, or the "+
			"restart can load a half-converged drop-in set and latch a success "+
			"for it (#4001, #6800)", restarts()-before)
	}
	if !d.rsyslogRestartOwed() {
		t.Fatal("a re-assert that never ran must leave the debt outstanding")
	}
}

// TestReassertDrivesOnlyTheServiceThatOwesAReload6800 is the PAIRED
// per-service cell: one service owes, the other does not, in both directions.
//
// The outer gate answers "does ANYTHING owe a reload", so it cannot tell the
// two apart. Without a gate per service, an owed rsyslog restart would drag a
// perfectly healthy chrony into a `systemctl restart chrony` (and vice versa) —
// a reload issued for a leg that never failed, which is the same gratuitous
// bounce the steady-state gate exists to prevent, just reached from the loop.
func TestReassertDrivesOnlyTheServiceThatOwesAReload6800(t *testing.T) {
	t.Run("rsyslog-owed-chrony-quiet", func(t *testing.T) {
		d, restarts, setFail := syslogDaemon6800(t)
		_, calls, _ := chronyDaemon6800(t)
		d.applySem = semaphore.NewWeighted(1)

		setFail(errors.New("simulated restart failure"))
		d.applySyslogFiles(syslogFileCfg6800("audit"))
		before := restarts()
		setFail(nil)

		d.reassertServiceReloadDebtOnce(context.Background())

		if restarts() != before+1 {
			t.Fatalf("the owed rsyslog restart was not re-driven (%d, want 1)",
				restarts()-before)
		}
		if len(calls()) != 0 {
			t.Fatalf("the re-assert reloaded chrony %d times while only rsyslog "+
				"owed one, want 0 — each service must gate on its OWN debt, or an "+
				"rsyslog failure drags a healthy chrony through `systemctl restart "+
				"chrony` every 30s (#6800)", len(calls()))
		}
	})

	t.Run("chrony-owed-rsyslog-quiet", func(t *testing.T) {
		d, restarts, _ := syslogDaemon6800(t)
		_, calls, setOutcome := chronyDaemon6800(t)
		d.applySem = semaphore.NewWeighted(1)

		setOutcome(chronyReloadOutcome{thresholdFailed: true})
		d.applySystemNTP(ntpCfg6800([]string{"10.0.0.1"}, 120))
		before := len(calls())
		setOutcome(chronyReloadOutcome{})

		d.reassertServiceReloadDebtOnce(context.Background())

		if len(calls()) != before+1 {
			t.Fatalf("the owed chrony reload was not re-driven (%d, want 1)",
				len(calls())-before)
		}
		if restarts() != 0 {
			t.Fatalf("the re-assert restarted rsyslog %d times while only chrony "+
				"owed a reload, want 0 — each service must gate on its OWN debt, or "+
				"a chrony failure bounces a healthy logging pipeline every 30s "+
				"(#6800)", restarts())
		}
	})
}

// TestServiceReloadDebtLoopTicks6800 binds the loop plumbing: the ticker
// actually drives the re-assert, and the loop stops on context cancellation.
//
// Separate from the source check below because they fail for different
// reasons: this reds if the loop is wired to the wrong function or never
// ticks; the source check reds if Run never starts it.
func TestServiceReloadDebtLoopTicks6800(t *testing.T) {
	d, restarts, setFail := syslogDaemon6800(t)
	d.applySem = semaphore.NewWeighted(1)

	orig := serviceReloadDebtReassertInterval
	serviceReloadDebtReassertInterval = 5 * time.Millisecond
	t.Cleanup(func() { serviceReloadDebtReassertInterval = orig })

	setFail(errors.New("simulated restart failure"))
	d.applySyslogFiles(syslogFileCfg6800("audit"))
	before := restarts()

	ctx, cancel := context.WithCancel(context.Background())
	loopDone := make(chan struct{})
	go func() { d.serviceReloadDebtReassertLoop(ctx); close(loopDone) }()

	deadline := time.Now().Add(5 * time.Second)
	for restarts() <= before {
		if time.Now().After(deadline) {
			cancel()
			<-loopDone
			t.Fatal("the re-assert loop never re-drove the owed rsyslog restart — " +
				"nothing else on the daemon retries it (#6800)")
		}
		time.Sleep(2 * time.Millisecond)
	}

	cancel()
	select {
	case <-loopDone:
	case <-time.After(5 * time.Second):
		t.Fatal("serviceReloadDebtReassertLoop did not return on context cancellation")
	}
}

// TestManagedServiceReloadAccessorsTrackTheDebt6800 binds the two EXPORTED
// accessors to the debt they report on, per service.
//
// They are the operator-visible half of the fix. Without them the retry owner
// is invisible: a node can re-drive a failing `systemctl restart rsyslog` for
// hours while every dashboard shows a firewall that committed cleanly.
//
// The failure COUNTER is asserted separately from the pending flag because they
// answer different questions — a gauge stuck at 1 says "not converged", a count
// that climbs alongside it says the retry owner is running and still failing —
// and a counter wired to the flag would collapse the two.
func TestManagedServiceReloadAccessorsTrackTheDebt6800(t *testing.T) {
	d, _, setFail := syslogDaemon6800(t)
	_, _, setOutcome := chronyDaemon6800(t)

	if owed := d.ManagedServiceReloadOwed(); owed[svcReloadRsyslog] ||
		owed[svcReloadChronySources] || owed[svcReloadChronyThreshold] {
		t.Fatalf("a fresh daemon must owe nothing, got %v", owed)
	}

	// rsyslog fails, chrony SOURCES fails, chrony THRESHOLD succeeds. All three
	// legs are exercised in one pass, and the succeeding one is what keeps this
	// from passing against an accessor that reports everything owed.
	setFail(errors.New("simulated restart failure"))
	d.applySyslogFiles(syslogFileCfg6800("audit"))
	setOutcome(chronyReloadOutcome{sourcesFailed: true})
	d.applySystemNTP(ntpCfg6800([]string{"10.0.0.1"}, 120))

	owed := d.ManagedServiceReloadOwed()
	if !owed[svcReloadRsyslog] || !owed[svcReloadChronySources] {
		t.Errorf("owed = %v; the two failed reloads must be reported", owed)
	}
	if owed[svcReloadChronyThreshold] {
		t.Errorf("owed = %v; the threshold leg SUCCEEDED, so reporting it owed "+
			"would page an operator for a reload that already landed", owed)
	}

	fails := d.ManagedServiceReloadFailures()
	if fails[svcReloadRsyslog] != 1 {
		t.Errorf("rsyslog failures = %d, want 1", fails[svcReloadRsyslog])
	}
	if fails[svcReloadChronySources] != 1 {
		t.Errorf("chrony-sources failures = %d, want 1", fails[svcReloadChronySources])
	}
	if fails[svcReloadChronyThreshold] != 0 {
		t.Errorf("chrony-threshold failures = %d, want 0 — that leg never failed, "+
			"and a counter that moves for a successful reload is noise an "+
			"operator will learn to ignore", fails[svcReloadChronyThreshold])
	}

	// A retry that fails again must CLIMB the counters while the flags stay 1 —
	// that pairing is the whole point of publishing both series.
	d.applySem = semaphore.NewWeighted(1)
	d.reassertServiceReloadDebtOnce(context.Background())
	fails = d.ManagedServiceReloadFailures()
	if fails[svcReloadRsyslog] != 2 || fails[svcReloadChronySources] != 2 {
		t.Errorf("failures after a second failed attempt = %v, want 2 apiece — "+
			"a flat counter beside a pending gauge of 1 cannot distinguish a "+
			"retry owner that is running-but-not-converging from one that is "+
			"wedged", fails)
	}
	if o := d.ManagedServiceReloadOwed(); !o[svcReloadRsyslog] || !o[svcReloadChronySources] {
		t.Errorf("owed = %v; the retry failed, so both debts stay outstanding", o)
	}

	// A success DISCHARGES the flags but must NOT rewind the counters: the
	// failures really happened, and a counter that resets on recovery hides
	// exactly the flapping it exists to show.
	setFail(nil)
	setOutcome(chronyReloadOutcome{})
	d.reassertServiceReloadDebtOnce(context.Background())
	if o := d.ManagedServiceReloadOwed(); o[svcReloadRsyslog] || o[svcReloadChronySources] {
		t.Errorf("owed = %v after a successful retry, want everything discharged", o)
	}
	if f := d.ManagedServiceReloadFailures(); f[svcReloadRsyslog] < 2 ||
		f[svcReloadChronySources] < 2 {
		t.Errorf("failures = %v after recovery, want the monotonic counts "+
			"preserved (>=2) — a counter that rewinds on success hides the "+
			"flapping it exists to show", f)
	}
}

// TestManagedServiceReloadFailureCountsAreIndependentPerLeg6800 is the MIRROR
// of the cell above, and it exists because that one could not see this.
//
// There the chrony THRESHOLD leg succeeds — deliberately, to bind "a leg that
// worked is not reported owed and does not move its counter". The cost is that
// the threshold counter is never exercised at its failing point, so deleting
// its increment changes nothing and the mutation survives. That is a fixture
// varying the right axis and sampling only the passing point.
//
// This one inverts every leg: rsyslog and chrony-sources succeed, chrony
// THRESHOLD fails. Between the two, each of the three counters is observed at
// both a failing and a succeeding point.
func TestManagedServiceReloadFailureCountsAreIndependentPerLeg6800(t *testing.T) {
	d, _, setFail := syslogDaemon6800(t)
	_, _, setOutcome := chronyDaemon6800(t)

	setFail(nil) // rsyslog restart SUCCEEDS
	d.applySyslogFiles(syslogFileCfg6800("audit"))
	setOutcome(chronyReloadOutcome{thresholdFailed: true}) // only threshold fails
	d.applySystemNTP(ntpCfg6800([]string{"10.0.0.1"}, 120))

	owed := d.ManagedServiceReloadOwed()
	if !owed[svcReloadChronyThreshold] {
		t.Errorf("owed = %v; the failed threshold reload must be reported — "+
			"chrony is still running the previous logchange/maxchange", owed)
	}
	if owed[svcReloadRsyslog] || owed[svcReloadChronySources] {
		t.Errorf("owed = %v; only the threshold leg failed", owed)
	}

	fails := d.ManagedServiceReloadFailures()
	if fails[svcReloadChronyThreshold] != 1 {
		t.Errorf("chrony-threshold failures = %d, want 1 — each leg keeps its "+
			"OWN count, or an operator cannot tell which reload is the one that "+
			"keeps failing", fails[svcReloadChronyThreshold])
	}
	if fails[svcReloadRsyslog] != 0 || fails[svcReloadChronySources] != 0 {
		t.Errorf("failures = %v; neither the rsyslog restart nor the sources "+
			"reload failed, and a counter that moves for a successful reload is "+
			"noise an operator will learn to ignore", fails)
	}

	// And it climbs on a failing retry, independently of the quiet legs.
	d.applySem = semaphore.NewWeighted(1)
	d.reassertServiceReloadDebtOnce(context.Background())
	fails = d.ManagedServiceReloadFailures()
	if fails[svcReloadChronyThreshold] != 2 {
		t.Errorf("chrony-threshold failures = %d after a second failed attempt, "+
			"want 2", fails[svcReloadChronyThreshold])
	}
	if fails[svcReloadRsyslog] != 0 || fails[svcReloadChronySources] != 0 {
		t.Errorf("failures = %v; the re-assert must not touch a leg that owes "+
			"nothing", fails)
	}
}

// TestDaemonWiresManagedServiceReloadMetrics6800 binds the WIRING of those
// accessors into the REST/metrics server.
//
// An exported accessor that nothing calls satisfies nothing: it is the #6852
// shape, and the accessor cell above would stay green with the operator still
// blind. startHTTPServer builds the api.Config inline and launches a goroutine,
// so it cannot be driven from a unit test; the assignment is asserted at the
// source with comments stripped, the same instrument the loop-start cell uses.
//
// FAIL-ON-REVERT: drop either assignment from daemon_run_servers.go and this
// reds, while every behavioural cell in this file stays green.
func TestDaemonWiresManagedServiceReloadMetrics6800(t *testing.T) {
	src := stripLineComments6791(readDaemonSource(t, "daemon_run_servers.go"))

	for _, want := range []string{
		"ManagedServiceReloadOwedFn:     d.ManagedServiceReloadOwed",
		"ManagedServiceReloadFailuresFn: d.ManagedServiceReloadFailures",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("daemon does not wire %q into the REST/metrics server; the "+
				"accessor has no production caller, so a managed service still "+
				"running the previous ruleset is invisible to an operator "+
				"(#6800, and the #6852 no-production-caller shape)", want)
		}
	}
}

// TestRunStartsTheServiceReloadDebtReassertLoop6800 binds the WIRING.
//
// Every cell above stays green if Run never starts the loop — which IS half the
// bug: a boot apply whose reload failed has no further apply coming, so with no
// loop the debt sits latched and nothing ever pays it. It is a source check
// because pkg/daemon has no seam that observes Run's goroutine set, and a cell
// that started Run for real would need the whole daemon bring-up.
//
// The start must also be UNCONDITIONAL. Nesting it under another feature's
// guard (the `!d.opts.NoDataplane` block, say) would skip the retry owner on
// exactly the deployments that use it — the reload debt has nothing to do with
// the dataplane.
//
// Comments are stripped before matching: the comment introducing the start
// names the function, and a gate satisfiable by its own documentation proves
// nothing.
func TestRunStartsTheServiceReloadDebtReassertLoop6800(t *testing.T) {
	src, err := os.ReadFile("daemon_run.go")
	if err != nil {
		t.Fatalf("read daemon_run.go: %v", err)
	}
	var code strings.Builder
	for _, line := range strings.Split(string(src), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			code.WriteString("\n")
			continue
		}
		code.WriteString(line)
		code.WriteString("\n")
	}
	body := code.String()

	const start = "d.serviceReloadDebtReassertLoop(ctx)"
	at := strings.Index(body, start)
	if at < 0 {
		t.Fatal("Run never starts serviceReloadDebtReassertLoop — a managed-service " +
			"reload that failed at boot has no further apply coming, so the debt " +
			"stays latched and rsyslog/chrony keep serving the previous ruleset " +
			"until an operator happens to edit syslog or NTP (#6800)")
	}
	lineStart := strings.LastIndex(body[:at], "\n") + 1
	indent := 0
	for _, r := range body[lineStart:at] {
		if r == '\t' {
			indent++
		}
	}
	if indent != 2 {
		t.Fatalf("serviceReloadDebtReassertLoop is started at indent %d, want 2 (the "+
			"goroutine body inside an unconditional wg.Add block) — a start nested "+
			"under another feature's conditional would skip the retry owner on "+
			"configs that do not use that feature", indent)
	}
}
