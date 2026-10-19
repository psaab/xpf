package daemon

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// #15084 (A54-01): SIGHUP terminated xpfd with no shutdown sequence, and
// systemd counted the death as a clean exit, so Restart=on-failure never
// restarted the firewall — an indefinite forwarding outage on a stray
// `systemctl kill -s HUP xpfd` (or HA: an ungraceful peer-loss failover
// after which the node never rejoined).
//
// The fix has three legs, and each cell below pins one leg at the exact
// mechanism. On current origin/master there is no daemonSignals and no
// ignoreSIGHUP seam and the unit carries no RestartForceExitStatus, so
// this file does not compile there — the absence of the seam IS the
// defect (no signal.Notify/Ignore of SIGHUP existed anywhere in pkg/ or
// cmd/). The RED was recorded by running these cells against master
// with only the test file present (build failure listing the two
// undefined symbols), then the full fix makes them GREEN.
//
// NOT shipped: treating SIGHUP as a shutdown. An orderly stop that
// exits 0 is still scored clean by systemd and would not be restarted
// either; the pin below (SIGHUP absent from the shutdown set) keeps
// that wrong fix out.

// TestDaemonSignalsExcludeSIGHUP15084 pins the shutdown-signal set: it
// names exactly the signals that must produce an orderly stop, proves
// SIGHUP is NOT one of them, and proves the surviving legitimate
// behaviour is unchanged (daemon mode still stops on SIGTERM+SIGINT,
// interactive mode on SIGTERM only so the CLI keeps Ctrl-C).
//
// RED on revert: adding syscall.SIGHUP to either arm of daemonSignals
// (the "orderly stop on HUP" fix shape) fails the exclusion assertion.
func hasSignal(set []os.Signal, want os.Signal) bool {
	return slices.ContainsFunc(set, func(s os.Signal) bool { return s == want })
}

func TestDaemonSignalsExcludeSIGHUP15084(t *testing.T) {
	daemonSet := daemonSignals(false)
	if hasSignal(daemonSet, syscall.SIGHUP) {
		t.Fatal("daemon-mode shutdown set contains SIGHUP: a HUP would run the shutdown " +
			"sequence and exit clean, so Restart=on-failure would still never revive the node (#15084)")
	}
	if !hasSignal(daemonSet, syscall.SIGTERM) || !hasSignal(daemonSet, syscall.SIGINT) {
		t.Errorf("daemon-mode shutdown set = %v, want SIGTERM and SIGINT preserved", daemonSet)
	}

	interactiveSet := daemonSignals(true)
	if hasSignal(interactiveSet, syscall.SIGHUP) {
		t.Fatal("interactive shutdown set contains SIGHUP (#15084)")
	}
	if hasSignal(interactiveSet, syscall.SIGINT) {
		t.Errorf("interactive shutdown set = %v, must keep SIGINT free for CLI Ctrl-C", interactiveSet)
	}
	if !hasSignal(interactiveSet, syscall.SIGTERM) {
		t.Errorf("interactive shutdown set = %v, want SIGTERM preserved", interactiveSet)
	}
}

// TestIgnoreSIGHUPSurvivesDelivery15084 delivers a REAL SIGHUP to this
// test process while the ignoreSIGHUP disposition is installed. If the
// capture is removed (or never installed), the default action kills
// the test binary mid-run — the failure cannot be mistaken for a pass.
// stop() is called exactly once at the end (a double close would
// panic), pinning that the returned func is the single release Run
// defers.
func TestIgnoreSIGHUPSurvivesDelivery15084(t *testing.T) {
	stop := ignoreSIGHUP()

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatalf("deliver SIGHUP to self: %v", err)
	}
	// A second HUP must be equally inert (burst safety: buffered chan).
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatalf("deliver second SIGHUP to self: %v", err)
	}
	// Reaching this line at all is the assertion: with the default
	// disposition the first Kill above terminated the process.
	stop()
}

// TestUnitRestartForceExitStatus15084 pins the supervisor leg: the
// shipped unit must declare SIGHUP (and SIGPIPE, the same default-clean
// death class) as failure exits so that even a hypothetical future
// SIGHUP death — a binary too old to carry ignoreSIGHUP, a HUP sent
// before Run installs it — is restarted by Restart=on-failure instead
// of scored clean and left down.
//
// It parses the shipped unit (test/incus/xpfd.service, the source
// debian/rules stages and injects ExecStartPre into) rather than
// pinning a comment, per the #8233 precedent: a directive stated in
// prose is true only until someone edits the unit.
//
// RED on revert: deleting the RestartForceExitStatus line fails here.
func TestUnitRestartForceExitStatus15084(t *testing.T) {
	unitPath := filepath.Join("..", "..", "test", "incus", "xpfd.service")
	raw, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatalf("read shipped unit %s: %v", unitPath, err)
	}
	var (
		forceValues []string
		hasRestart  bool
	)
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if line == "Restart=on-failure" {
			hasRestart = true
		}
		if v, ok := strings.CutPrefix(line, "RestartForceExitStatus="); ok {
			forceValues = append(forceValues, strings.Fields(v)...)
		}
	}
	if !hasRestart {
		t.Fatal("shipped unit lost Restart=on-failure; RestartForceExitStatus alone restarts nothing (#15084)")
	}
	// systemd accepts names or numbers; pin the names this fix ships.
	if !slices.Contains(forceValues, "SIGHUP") {
		t.Errorf("RestartForceExitStatus values = %v, want SIGHUP forced to a failure exit "+
			"so a HUP death is restarted, not scored clean (#15084)", forceValues)
	}
	if !slices.Contains(forceValues, "SIGPIPE") {
		t.Errorf("RestartForceExitStatus values = %v, want SIGPIPE alongside SIGHUP "+
			"(issue-directed pair; same default-clean death class) (#15084)", forceValues)
	}
}
