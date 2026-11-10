package testguard

import (
	"errors"
	"testing"
	"time"
)

// TestJudgeChild19066 pins how a parent judges its re-executed child. It
// started as the 12088 carrier-loss verdict (R16 F1 on #19058, N1 on its
// 3eb2111624 fold, Codex F1/F2 on 5c84aeba3d) and became the shared one when #19066 R2 F1 found the same
// exit-status-only judgment in the other re-exec parents. Go exits 0 both for
// a test that SKIPs and for a -test.run that matches nothing, so either read
// as a PASS. The rows are real -test.v shapes; each non-PASS row is one an
// exit-status judgment scored as a pass or a skip.
func TestJudgeChild19066(t *testing.T) {
	const name = "TestProbePinCarrierLossTriggersIPMonFailover12088"
	exit1 := errors.New("exit status 1")
	const run = "=== RUN   " + name + "\n"
	for _, tc := range []struct {
		name string
		out  string
		err  error
		want ChildVerdict
	}{
		{"child passed", run + "--- PASS: " + name + " (9.20s)\nPASS\n", nil, ChildPassed},
		{"child skipped exits 0", run + "    daemon_rpm_test.go:1241: carrier-loss acceptance skipped: cannot create veth pair: operation not permitted\n" +
			"--- SKIP: " + name + " (0.01s)\nPASS\n", nil, ChildSkipped},
		{"skip then panic", run + "--- SKIP: " + name + " (0.01s)\npanic: boom [recovered]\n", errors.New("exit status 2"), ChildFailed},
		{"skip then nonzero exit", run + "--- SKIP: " + name + " (0.01s)\nPASS\ntestguard: TestMain failed after the run\n", exit1, ChildFailed},
		{"no tests to run exits 0", "testing: warning: no tests to run\nPASS\n", nil, ChildFailed},
		{"pass line for another name", "=== RUN   " + name + "X\n--- PASS: " + name + "X (0.01s)\nPASS\n", nil, ChildFailed},
		{"pass line but nonzero exit", run + "--- PASS: " + name + " (9.20s)\nFAIL\n", exit1, ChildFailed},
		{"child failed", run + "    daemon_rpm_test.go:1317: carrier-down pin failed shape verification\n--- FAIL: " + name + " (9.20s)\nFAIL\n", exit1, ChildFailed},
		// A tool inside a child that DID start prints the same "Operation not
		// permitted" an unshare refusal does; that is the acceptance failing.
		{"EPERM inside a child that started", run + "    daemon_rpm_test.go:1250: ip link set xpf12088ca up: exit status 2: RTNETLINK answers: Operation not permitted\n--- FAIL: " + name + " (0.01s)\nFAIL\n", exit1, ChildFailed},
		{"unshare refused before the child started", "unshare: unshare failed: Operation not permitted\n", exit1, ChildSkipped},
		{"guard refused the child", "testguard: refusing to run: readlink /proc/1/ns/net: permission denied\n", exit1, ChildFailed},
		{"killed at its deadline", run + "signal: killed\n", errors.New("signal: killed"), ChildFailed},
		{"empty output exits 0", "", nil, ChildFailed},
		// #19058 Codex F1: a result record outranks the pre-start refusal
		// exception, and CRLF output still reads as started.
		{"CRLF EPERM inside a child that started", "=== RUN   " + name + "\r\n    daemon_rpm_test.go:1250: ip link set xpf12088ca up: exit status 2: RTNETLINK answers: Operation not permitted\r\n--- FAIL: " + name + " (0.01s)\r\nFAIL\r\n", exit1, ChildFailed},
		{"CRLF started, refusal text, no record", "=== RUN   " + name + "\r\n    daemon_rpm_test.go:1250: unshare: nested call failed\r\nFAIL\r\n", exit1, ChildFailed},
		{"no RUN, exact FAIL plus refusal text", "unshare: unshare failed: Operation not permitted\n--- FAIL: " + name + " (0.01s)\nFAIL\n", exit1, ChildFailed},
		{"no RUN, SKIP then crash plus refusal text", "unshare: unshare failed: Operation not permitted\n--- SKIP: " + name + " (0.01s)\npanic: boom\n", errors.New("exit status 2"), ChildFailed},
		{"no RUN, exact PASS plus refusal text, nonzero exit", "Operation not permitted\n--- PASS: " + name + " (0.01s)\n", exit1, ChildFailed},
		// #19058 Codex F2: one witness row per parser rule.
		{"mid-line exact PASS exits 0", run + "noise--- PASS: " + name + " (0.01s)\nPASS\n", nil, ChildFailed},
		{"exact FAIL plus exact PASS exits 0", run + "--- FAIL: " + name + " (0.01s)\n--- PASS: " + name + " (0.01s)\n", nil, ChildFailed},
		{"refusal text exits 0 without RUN", "unshare: unshare failed: Operation not permitted\n", nil, ChildFailed},
		{"started, unshare text, no record", run + "    daemon_rpm_test.go:1250: unshare: nested call failed\nFAIL\n", exit1, ChildFailed},
		{"refusal token Operation not permitted alone", "unshare failed: Operation not permitted\n", exit1, ChildSkipped},
		{"refusal token unshare: alone", "unshare: write failed /proc/self/uid_map\n", exit1, ChildSkipped},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := JudgeChild(name, []byte(tc.out), tc.err)
			if got != tc.want {
				t.Fatalf("verdict = %d (%s), want %d, for child output:\n%s", got, reason, tc.want, tc.out)
			}
			if got != ChildPassed && reason == "" {
				t.Fatalf("a non-PASS verdict must carry a reason")
			}
		})
	}
	// The skip reason is the child's own message, not a generic one.
	_, reason := JudgeChild(name, []byte(run+"    daemon_rpm_test.go:1241: carrier-loss acceptance skipped: cannot create veth pair: operation not permitted\n--- SKIP: "+name+" (0.01s)\n"), nil)
	if want := "the child skipped: carrier-loss acceptance skipped: cannot create veth pair: operation not permitted"; reason != want {
		t.Fatalf("skip reason = %q, want %q", reason, want)
	}
}

// TestRequireChildPassActsOnTheVerdict19066: a PASS returns, a SKIP goes
// through NetnsUnavailable (FAIL under RequireNetnsEnv), anything else FAILS.
func TestRequireChildPassActsOnTheVerdict19066(t *testing.T) {
	const name = "TestX"
	pass := []byte("=== RUN   TestX\n--- PASS: TestX (0.01s)\nPASS\n")
	skip := []byte("=== RUN   TestX\n    x_test.go:1: no veth\n--- SKIP: TestX (0.01s)\nPASS\n")
	none := []byte("testing: warning: no tests to run\nPASS\n")

	t.Setenv(RequireNetnsEnv, "")
	r := &recTB{}
	RequireChildPass(r, name, pass, nil)
	if r.fatal != "" || r.skip != "" {
		t.Fatalf("PASS child: fatal=%q skip=%q, want neither", r.fatal, r.skip)
	}
	r = &recTB{}
	RequireChildPass(r, name, skip, nil)
	if r.skip == "" || r.fatal != "" {
		t.Fatalf("SKIP child without %s: fatal=%q skip=%q, want a SKIP", RequireNetnsEnv, r.fatal, r.skip)
	}
	r = &recTB{}
	RequireChildPass(r, name, none, nil)
	if r.fatal == "" {
		t.Fatalf("no-tests child: fatal=%q skip=%q, want a FAIL", r.fatal, r.skip)
	}
	t.Setenv(RequireNetnsEnv, "1")
	r = &recTB{}
	RequireChildPass(r, name, skip, nil)
	// recTB's Fatalf returns instead of ending the test, so only the FAIL is
	// asserted here.
	if r.fatal == "" {
		t.Fatalf("SKIP child under %s: fatal=%q, want a FAIL", RequireNetnsEnv, r.fatal)
	}
}

type deadlineTB19066 struct {
	*testing.T
	d time.Time
}

func (d deadlineTB19066) Deadline() (time.Time, bool) { return d.d, true }

// TestReexecCommandHasItsOwnDeadline19066 (R18 N1): the child is killed
// reexecMargin before the parent's own deadline, so a hung child fails its
// cell instead of hanging until the package -timeout.
func TestReexecCommandHasItsOwnDeadline19066(t *testing.T) {
	tb := deadlineTB19066{T: t, d: time.Now().Add(reexecMargin + time.Second)}
	cmd := ReexecCommand(tb, "sleep", "30")
	start := time.Now()
	err := cmd.Run()
	if err == nil {
		t.Fatal("a child running past its deadline exited cleanly")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("the child ran %v; it should have been killed about 1 s in", elapsed)
	}
}
