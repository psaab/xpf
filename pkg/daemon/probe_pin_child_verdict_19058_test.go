package daemon

import (
	"errors"
	"testing"
)

// TestCarrierLossChildVerdict12088 pins how the 12088 carrier-loss parent
// judges its re-executed child (R16 F1 on #19058, and N1 on 3eb2111624).
// Before, the parent read only the child's exit status, and Go exits 0 both
// for a test that SKIPs and for a -test.run that matches nothing, so either
// was reported as a PASS. The rows are real -test.v shapes; each non-PASS row
// is one the old judgment scored as a pass or a skip.
func TestCarrierLossChildVerdict12088(t *testing.T) {
	exit1 := errors.New("exit status 1")
	const run = "=== RUN   " + carrierLossTest12088 + "\n"
	for _, tc := range []struct {
		name string
		out  string
		err  error
		want carrierLossChildVerdict12088
	}{
		{"child passed", run + "--- PASS: " + carrierLossTest12088 + " (9.20s)\nPASS\n", nil, carrierLossChildPassed12088},
		{"child skipped exits 0", run + "    daemon_rpm_test.go:1241: carrier-loss acceptance skipped: cannot create veth pair: operation not permitted\n" +
			"--- SKIP: " + carrierLossTest12088 + " (0.01s)\nPASS\n", nil, carrierLossChildSkipped12088},
		// R16 N1 on 3eb2111624: a crash after the skip must not read as a skip.
		{"skip then panic", run + "--- SKIP: " + carrierLossTest12088 + " (0.01s)\npanic: boom [recovered]\n", errors.New("exit status 2"), carrierLossChildFailed12088},
		{"skip then nonzero exit", run + "--- SKIP: " + carrierLossTest12088 + " (0.01s)\nPASS\ntestguard: TestMain failed after the run\n", exit1, carrierLossChildFailed12088},
		{"no tests to run exits 0", "testing: warning: no tests to run\nPASS\n", nil, carrierLossChildFailed12088},
		{"pass line for another name", "=== RUN   " + carrierLossTest12088 + "X\n--- PASS: " + carrierLossTest12088 + "X (0.01s)\nPASS\n", nil, carrierLossChildFailed12088},
		{"pass line but nonzero exit", run + "--- PASS: " + carrierLossTest12088 + " (9.20s)\nFAIL\n", exit1, carrierLossChildFailed12088},
		{"child failed", run + "    daemon_rpm_test.go:1317: carrier-down pin failed shape verification\n--- FAIL: " + carrierLossTest12088 + " (9.20s)\nFAIL\n", exit1, carrierLossChildFailed12088},
		// A tool inside a child that DID start prints the same "Operation not
		// permitted" an unshare refusal does; the old judgment skipped on it.
		{"EPERM inside a child that started", run + "    daemon_rpm_test.go:1250: ip link set xpf12088ca up: exit status 2: RTNETLINK answers: Operation not permitted\n--- FAIL: " + carrierLossTest12088 + " (0.01s)\nFAIL\n", exit1, carrierLossChildFailed12088},
		{"unshare refused before the child started", "unshare: unshare failed: Operation not permitted\n", exit1, carrierLossChildSkipped12088},
		{"guard refused the child", "testguard: refusing to run: readlink /proc/1/ns/net: permission denied\n", exit1, carrierLossChildFailed12088},
		{"empty output exits 0", "", nil, carrierLossChildFailed12088},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := judgeCarrierLossChild12088([]byte(tc.out), tc.err)
			if got != tc.want {
				t.Fatalf("verdict = %d (%s), want %d, for child output:\n%s", got, reason, tc.want, tc.out)
			}
			if got != carrierLossChildPassed12088 && reason == "" {
				t.Fatalf("a non-PASS verdict must carry a reason")
			}
		})
	}
	// The skip reason is the child's own message, not a generic one.
	_, reason := judgeCarrierLossChild12088([]byte(run+"    daemon_rpm_test.go:1241: carrier-loss acceptance skipped: cannot create veth pair: operation not permitted\n--- SKIP: "+carrierLossTest12088+" (0.01s)\n"), nil)
	if want := "the child skipped: carrier-loss acceptance skipped: cannot create veth pair: operation not permitted"; reason != want {
		t.Fatalf("skip reason = %q, want %q", reason, want)
	}
}
