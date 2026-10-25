package docsref

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #16493: userspace-dp/src/session/README.md (the session module contract)
// still documented #9412 as OPEN — close state "does NOT cross" the HA
// session-sync wire, imported sessions ageing on a 300 s ESTABLISHED window,
// and a deliberately TWO-SIDED guard cell that "FAILS when #9412 is fixed".
// #9412 closed 2026-09-10: close state rides SessionSyncRequest.tcp_close_class
// (see the "TCP close class on the session-sync wire (#9412)" section in the
// same README and close_state_sync_9412_acceptance_tests.rs), the TCP
// established default is 1800 s (#15127), and the Timeouts table carries the
// OSPF 60 s / Other-protocols 1800 s rows from #16486. This gate pins the
// contract so the stale claims cannot silently return.
//
// FAIL-ON-REVERT: restore any stale string below (e.g. "#9412, OPEN" or
// "(300 s)") in the session README and this test fails.
func TestSessionReadme9412Contract16493(t *testing.T) {
	root := repoRoot(t)
	b, err := os.ReadFile(filepath.Join(root, "userspace-dp/src/session/README.md"))
	if err != nil {
		t.Fatalf("read session README: %v", err)
	}
	s := string(b)

	stale := []string{
		"#9412, OPEN",
		"Close state does NOT cross",
		"ESTABLISHED window (300 s)",
		"holds a table slot for up to 300 s",
		"TWO-SIDED: it FAILS when #9412 is fixed",
		"300 s established timeout",
		"300 s established entry",
		"300 s by default) instead of its close window",
	}
	for _, bad := range stale {
		if strings.Contains(s, bad) {
			t.Errorf("#16493: session README still contains stale claim %q", bad)
		}
	}
	// The established default has been 1800 s since #15127, so the
	// present-tense descriptions of the current windows must not pair
	// 300 s with "established". Historical narratives of pre-#15127
	// behaviour ("kept the 300 s established timeout" for #4109 F17,
	// "back to the 300 s established window" for #3489) describe what
	// those fixes changed at the time and are out of scope.
	for i, line := range strings.Split(s, "\n") {
		low := strings.ToLower(line)
		if (strings.Contains(line, "300 s established timeout") ||
			strings.Contains(line, "300 s established entry") ||
			strings.Contains(line, "300 s by default")) &&
			strings.Contains(low, "established") {
			t.Errorf("#16493: session README:%d pairs 300 s with the established window: %q", i+1, line)
		}
	}

	required := []string{
		"`SessionSyncRequest.tcp_close_class`",
		"close_state_sync_9412_acceptance_tests.rs",
		"| TCP established | 1800 s (#15127",
		"| OSPF  | 60 s (#16486",
		"| Other IP protocols (GRE/ESP/AH/SCTP/6in4/…) | 1800 s (#16486",
	}
	for _, want := range required {
		if !strings.Contains(s, want) {
			t.Errorf("#16493: session README lost required contract text %q", want)
		}
	}
}
