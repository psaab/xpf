package userspace

import (
	"testing"

	"github.com/psaab/xpf/internal/testguard"
)

// TestNetnsThreadDiscipline19088 is the static half of the #19088 guard (the
// runtime half is testguard.Run in TestMain): a test file here that switches
// a thread's network namespace locks and releases it only through the
// testguard helpers, and nothing names /proc/self/ns/.
func TestNetnsThreadDiscipline19088(t *testing.T) {
	if err := testguard.CheckNetnsThreadDiscipline("."); err != nil {
		t.Fatal(err)
	}
}
