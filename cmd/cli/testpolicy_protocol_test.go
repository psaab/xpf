package main

import (
	"strings"
	"testing"
)

// TestTestPolicyRejectsInvalidProtocol covers the #3108 gap on the remote `cli`
// client's `test policy` command (cmd/cli). A non-empty but unknown/out-of-range
// protocol token must return a clear command error and NEVER be forwarded to the
// backend: constrained terms would never match it, but an `application any`
// term may still match and return a misleading verdict.
//
// Only the rejection path is unit-testable here: a VALID/ABSENT protocol
// proceeds to c.showText, which dials the gRPC client (an integration path). The
// rejection returns before any client call, so an empty *ctl is sufficient.
//
// FAIL-ON-REVERT: removing the policymatch.ValidateProtocol guard makes
// "notaproto"/"999" build a topic and dial the backend with no error, flipping
// these want-error cases red.
func TestTestPolicyRejectsInvalidProtocol(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"unknown name", []string{"from-zone", "trust", "to-zone", "untrust", "protocol", "notaproto"}},
		{"typo", []string{"from-zone", "trust", "to-zone", "untrust", "protocol", "tcpp"}},
		{"out of range", []string{"from-zone", "trust", "to-zone", "untrust", "protocol", "999"}},
	}
	c := &ctl{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := c.testPolicy(tc.args)
			if err == nil {
				t.Fatalf("testPolicy(%v) err = nil, want an invalid-protocol error", tc.args)
			}
			if !strings.Contains(err.Error(), "protocol") {
				t.Fatalf("testPolicy(%v) err = %v, want a protocol diagnostic", tc.args, err)
			}
		})
	}
}
