package main

import (
	"strings"
	"testing"
)

// #15944 H21-02: remote `show system license` printed the constant
// `License: open-source (no license required)` and returned, never
// calling the ShowText RPC already wired to the shared
// config.LicenseText — so configured autoupdate URLs / inert notice
// that the local path renders were invisible to remote operators.
//
// FAIL-ON-REVERT: restoring the hardcoded arm leaves the fake's
// recorded topics empty and prints only the constant.

func TestRemoteShowSystemLicenseUsesRPC15944(t *testing.T) {
	f := &fake13551{}
	c := &ctl{client: f}
	out := captureStdout(t, func() {
		if err := c.handleShowSystem([]string{"license"}); err != nil {
			t.Fatalf("handleShowSystem(license): %v", err)
		}
	})
	if len(f.showTextTopics) != 1 || f.showTextTopics[0] != "license" {
		t.Fatalf("ShowText topics = %v, want [license]", f.showTextTopics)
	}
	if !strings.Contains(out, "text:license") {
		t.Fatalf("output %q must be the RPC render, not the hardcoded constant", out)
	}
}
