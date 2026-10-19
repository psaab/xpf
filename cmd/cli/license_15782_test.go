package main

import (
	"strings"
	"testing"
)

// #15782: remote `request system license ...` fails closed, no RPC.
func TestRemoteRequestSystemLicenseFailClosed15782(t *testing.T) {
	c := &ctl{}
	err := c.handleRequest([]string{"system", "license", "update"})
	if err == nil || !strings.Contains(err.Error(), "not implemented") {
		t.Fatalf("handleRequest license = %v, want not implemented", err)
	}
}
