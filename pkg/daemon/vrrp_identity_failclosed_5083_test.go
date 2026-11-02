package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15856 moved duplicate VRRP identity rejection to strict config compilation.
// Two IPv4 addresses on the same unit with the same VRID produce duplicate
// (kernel interface, VRID, family) instances without an earlier device-collision
// gate masking the identity check.
func TestDuplicateVRRPIdentityRejectedAtStrictCompile5083(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, line := range []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24 vrrp-group 5 virtual-address 10.0.0.10/24",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24 vrrp-group 5 virtual-address 10.0.1.10/24",
	} {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}

	_, err := config.CompileConfig(tree)
	if err == nil {
		t.Fatal("strict compile accepted two VRRP groups resolving to ge-0-0-0 with VRID 5")
	}
	if !strings.Contains(err.Error(), "duplicate VRRP instance identity") ||
		!strings.Contains(err.Error(), `interface="ge-0-0-0" VRID=5 family="inet"`) {
		t.Fatalf("commit-time refusal did not identify the colliding kernel instance: %v", err)
	}
}
