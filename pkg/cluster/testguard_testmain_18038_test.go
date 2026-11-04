package cluster

import (
	"os"
	"testing"

	"github.com/psaab/xpf/internal/testguard"
)

// #18038: pkg/cluster gained its first census-registered host-state mutation
// (the lo-up netlink call in sync_loopback_18038_test.go), so the package
// joins the guarded set: the test binary refuses to run outside a private
// net+mount namespace, like every other package in
// host-mutation-census.py's PACKAGES.
func TestMain(m *testing.M) {
	testguard.ExitIfUnsafe()
	os.Exit(m.Run())
}
