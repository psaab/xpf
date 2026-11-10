package nfqueue

import (
	"os"
	"testing"

	"github.com/psaab/xpf/internal/testguard"
)

// TestMain runs the package's tests under the #19088 thread-namespace guard:
// after the tests, no OS thread may be left outside the package's network
// namespace. This package runs its kernel cells in a re-executed child under
// `unshare -Urn` (requireNetNS), so the guard covers that child's process as
// well as the parent's. It does not add #18038's ExitIfUnsafe: these tests do
// not mutate the namespace they start in.
func TestMain(m *testing.M) {
	os.Exit(testguard.Run(m))
}
