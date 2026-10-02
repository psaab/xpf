package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// TestMain points package-level external/stateful paths at disposable locations.
// Every commit/apply path consults reset handoff and some run SSH reconciliation;
// fixtures that do not install the SSH seam must never touch live /etc files.
// An unreadable /etc/xpf/.reset-handoff fails closed, while the PAM policy also
// needs an isolated marker and common-auth stack. The hostname seams are stubbed
// for the same reason: tests drive the real apply pipeline with fixture
// host-names (e.g. "rollback-target", "mtu-test"), and under a root `go test`
// the real sethostname + /etc/hostname write RENAMED the test host. sethostname
// fails with EPERM so root runs observe exactly the unprivileged behavior every
// cell was written against; hostnamePath points at the temp dir so even a test
// that overrides sethostname to succeed cannot reach live /etc/hostname.
// Per-test overrides save/restore these values. Committing tests in this package
// do not run in parallel, so the shared paths cannot race.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "daemon-reset-handoff")
	if err != nil {
		fmt.Fprintf(os.Stderr, "reset handoff test seam: %v\n", err)
		os.Exit(1)
	}
	configstore.ResetHandoffPath = filepath.Join(dir, ".reset-handoff")
	resetPersistentNatGenerationStatePath = func() string {
		return filepath.Join(dir, "persistent-nat-lease-generation.json")
	}
	applianceMarkerFile = filepath.Join(dir, "appliance")
	sshdPAMCommonAuthPath = filepath.Join(dir, "common-auth")
	if err := os.WriteFile(sshdPAMCommonAuthPath, stockCommonAuth11492(), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "daemon test PAM seam: %v\n", err)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	sshdPAMModuleAvailable = func() bool { return true }
	sethostname = func([]byte) error { return os.ErrPermission }
	hostnamePath = filepath.Join(dir, "hostname")
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
