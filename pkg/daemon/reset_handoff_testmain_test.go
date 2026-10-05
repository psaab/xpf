package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// TestMain points package-level external/stateful paths at disposable locations.
// Apply fixtures drive the real tail, so its DNS writer, resolved/systemctl op,
// sudoers sweep, and ownership inventory must not touch live host paths. The
// reset handoff, PAM policy, and hostname are isolated for the same reason.
// Host-name fixtures run through the real apply pipeline, so the real
// sethostname + /etc/hostname write would rename the test host when run as root.
// Per-test overrides save/restore these values. Tests touching package-global
// apply seams do not run in parallel.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "daemon-reset-handoff")
	if err != nil {
		fmt.Fprintf(os.Stderr, "reset handoff test seam: %v\n", err)
		os.Exit(1)
	}
	sudoersDir = filepath.Join(dir, "sudoers.d")
	if err := os.MkdirAll(sudoersDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "daemon test sudoers seam: %v\n", err)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	provisionedUsersDir = filepath.Join(dir, "provisioned-users")
	dnsDir := filepath.Join(dir, "dns")
	if err := os.MkdirAll(dnsDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "daemon test DNS seam: %v\n", err)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	newDNSReconcilerFn = func() *dnsReconciler {
		return &dnsReconciler{
			resolvConfPath:       filepath.Join(dnsDir, "resolv.conf"),
			legacyResolvedDropin: filepath.Join(dnsDir, "bpfrx.conf"),
			xpfResolvedDropin:    filepath.Join(dnsDir, "xpf.conf"),
			disableMaskResolved:  func() error { return nil },
		}
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
