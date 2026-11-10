package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/internal/testguard"
	"github.com/psaab/xpf/pkg/api"
	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/frr"
)

// productionStateDefaults19084 records the declared production values of the
// redirected seams, so a test that pins the operator contract (where a real box
// writes, e.g. TestProductionDropInDirIsUnchanged7609) reads the declaration
// rather than the test-time redirect.
var productionStateDefaults19084 map[string]string

// redirectProductionStatePaths19084 points every production state path the
// package's in-process tests were measured to write or delete, as real root,
// at dir (#19084). Measured on a root leg of the whole package with each file
// pre-populated: the apply tail removed /etc/ssh/ssh_known_hosts,
// /etc/ssh/sshd_config.d/00-xpf.conf, /etc/chrony/sources.d/xpf.sources and
// /etc/rsyslog.d/10-xpf-*; cluster comms rewrote or removed the
// /var/lib/xpf HA epoch and grace records; the feed guard, the SNMP agent and
// a management server created feed-shrink-history.json, snmp-engine-id,
// snmp-engineboots and /etc/xpf/tls. Tests that exercise one of these
// reconcilers still save/restore the seam per test.
func redirectProductionStatePaths19084(dir string) {
	productionStateDefaults19084 = map[string]string{
		"sshdConfPath":      sshdConfPath,
		"sshKnownHostsPath": sshKnownHostsPath,
		"chronySourcesPath": chronySourcesPath,
		"rsyslogConfDir":    rsyslogConfDir,
	}
	etc := filepath.Join(dir, "etc")
	chronySourcesPath = filepath.Join(etc, "chrony/sources.d/xpf.sources")
	chronyThresholdPath = filepath.Join(etc, "chrony/conf.d/xpf-threshold.conf")
	chronyAcquisitionPath = filepath.Join(etc, "chrony/conf.d/xpf-acquisition.conf")
	sshKnownHostsPath = filepath.Join(etc, "ssh/ssh_known_hosts")
	sshdConfPath = filepath.Join(etc, "ssh/sshd_config.d/00-xpf.conf")
	rsyslogConfDir = filepath.Join(etc, "rsyslog.d")
	for _, d := range []string{filepath.Dir(chronySourcesPath), filepath.Dir(chronyThresholdPath),
		filepath.Dir(sshKnownHostsPath), filepath.Dir(sshdConfPath), rsyslogConfDir} {
		_ = os.MkdirAll(d, 0o755)
	}
	state := filepath.Join(dir, "var-lib-xpf")
	_ = os.MkdirAll(state, 0o755)
	_ = cluster.SetStateDirForTesting(state)
	transitOwnershipRecordFile = filepath.Join(state, "transit-gate-owned")
	configstore.TransitOwnershipRecordPath = filepath.Join(state, "transit-gate-owned")
	feedShrinkHistoryPath = filepath.Join(state, "feed-shrink-history.json")
	defaultSNMPBootsPath = filepath.Join(state, "snmp-engineboots")
	defaultSNMPEngineIDPath = filepath.Join(state, "snmp-engine-id")
	ipsecQuarantineIdentityPath9506 = filepath.Join(state, "ipsec-quarantine-identity")
	_ = api.SetDefaultTLSSelfSignedDirForTesting(filepath.Join(etc, "xpf/tls"))
}

// TestMain points package-level external/stateful paths at disposable locations.
// Apply fixtures drive the real tail, so its DNS writer, resolved/systemctl op,
// sudoers sweep, and ownership inventory must not touch live host paths. The
// reset handoff, PAM policy, and hostname are isolated for the same reason.
// Host-name fixtures run through the real apply pipeline, so the real
// sethostname + /etc/hostname write would rename the test host when run as root.
// Per-test overrides save/restore these values. Tests touching package-global
// apply seams do not run in parallel.
func TestMain(m *testing.M) {
	testguard.ExitIfUnsafe()
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
	redirectProductionStatePaths19084(dir)
	// #16046 fold-2: default frr-group resolution for daemon fixtures
	// that write a seeded 0644 frr.conf through a NewForTest manager —
	// the process egid as service gid (pure-preserve tightening, no
	// root/host group needed). Per-test stubs restore via the seam.
	_ = frr.SetFRRGroupResolverForTest(func() (int, bool) { return os.Getegid(), true })
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
