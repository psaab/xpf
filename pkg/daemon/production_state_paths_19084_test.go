package daemon

import (
	"strings"
	"testing"
)

// TestProductionStatePathsRedirectedUnderTest19084 pins TestMain's #19084
// redirects: none of the production state seams the package's in-process
// tests reach may still name a host path while the suite runs. A real-root
// leg otherwise deletes the host's xpf-managed /etc files and rewrites its
// /var/lib/xpf HA state (measured with pre-populated files on master).
func TestProductionStatePathsRedirectedUnderTest19084(t *testing.T) {
	for name, path := range map[string]string{
		"chronySourcesPath":               chronySourcesPath,
		"chronyThresholdPath":             chronyThresholdPath,
		"chronyAcquisitionPath":           chronyAcquisitionPath,
		"sshKnownHostsPath":               sshKnownHostsPath,
		"sshdConfPath":                    sshdConfPath,
		"rsyslogConfDir":                  rsyslogConfDir,
		"transitOwnershipRecordFile":      transitOwnershipRecordFile,
		"feedShrinkHistoryPath":           feedShrinkHistoryPath,
		"defaultSNMPBootsPath":            defaultSNMPBootsPath,
		"defaultSNMPEngineIDPath":         defaultSNMPEngineIDPath,
		"ipsecQuarantineIdentityPath9506": ipsecQuarantineIdentityPath9506,
	} {
		if path == "" || strings.HasPrefix(path, "/etc/") || strings.HasPrefix(path, "/var/lib/xpf") {
			t.Errorf("%s = %q under test; TestMain must point it at the package temp dir (#19084)", name, path)
		}
	}
}
