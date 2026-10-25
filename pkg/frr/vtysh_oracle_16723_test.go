package frr

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// #16723: bgpd -C cannot run unprivileged in every environment — FRR's
// privs_init calls setgroups, which the sandbox refuses
// ("privs_init: could not setgroups, Operation not permitted") before
// any config line is read, so a bgpd-based oracle reds on environment,
// not on the rendered grammar. The family already has a working
// unprivileged oracle (validateRenderedRouting11417 over vtysh -C,
// used by the 12185/11417 cells). This helper gives the former bgpd
// cells the same treatment: resolve vtysh, validate, and skip only
// when vtysh is genuinely absent.
func bgpdOracleConfig16723(t *testing.T, rendered string) {
	t.Helper()
	vtysh := frrVtyshBinary12185(t)
	if output, err := validateRenderedRouting11417(t, vtysh, rendered); err != nil {
		t.Fatalf("FRR rejected the rendered config: %v\n%s\nconfig:\n%s", err, output, rendered)
	}
	// Prove the validator reads the file: an invalid keyword must be
	// rejected and named, exactly as the 12185 cells pin.
	const invalidCommand = "xpf-invalid-16723-command"
	output, err := validateRenderedRouting11417(t, vtysh, rendered+invalidCommand+"\n")
	if err == nil || !strings.Contains(string(output), invalidCommand) {
		t.Fatalf("FRR vtysh did not reject the invalid config control: %v\n%s", err, output)
	}
}

// bgpdBinary16723 is kept for cells that still shell bgpd directly in
// a root-only leg; it is not used by the unprivileged oracle above.
func bgpdBinary16723(t *testing.T) string {
	t.Helper()
	if bgpd := os.Getenv("FRR_BGPD_BINARY"); bgpd != "" {
		return bgpd
	}
	if bgpd, err := exec.LookPath("bgpd"); err == nil {
		return bgpd
	}
	for _, candidate := range []string{"/usr/lib/frr/bgpd", "/usr/libexec/frr/bgpd", filepath.Join("/", "usr", "libexec", "frr", "bgpd")} {
		if _, statErr := os.Stat(candidate); statErr == nil {
			return candidate
		}
	}
	t.Skip("FRR bgpd is not installed; FRR config-load validation unavailable")
	return ""
}
