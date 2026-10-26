package factoryreset

import (
	"os"
	"path/filepath"
	"testing"
)

// #17880: the legacy bpfrx.conf leg of wipeRenderedConfigs must be derived
// from the SUPPLIED swanctlSnippet argument, not from the package-global
// wipeSwanctlSnippet seam. Before the fix, legacySwanctlSnippetPath()
// resolved through the global, so a caller passing a throwaway-tree snippet
// (every existing temp-dir test) left the supplied tree's legacy sibling in
// place and instead removed the legacy file beside the GLOBAL path — the
// real /etc/swanctl/conf.d/bpfrx.conf under the production default.
//
// RED on revert: restore the parameterless global-derived helper and the
// supplied-tree legacy file survives while the global-tree sentinel is
// deleted; both assertions below fail.
func TestZeroizeRenderedLegacyFollowsSuppliedSnippet17880(t *testing.T) {
	dir := t.TempDir()

	// Supplied tree: the paths actually handed to wipeRenderedConfigs.
	frrConf := filepath.Join(dir, "supplied", "frr", "frr.conf")
	suppliedSwan := filepath.Join(dir, "supplied", "swanctl", "xpf.conf")
	suppliedLegacy := filepath.Join(dir, "supplied", "swanctl", "bpfrx.conf")
	kea4 := filepath.Join(dir, "supplied", "kea", "kea-dhcp4.conf")
	kea6 := filepath.Join(dir, "supplied", "kea", "kea-dhcp6.conf")
	mustWriteFile(t, frrConf, []byte("hostname r1\n"))
	mustWriteFile(t, suppliedSwan, []byte("secrets { ike-x { secret = PSK-X } }\n"))
	mustWriteFile(t, suppliedLegacy, []byte("secrets { ike-old { secret = PSK-LEGACY-17880 } }\n"))
	mustWriteFile(t, kea4, []byte("kea4"))
	mustWriteFile(t, kea6, []byte("kea6"))

	// Global seam points at a DIFFERENT tree holding a sentinel legacy
	// file. The wipe of the supplied tree must never touch it.
	globalLegacy := filepath.Join(dir, "global", "swanctl", "bpfrx.conf")
	const sentinel = "secrets { ike-global { secret = PSK-GLOBAL-17880 } }\n"
	mustWriteFile(t, globalLegacy, []byte(sentinel))
	origSwan := wipeSwanctlSnippet
	wipeSwanctlSnippet = filepath.Join(dir, "global", "swanctl", "xpf.conf")
	t.Cleanup(func() { wipeSwanctlSnippet = origSwan })

	if err := wipeRenderedConfigs(frrConf, suppliedSwan, kea4, kea6); err != nil {
		t.Fatalf("wipeRenderedConfigs: %v", err)
	}

	// The legacy sibling of the SUPPLIED snippet is erased.
	assertAbsent(t, suppliedLegacy)
	assertAbsent(t, suppliedSwan)

	// The legacy file beside the global seam path is untouched.
	got, err := os.ReadFile(globalLegacy)
	if err != nil {
		t.Fatalf("legacy file beside the global wipeSwanctlSnippet was removed by a wipe of a different supplied tree: %v", err)
	}
	if string(got) != sentinel {
		t.Fatalf("global-tree legacy file modified:\n%s", got)
	}
}
