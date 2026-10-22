package factoryreset

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// renderedTempSecret5509 stands in for the cleartext secret a crash-leaked
// fsatomic temp of a RENDERED service config would carry — a BGP-MD5/OSPF/IS-IS
// routing-auth key in frr.conf, an IKE PSK in the swanctl snippet, or a Kea
// credential. No file holding it may survive a factory reset.
const renderedTempSecret5509 = "MARKER-SECRET-5509-rendered-crash-temp"

// TestZeroizeRenderedConfigsRemovesFsatomicTemps pins #5509: wipeRenderedConfigs
// must sweep crash-leaked fsatomic write temps (".<base>.tmp-<rand>",
// isFsatomicTemp) from EVERY directory it renders cleartext into — /etc/frr,
// /etc/swanctl/conf.d, /etc/kea — not only remove the known exact paths. Each
// rendered config is written via pkg/fsatomic (frr.WriteFileDurable,
// ipsec.WriteFileAtomic, dhcpserver.WriteFileAtomic), which leaves a
// ".<base>.tmp-<rand>" temp holding the full cleartext render if the daemon is
// hard-killed between CreateTemp and the atomic rename. A factory reset + reboot
// has no next write to self-heal it, so without this sweep the temp — and its
// secrets — survive to the next tenant.
//
// This is the rendered-config-dir sibling of #5475 (the configDir sweep),
// distinct from #5186 (the /var/lib/xpf/archive wipe).
//
// RED on revert: delete the sweepFsatomicTemps loop and every temp below
// survives the wipe — the assertAbsent checks fail.
func TestZeroizeRenderedConfigsRemovesFsatomicTemps(t *testing.T) {
	dir := t.TempDir()
	marker := []byte(renderedTempSecret5509)

	// The three rendered-config directories, each with its own subdir so the
	// sweep's per-directory scoping is exercised (kea4/kea6 deliberately share
	// /etc/kea to also exercise the directory dedup).
	frrConf := filepath.Join(dir, "frr", "frr.conf")
	swanctlSnippet := filepath.Join(dir, "swanctl", "xpf.conf")
	kea4 := filepath.Join(dir, "kea", "kea-dhcp4.conf")
	kea6 := filepath.Join(dir, "kea", "kea-dhcp6.conf")

	// The normal managed renders (so the pre-existing exact-path removal keeps
	// working alongside the new sweep). frr.conf carries an xpf managed section
	// so StripManagedSectionFile has something to strip.
	frrBody := "hostname r1\n" +
		"! BEGIN BPFRX MANAGED CONFIG - do not edit this section\n" +
		" ip ospf message-digest-key 1 md5 " + renderedTempSecret5509 + "\n" +
		"! END BPFRX MANAGED CONFIG\n"
	mustWriteFile(t, frrConf, []byte(frrBody))
	mustWriteFile(t, swanctlSnippet, marker)
	mustWriteFile(t, kea4, marker)
	mustWriteFile(t, kea6, marker)

	// Crash-leaked fsatomic temps — one per rendered base — each holding the
	// full cleartext render. These are what the exact-path removal MISSES.
	temps := []string{
		filepath.Join(dir, "frr", ".frr.conf.tmp-abc123"),
		filepath.Join(dir, "swanctl", ".xpf.conf.tmp-DEADBEEF"),
		filepath.Join(dir, "kea", ".kea-dhcp4.conf.tmp-0f0f"),
		filepath.Join(dir, "kea", ".kea-dhcp6.conf.tmp-1e1e"),
	}
	for _, p := range temps {
		mustWriteFile(t, p, marker)
	}

	// Bystanders that must SURVIVE — the sweep is narrow (only ".<base>.tmp-*")
	// and scoped to xpf's own rendered dirs, so it never eats a legitimate
	// service config, an operator snippet, or a non-temp dotfile.
	survivors := []string{
		filepath.Join(dir, "frr", "daemons"),     // FRR's own file, non-temp
		filepath.Join(dir, "frr", ".keepme"),     // dotfile without .tmp-
		filepath.Join(dir, "swanctl", "op.conf"), // operator-owned snippet
		filepath.Join(dir, "kea", "ctrl-agent.conf"),
	}
	for _, p := range survivors {
		mustWriteFile(t, p, []byte("keep"))
	}

	if err := wipeRenderedConfigs(frrConf, swanctlSnippet, kea4, kea6); err != nil {
		t.Fatalf("wipeRenderedConfigs returned error: %v", err)
	}

	// Every crash-leaked temp is gone — the leak #5509 closes.
	for _, p := range temps {
		assertAbsent(t, p)
	}
	// The exact-path removals still happened: swanctl/Kea gone, frr secret+section
	// stripped.
	assertAbsent(t, swanctlSnippet)
	assertAbsent(t, kea4)
	assertAbsent(t, kea6)
	got, err := os.ReadFile(frrConf)
	if err != nil {
		t.Fatalf("read frr.conf after strip: %v", err)
	}
	if strings.Contains(string(got), renderedTempSecret5509) {
		t.Errorf("frr.conf still carries the routing-auth secret after zeroize:\n%s", got)
	}
	// Bystanders untouched.
	for _, p := range survivors {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("zeroize removed a bystander it must not touch %s: %v", p, err)
		}
	}
}

// TestZeroizeRenderedConfigsTempSweepAbsentDirNoError pins that a rendered dir
// the appliance does not run (no FRR / strongSwan / Kea installed → the
// directory is absent) is a clean no-op for the temp sweep, not an error: an
// absent-directory ReadDir yields os.ErrNotExist, which the wipe excludes.
func TestZeroizeRenderedConfigsTempSweepAbsentDirNoError(t *testing.T) {
	dir := t.TempDir()
	if err := wipeRenderedConfigs(
		filepath.Join(dir, "no-frr", "frr.conf"),
		filepath.Join(dir, "no-swanctl", "xpf.conf"),
		filepath.Join(dir, "no-kea", "kea-dhcp4.conf"),
		filepath.Join(dir, "no-kea", "kea-dhcp6.conf"),
	); err != nil {
		t.Fatalf("wipeRenderedConfigs over absent rendered dirs returned error: %v", err)
	}
}
