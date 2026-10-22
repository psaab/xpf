package factoryreset

import (
	"os"
	"path/filepath"
	"testing"
)

// wipeTempMarker5475 stands in for the IKE PSK / WireGuard key / SNMP
// community a crash-leaked fsatomic temp would carry; no file holding it may
// survive a zeroize.
const wipeTempMarker5475 = "MARKER-SECRET-5475-crash-temp"

// TestZeroizeConfigDirRemovesFsatomicTemps pins #5475 for the gRPC factory-reset
// path: wipeConfigDir's top-level sweep must also delete fsatomic
// crash-leaked write temps (".<base>.tmp-<rand>", pkg/fsatomic createTemp). A
// daemon killed between CreateTemp and the rename leaves one at the top level of
// configDir still holding the FULL cleartext config text it was mid-writing.
// Before this fix the sweep matched only `.conf` / `rollback*` /
// `.config.journal[.N]` / numbered rollback slots, so a name ending in "-<rand>"
// slipped through and its secrets survived the reset and the completing reboot.
//
// RED on revert: drop the `|| isFsatomicTemp(name)` clause and every temp below
// survives — the assertAbsent checks fail.
func TestZeroizeConfigDirRemovesFsatomicTemps(t *testing.T) {
	dir := t.TempDir()
	configBase := "xpf.conf"
	marker := []byte(wipeTempMarker5475)

	temps := []string{
		filepath.Join(dir, ".xpf.conf.tmp-abc123"),
		filepath.Join(dir, ".rescue.conf.tmp-DEADBEEF"),
		filepath.Join(dir, ".xpf.conf.1.tmp-0f0f"),
		filepath.Join(dir, "..config.journal.tmp-99"),
	}
	for _, p := range temps {
		mustWriteFile(t, p, marker)
	}

	// A legitimate non-temp dotfile must survive — the recognizer is narrow.
	keep := filepath.Join(dir, ".keepme")
	mustWriteFile(t, keep, []byte("keep"))
	bystander := filepath.Join(dir, "node-id")
	mustWriteFile(t, bystander, []byte("0"))

	if err := wipeConfigDir(dir, configBase); err != nil {
		t.Fatalf("wipeConfigDir returned error: %v", err)
	}

	for _, p := range temps {
		assertAbsent(t, p)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("zeroize removed a legitimate non-temp dotfile %s: %v", keep, err)
	}
	if _, err := os.Stat(bystander); err != nil {
		t.Errorf("zeroize removed a non-xpf file %s: %v", bystander, err)
	}
}

// TestIsFsatomicTempGRPC pins the gRPC-side recognizer (kept in sync with the
// configstore sibling) so the two factory-reset paths sweep the identical
// ".<base>.tmp-<rand>" shape without eating legitimate dotfiles.
func TestIsFsatomicTempGRPC(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{".xpf.conf.tmp-abc123", true},
		{".rescue.conf.tmp-DEADBEEF", true},
		{".xpf.conf.1.tmp-0f0f", true},
		{"..config.journal.tmp-99", true},
		{"xpf.conf", false},
		{"xpf.conf.1", false},
		{".config.journal", false},
		{".config.journal.1", false},
		{".keepme", false},
		{"node-id", false},
		{"xpf.conf.tmp-abc", false},
		{".tmp-abc", false},
	}
	for _, tc := range cases {
		if got := isFsatomicTemp(tc.name); got != tc.want {
			t.Errorf("isFsatomicTemp(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}
