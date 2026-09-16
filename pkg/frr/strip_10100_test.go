package frr

import (
	"os"
	"path/filepath"
	"testing"
)

// R-2 FRR leg (#10100): StripManagedSectionFile ReadFiles through a link and
// rewrites with WithResolveSymlinks, replacing content AT THE TARGET — a
// privileged modification of a victim file carrying managed markers. It must
// refuse a symlinked path (non-nil, no target modification). The grpcapi
// zeroize pre-check reports the Skipped entry; this cell pins the primitive
// itself fail-closed for direct callers.

func TestStripManagedSectionFileRefusesSymlink10100(t *testing.T) {
	root := t.TempDir()
	victim := filepath.Join(root, "elsewhere", "victim-frr.conf")
	victimBody := "hostname r1\n" +
		"! BEGIN BPFRX MANAGED CONFIG - do not edit this section\n" +
		" ip ospf message-digest-key 1 md5 SECRET-10100-FRR-VICTIM\n" +
		"! END BPFRX MANAGED CONFIG\n"
	if err := os.MkdirAll(filepath.Dir(victim), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(victim, []byte(victimBody), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "frr", "frr.conf")
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}

	if err := StripManagedSectionFile(link); err == nil {
		t.Fatal("R-2 frr primitive: expected non-nil for symlinked frr.conf, got nil; " +
			"the strip followed the link")
	}
	got, rerr := os.ReadFile(victim)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if string(got) != victimBody {
		t.Fatalf("R-2 frr primitive: victim file modified through the link:\n%s", got)
	}
	fi, lerr := os.Lstat(link)
	if lerr != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("R-2 frr primitive: link was replaced/unlinked: %v", lerr)
	}
}
