package networkd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #9494: Apply must refuse an interface name that would escape the managed
// directory, write NOTHING outside it, and leave a well-formed sibling's files
// byte-identical to a run without the bad names.
func TestApplyRefusesInterfaceNameEscapingNetworkDir_9494(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "a", "b", "network")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	m := &Manager{networkDir: dir}
	err := m.Apply([]InterfaceConfig{
		{Name: "fab0", IsBond: true, BondMode: "active-backup"},
		{Name: "a/../../../b", IsBond: true, BondMode: "active-backup"},
		{Name: "br-x/../../pwnbd", IsBridge: true},
	})
	if err == nil || !strings.Contains(err.Error(), "refusing interface name") {
		t.Fatalf("#9494: Apply must fail naming the refused interface names, got err=%v", err)
	}
	var outside []string
	_ = filepath.Walk(root, func(p string, info os.FileInfo, e error) error {
		if e == nil && !info.IsDir() && !strings.HasPrefix(p, dir+string(os.PathSeparator)) {
			outside = append(outside, p)
		}
		return nil
	})
	if len(outside) != 0 {
		t.Fatalf("#9494: files written OUTSIDE the managed directory: %v", outside)
	}

	// Control: the well-formed fab0 is still written, byte-identical to a clean run.
	cleanDir := filepath.Join(t.TempDir(), "network")
	if err := os.MkdirAll(cleanDir, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = (&Manager{networkDir: cleanDir}).Apply([]InterfaceConfig{{Name: "fab0", IsBond: true, BondMode: "active-backup"}})
	for _, suf := range []string{".netdev", ".network"} {
		got, err := os.ReadFile(filepath.Join(dir, filePrefix+"fab0"+suf))
		if err != nil {
			t.Fatalf("control fab0%s missing beside the refused names: %v", suf, err)
		}
		want, err := os.ReadFile(filepath.Join(cleanDir, filePrefix+"fab0"+suf))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Fatalf("control fab0%s differs from a clean run:\n got=%q\nwant=%q", suf, got, want)
		}
	}
}
