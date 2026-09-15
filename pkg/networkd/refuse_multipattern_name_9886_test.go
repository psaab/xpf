package networkd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stubNetworkctl9886 makes Apply hermetic: reload/reconfigure succeed without a
// real systemd. Refusal tests must not depend on the sandbox's networkctl.
// The rp_filter fixture + debt reset are load-bearing, not hygiene: a stubbed
// successful reload reaches restoreSlowPathRPFilter, which writes REAL
// /proc/sys/net/ipv4 sysctls unless procSysNetRoot is redirected, and the
// reload/tail debt is process-global across the package's tests.
func stubNetworkctl9886(t *testing.T) {
	t.Helper()
	resetReloadDebtForTest(t)
	rpFilterFixture(t)
	orig := runNetworkctl
	runNetworkctl = func(args ...string) error { return nil }
	t.Cleanup(func() { runNetworkctl = orig })
}

// #9886: Apply must refuse a name that is not render-safe — write NO file for
// it — while well-formed siblings are byte-identical to a clean run. Mirrors
// confine_name_9494_test.go. The refused fixtures cover all three generated
// suffixes (bond → .netdev, bridge → .netdev, MAC → .link, all → .network) so
// no absence assertion below is vacuous.
func TestApplyRefusesMultiPatternInterfaceName_9886(t *testing.T) {
	stubNetworkctl9886(t)
	dir := t.TempDir()
	m := &Manager{networkDir: dir}
	err := m.Apply([]InterfaceConfig{
		{Name: "fab0", MACAddress: "52:54:00:aa:bb:cc", Addresses: []string{"10.0.1.10/24"}},
		{Name: "ae1", IsBond: true, BondMode: "active-backup", Addresses: []string{"10.0.2.10/24"}},
		{Name: "ge 0", IsBond: true, BondMode: "active-backup", Addresses: []string{"10.0.0.1/24"}},
		{Name: "ge-0-0-0 eth0", IsBridge: true, Addresses: []string{"10.0.0.2/24"}},
		{Name: "ge\t0", MACAddress: "52:54:00:aa:bb:cd", Addresses: []string{"10.0.0.3/24"}},
	})
	if err == nil {
		t.Fatal("#9886: Apply must fail on multi-pattern interface names, got nil")
	}
	for _, want := range []string{"refusing interface name", "[Match] Name=", "#9886"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("#9886: Apply error must mention %q, got %v", want, err)
		}
	}

	// No file for any refused name, in any suffix.
	for _, name := range []string{"ge 0", "ge-0-0-0 eth0", "ge\t0"} {
		for _, suf := range []string{".link", ".network", ".netdev"} {
			if p := filepath.Join(dir, filePrefix+name+suf); fileExists9886(p) {
				t.Errorf("#9886: refused name %q must write no file, but %s exists", name, p)
			}
		}
	}

	// Control: the well-formed siblings are still written, byte-identical to a
	// clean run — including the bond's .netdev, which the refused bond's
	// absence assertion above is measured against.
	cleanDir := t.TempDir()
	_ = (&Manager{networkDir: cleanDir}).Apply([]InterfaceConfig{
		{Name: "fab0", MACAddress: "52:54:00:aa:bb:cc", Addresses: []string{"10.0.1.10/24"}},
		{Name: "ae1", IsBond: true, BondMode: "active-backup", Addresses: []string{"10.0.2.10/24"}},
	})
	for _, tc := range []struct{ name, suf string }{
		{"fab0", ".link"}, {"fab0", ".network"}, {"ae1", ".netdev"}, {"ae1", ".network"},
	} {
		got, rerr := os.ReadFile(filepath.Join(dir, filePrefix+tc.name+tc.suf))
		if rerr != nil {
			t.Fatalf("control %s%s missing beside the refused names: %v", tc.name, tc.suf, rerr)
		}
		want, rerr := os.ReadFile(filepath.Join(cleanDir, filePrefix+tc.name+tc.suf))
		if rerr != nil {
			t.Fatal(rerr)
		}
		if string(got) != string(want) {
			t.Fatalf("control %s%s differs from a clean run:\n got=%q\nwant=%q", tc.name, tc.suf, got, want)
		}
	}

	// A second identical Apply fails identically: the refusal is stateless, not
	// debt the first failure discharges.
	if err2 := m.Apply([]InterfaceConfig{
		{Name: "fab0", MACAddress: "52:54:00:aa:bb:cc", Addresses: []string{"10.0.1.10/24"}},
		{Name: "ge 0", MACAddress: "52:54:00:aa:bb:cd", Addresses: []string{"10.0.0.1/24"}},
	}); err2 == nil || !strings.Contains(err2.Error(), "#9886") {
		t.Fatalf("#9886: second identical Apply must fail identically, got %v", err2)
	}
}

// #9886: the refused name behaves like a DELETED interface — a poisoned unit a
// previous apply rendered is swept, not pinned in `expected`. This is the
// assertion that distinguishes the pre-expected placement from a write-loop
// refusal, which would keep the poison on disk forever.
func TestApplySweepsStalePoisonedUnitsForRefusedName_9886(t *testing.T) {
	stubNetworkctl9886(t)
	dir := t.TempDir()
	poisonLink := "[Match]\nMACAddress=52:54:00:aa:bb:cd\n\n[Link]\nName=ge 0\n"
	poisonNet := "[Match]\nName=ge 0\n"
	poisonNetdev := "[NetDev]\nName=ge 0\nKind=bond\n"
	if err := os.WriteFile(filepath.Join(dir, filePrefix+"ge 0.link"), []byte(poisonLink), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, filePrefix+"ge 0.network"), []byte(poisonNet), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, filePrefix+"ge 0.netdev"), []byte(poisonNetdev), 0o644); err != nil {
		t.Fatal(err)
	}
	m := &Manager{networkDir: dir}
	err := m.Apply([]InterfaceConfig{
		{Name: "fab0", MACAddress: "52:54:00:aa:bb:cc", Addresses: []string{"10.0.1.10/24"}},
		{Name: "ge 0", IsBond: true, BondMode: "active-backup", Addresses: []string{"10.0.0.1/24"}},
	})
	if err == nil || !strings.Contains(err.Error(), "#9886") {
		t.Fatalf("#9886: Apply must fail on the refused name, got %v", err)
	}
	for _, suf := range []string{".link", ".network", ".netdev"} {
		if p := filepath.Join(dir, filePrefix+"ge 0"+suf); fileExists9886(p) {
			t.Errorf("#9886: stale poisoned %s must be swept, but it survives", p)
		}
	}
	if p := filepath.Join(dir, filePrefix+"fab0.network"); !fileExists9886(p) {
		t.Errorf("#9886: the sweep must not take the well-formed sibling's files (%s missing)", p)
	}
}

// #9886: a name failing BOTH the one-pattern predicate and confinedInterfaceName
// (slash plus space) is refused exactly ONCE — at the pre-expected belt, never
// reaching #9494. Both messages share the "refusing interface name" stem, so a
// count of 1 proves exactly-once across both checks.
func TestApplyRefusesSlashPlusSpaceExactlyOnce_9886(t *testing.T) {
	stubNetworkctl9886(t)
	m := &Manager{networkDir: t.TempDir()}
	err := m.Apply([]InterfaceConfig{{Name: "a b/c", IsBond: true}})
	if err == nil {
		t.Fatal("#9886: Apply must fail on a slash-plus-space name, got nil")
	}
	if n := strings.Count(err.Error(), "refusing interface name"); n != 1 {
		t.Fatalf("#9886: want exactly 1 refusal for \"a b/c\", got %d in %v", n, err)
	}
	if !strings.Contains(err.Error(), "#9886") || strings.Contains(err.Error(), "#9494") {
		t.Fatalf("#9886: the refusal must be the #9886 belt, not #9494: %v", err)
	}
}

// #9886: skip-first ordering — an unmanaged interface with an external config is
// never rendered by xpf, so even a multi-pattern name there must not trip the
// belt. Silent skip, no error contribution.
func TestApplySkipsExternallyManagedMultiPatternName_9886(t *testing.T) {
	stubNetworkctl9886(t)
	dir := t.TempDir()
	external := "[Match]\nName=ge 0\n\n[Network]\nDHCP=yes\n"
	if err := os.WriteFile(filepath.Join(dir, "zz-external.network"), []byte(external), 0o644); err != nil {
		t.Fatal(err)
	}
	m := &Manager{networkDir: dir}
	if err := m.Apply([]InterfaceConfig{{Name: "ge 0", Unmanaged: true}}); err != nil {
		t.Fatalf("#9886: externally-managed skip must not trip the belt, got %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "zz-external.network")); string(got) != external {
		t.Fatalf("external file disturbed: got %q", got)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), filePrefix) {
			t.Fatalf("#9886: skip must write no xpf files, found %s", e.Name())
		}
	}
}

// #9886: a refused name that is ALSO in the protected set keeps its files —
// lifeline wins over the sweep — while the refusal still fails the commit.
func TestApplyProtectedPlusPoisonedKeepsFilesAndFails_9886(t *testing.T) {
	stubNetworkctl9886(t)
	dir := t.TempDir()
	poisonNet := "[Match]\nName=ge 0\n"
	p := filepath.Join(dir, filePrefix+"ge 0.network")
	if err := os.WriteFile(p, []byte(poisonNet), 0o644); err != nil {
		t.Fatal(err)
	}
	m := &Manager{networkDir: dir}
	m.SetProtectedResolver(func() map[string]bool { return map[string]bool{"ge 0": true} })
	err := m.Apply([]InterfaceConfig{
		{Name: "ge 0", Addresses: []string{"10.0.0.1/24"}},
	})
	if err == nil || !strings.Contains(err.Error(), "#9886") {
		t.Fatalf("#9886: protected-plus-poisoned must still fail the commit, got %v", err)
	}
	if got, rerr := os.ReadFile(p); rerr != nil || string(got) != poisonNet {
		t.Fatalf("#9886: lifeline wins — the protected file must be preserved byte-identical, got %q, err %v", got, rerr)
	}
}

// #9886: empty is zero slots, not one — refused. (Previously the #9494 empty
// arm caught it in the write loop; the belt fires first now. Either way the
// name never renders.)
func TestApplyRefusesEmptyInterfaceName_9886(t *testing.T) {
	stubNetworkctl9886(t)
	m := &Manager{networkDir: t.TempDir()}
	err := m.Apply([]InterfaceConfig{{Name: ""}})
	if err == nil || !strings.Contains(err.Error(), "refusing interface name") {
		t.Fatalf("#9886: Apply must refuse an empty interface name, got %v", err)
	}
}

// #9886: control bytes that are NOT whitespace (\x01, DEL) are one pattern but
// still refused at render — what systemd makes of a raw control byte in a unit
// file is version-dependent and unanalyzed, so no file may carry one.
func TestApplyRefusesControlByteInterfaceName_9886(t *testing.T) {
	stubNetworkctl9886(t)
	dir := t.TempDir()
	m := &Manager{networkDir: dir}
	err := m.Apply([]InterfaceConfig{
		{Name: "ge\x010", MACAddress: "52:54:00:aa:bb:cc", Addresses: []string{"10.0.0.1/24"}},
		{Name: "ge\x7f0", Addresses: []string{"10.0.0.2/24"}},
	})
	if err == nil {
		t.Fatal("#9886: Apply must fail on control-byte interface names, got nil")
	}
	for _, want := range []string{"refusing interface name", "#9886"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("#9886: Apply error must mention %q, got %v", want, err)
		}
	}
	for _, name := range []string{"ge\x010", "ge\x7f0"} {
		for _, suf := range []string{".link", ".network"} {
			if p := filepath.Join(dir, filePrefix+name+suf); fileExists9886(p) {
				t.Errorf("#9886: refused name %q must write no file, but %s exists", name, p)
			}
		}
	}
}

// #9886: the .link's [Match] OriginalName= is itself a whitespace-separated
// match list, so a render-unsafe OriginalName is refused with the row — while
// a clean set-but-present OriginalName still renders (no over-refusal).
func TestApplyRefusesUnsafeOriginalName_9886(t *testing.T) {
	stubNetworkctl9886(t)
	dir := t.TempDir()
	m := &Manager{networkDir: dir}
	err := m.Apply([]InterfaceConfig{
		{Name: "ge-0-0-0", OriginalName: "enp 0s0", MACAddress: "52:54:00:aa:bb:cc"},
		{Name: "ge-0-0-1", OriginalName: "enp\x010s0"},
		{Name: "ge-0-0-2", OriginalName: "enp0s2", MACAddress: "52:54:00:aa:bb:cd"},
	})
	if err == nil {
		t.Fatal("#9886: Apply must fail on render-unsafe OriginalName values, got nil")
	}
	for _, want := range []string{"refusing OriginalName", "[Match] OriginalName=", "#9886"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("#9886: Apply error must mention %q, got %v", want, err)
		}
	}
	for _, name := range []string{"ge-0-0-0", "ge-0-0-1"} {
		for _, suf := range []string{".link", ".network"} {
			if p := filepath.Join(dir, filePrefix+name+suf); fileExists9886(p) {
				t.Errorf("#9886: refused row %q must write no file, but %s exists", name, p)
			}
		}
	}
	got, rerr := os.ReadFile(filepath.Join(dir, filePrefix+"ge-0-0-2.link"))
	if rerr != nil {
		t.Fatalf("clean OriginalName row must still render its .link: %v", rerr)
	}
	if !strings.Contains(string(got), "OriginalName=enp0s2") {
		t.Fatalf("clean .link must carry OriginalName=enp0s2, got:\n%s", got)
	}
}

func fileExists9886(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
