package networkd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestApplyRefusesNegatedInterfaceNames_15079 covers the render-side sink
// directly. A leading '!' occupies one [Match] slot, so the #9886 predicate
// alone cannot catch it; systemd reads it as inverting the whole match
// list, so the rendered unit matches every interface EXCEPT the named one.
// Apply must refuse it before expected filenames are built and must leave
// valid siblings unchanged.
func TestApplyRefusesNegatedInterfaceNames_15079(t *testing.T) {
	stubNetworkctl9886(t)
	dir := t.TempDir()
	m := &Manager{networkDir: dir}
	interfaces := []InterfaceConfig{
		{Name: "!eth0", Unmanaged: true, MACAddress: "52:54:00:aa:bb:cc", Addresses: []string{"10.0.0.1/24"}},
		{Name: "!x", Unmanaged: true, MACAddress: "52:54:00:aa:bb:dd"},
		{Name: "ge-0-0-1", OriginalName: "!enp9s0", MACAddress: "52:54:00:aa:bb:cd", Addresses: []string{"10.0.0.4/24"}},
		{Name: "ge-0-0-0", Addresses: []string{"10.0.0.5/24"}},
	}
	if err := m.Apply(interfaces); err == nil {
		t.Fatal("#15079: Apply must refuse leading-'!' interface names")
	} else {
		if !strings.Contains(err.Error(), "#15079") {
			t.Errorf("#15079: refusal must cite #15079, got %v", err)
		}
		if !strings.Contains(err.Error(), "leading '!'") || !strings.Contains(err.Error(), "inverts the match list") {
			t.Errorf("#15079: refusal must explain the inversion, got %v", err)
		}
		if !strings.Contains(err.Error(), "refusing OriginalName") {
			t.Errorf("#15079: OriginalName negation refusal must name the match slot, got %v", err)
		}
		if strings.Contains(err.Error(), "#9886") || strings.Contains(err.Error(), "#10089") {
			t.Errorf("#15079: clean negated names must not be classified as #9886/#10089 errors: %v", err)
		}
	}
	for _, name := range []string{"!eth0", "!x", "ge-0-0-1"} {
		for _, suffix := range []string{".link", ".network", ".netdev"} {
			if p := filepath.Join(dir, filePrefix+name+suffix); fileExists9886(p) {
				t.Errorf("#15079: refused negated %q must write no %s file", name, suffix)
			}
		}
	}

	cleanDir := t.TempDir()
	if err := (&Manager{networkDir: cleanDir}).Apply([]InterfaceConfig{{
		Name: "ge-0-0-0", Addresses: []string{"10.0.0.5/24"},
	}}); err != nil {
		t.Fatalf("clean control Apply failed: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, filePrefix+"ge-0-0-0.network"))
	if err != nil {
		t.Fatalf("valid sibling network file missing: %v", err)
	}
	want, err := os.ReadFile(filepath.Join(cleanDir, filePrefix+"ge-0-0-0.network"))
	if err != nil {
		t.Fatalf("clean sibling network file missing: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("valid sibling changed beside negation refusals:\n got %q\nwant %q", got, want)
	}
}

// TestApplySweepsStalePoisonedNegatedUnits_15079 preserves the #9886
// pre-expected placement contract: a refused name behaves like a deleted
// interface, so stale units from an older apply are removed rather than
// kept in expected. This is the persistent-across-reboots leg: a poisoned
// 10-xpf-!x.network left on disk would otherwise keep matching every
// interface except x at every boot.
func TestApplySweepsStalePoisonedNegatedUnits_15079(t *testing.T) {
	stubNetworkctl9886(t)
	dir := t.TempDir()
	for _, suffix := range []string{".link", ".network", ".netdev"} {
		path := filepath.Join(dir, filePrefix+"!x"+suffix)
		if err := os.WriteFile(path, []byte("[Match]\nName=!x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	m := &Manager{networkDir: dir}
	err := m.Apply([]InterfaceConfig{{Name: "!x", Unmanaged: true}})
	if err == nil || !strings.Contains(err.Error(), "#15079") {
		t.Fatalf("#15079: Apply must refuse poisoned negated name, got %v", err)
	}
	for _, suffix := range []string{".link", ".network", ".netdev"} {
		if p := filepath.Join(dir, filePrefix+"!x"+suffix); fileExists9886(p) {
			t.Errorf("#15079: stale poisoned %s must be swept", suffix)
		}
	}
}

// TestApplyAllowsNonLeadingBangNames_15079 pins the scope boundary: only a
// leading '!' is the inversion prefix. A '!' elsewhere in the name is an
// ordinary (if exotic) glob character to systemd, so a name like "eth0!"
// remains renderable and must not trip the new belt.
func TestApplyAllowsNonLeadingBangNames_15079(t *testing.T) {
	stubNetworkctl9886(t)
	dir := t.TempDir()
	m := &Manager{networkDir: dir}
	if err := m.Apply([]InterfaceConfig{{Name: "eth0!", Unmanaged: true}}); err != nil {
		t.Fatalf("#15079: non-leading '!' must not be refused, got %v", err)
	}
	if p := filepath.Join(dir, filePrefix+"eth0!.network"); !fileExists9886(p) {
		t.Errorf("#15079: control name eth0! must still render its .network file")
	}
}
