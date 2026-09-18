package networkd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestApplyRefusesSinglePatternGlobInterfaceNames_10089 covers the render-side
// sink directly. A glob occupies one [Match] pattern, so the #9886 predicate
// alone cannot catch it; Apply must refuse the literal token before expected
// filenames are built and must leave valid siblings unchanged.
func TestApplyRefusesSinglePatternGlobInterfaceNames_10089(t *testing.T) {
	stubNetworkctl9886(t)
	dir := t.TempDir()
	m := &Manager{networkDir: dir}
	interfaces := []InterfaceConfig{
		{Name: "ge*", IsBond: true, BondMode: "active-backup", Addresses: []string{"10.0.0.1/24"}},
		{Name: "ge?", IsBridge: true, Addresses: []string{"10.0.0.2/24"}},
		{Name: "ge[0-9]", MACAddress: "52:54:00:aa:bb:cc", Addresses: []string{"10.0.0.3/24"}},
		{Name: "ge-0-0-1", OriginalName: "enp*", MACAddress: "52:54:00:aa:bb:cd", Addresses: []string{"10.0.0.4/24"}},
		{Name: "ge-0-0-0", Addresses: []string{"10.0.0.5/24"}},
	}
	if err := m.Apply(interfaces); err == nil {
		t.Fatal("#10089: Apply must refuse single-pattern glob interface names")
	} else {
		for _, token := range []string{"\"*\"", "\"?\"", "\"[\""} {
			if !strings.Contains(err.Error(), "#10089") || !strings.Contains(err.Error(), "glob metacharacter "+token) {
				t.Errorf("#10089: refusal must name token %s, got %v", token, err)
			}
		}
		if strings.Contains(err.Error(), "#9886") {
			t.Errorf("#10089: clean single-pattern globs must not be classified as #9886 whitespace/control errors: %v", err)
		}
		if !strings.Contains(err.Error(), "refusing OriginalName") {
			t.Errorf("#10089: OriginalName glob refusal must name the match slot, got %v", err)
		}
	}
	for _, name := range []string{"ge*", "ge?", "ge[0-9]", "ge-0-0-1"} {
		for _, suffix := range []string{".link", ".network", ".netdev"} {
			if p := filepath.Join(dir, filePrefix+name+suffix); fileExists9886(p) {
				t.Errorf("#10089: refused glob %q must write no %s file", name, suffix)
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
		t.Fatalf("valid sibling changed beside glob refusals:\n got %q\nwant %q", got, want)
	}
}

// TestApplySweepsStalePoisonedGlobUnits_10089 preserves the #9886 pre-expected
// placement contract: a refused name behaves like a deleted interface, so
// stale units from an older apply are removed rather than kept in expected.
func TestApplySweepsStalePoisonedGlobUnits_10089(t *testing.T) {
	stubNetworkctl9886(t)
	dir := t.TempDir()
	for _, suffix := range []string{".link", ".network", ".netdev"} {
		path := filepath.Join(dir, filePrefix+"ge*"+suffix)
		if err := os.WriteFile(path, []byte("[Match]\nName=ge*\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	m := &Manager{networkDir: dir}
	err := m.Apply([]InterfaceConfig{{Name: "ge*"}})
	if err == nil || !strings.Contains(err.Error(), "#10089") {
		t.Fatalf("#10089: Apply must refuse poisoned glob name, got %v", err)
	}
	for _, suffix := range []string{".link", ".network", ".netdev"} {
		if p := filepath.Join(dir, filePrefix+"ge*"+suffix); fileExists9886(p) {
			t.Errorf("#10089: stale poisoned %s must be swept", suffix)
		}
	}
}
