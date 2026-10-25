package ipsec

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #16852 (R3-B02-02): the bpfrx->xpf rename (b67f80edf9) changed the managed
// snippet from conf.d/bpfrx.conf to conf.d/xpf.conf but nothing removed the
// old file. charon includes conf.d/*.conf, so the stale connections and
// ike-* secrets kept loading on every reload: a deleted VPN stayed
// authorized (peer could re-establish), a same-named connection merged
// stale children, and the cleartext PSK survived Clear / factory reset.
//
// RED on revert: delete removeLegacySwanctlSnippet (or its call sites in
// applyConfig/clearConfig) and every "legacy survives" assertion below
// fails — the planted file otherwise survives Apply, Apply(nil) and Clear.

const legacySnippet16852 = "connections {\n vpn-old {\n  children { vpn-old { } }\n }\n}\nsecrets {\n ike-vpn-old { secret = \"legacy-psk-16852\" }\n}\n"

// legacyRecorder16852 is a swanctl double that, at every --load-all,
// snapshots which conf.d snippet files charon would glob. loadFiles is
// therefore exactly the set charon loads at that reload.
type legacyRecorder16852 struct {
	dir        string
	failLoad   bool
	loadErr    error
	loadAll    int
	atLoad     [][]string // per --load-all: basenames present in dir
	liveAtLoad []string   // per --load-all: "name" lines a fake charon would report (legacy conn if its file was present)
	listSAs    string
}

func (r *legacyRecorder16852) snapshot() []string {
	entries, _ := os.ReadDir(r.dir)
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

func (r *legacyRecorder16852) run(args ...string) ([]byte, error) {
	switch {
	case len(args) > 0 && args[0] == "--load-all":
		r.loadAll++
		files := r.snapshot()
		r.atLoad = append(r.atLoad, files)
		// Fake charon: it loads vpn-old iff bpfrx.conf is in the glob.
		live := "vpn1"
		for _, f := range files {
			if f == LegacyBPFRXConfFile {
				live = "vpn-old"
			}
		}
		r.liveAtLoad = append(r.liveAtLoad, live)
		if r.failLoad {
			return []byte("unable to load config"), r.loadErr
		}
		return nil, nil
	case len(args) > 0 && args[0] == "--list-conns":
		// Fake charon loaded set derived from the last --load-all snapshot,
		// in the --raw event shape parseListConnsRaw consumes.
		if len(r.liveAtLoad) == 0 {
			return nil, nil
		}
		return []byte("list-conn event {" + r.liveAtLoad[len(r.liveAtLoad)-1] + " {}}\nlist-conns reply {}\n"), nil
	case len(args) > 0 && args[0] == "--list-sas":
		return []byte(r.listSAs), nil
	}
	return nil, nil
}

func hasFile(files []string, name string) bool {
	for _, f := range files {
		if f == name {
			return true
		}
	}
	return false
}

func mustWriteLegacy(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func assertAbsent16852(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("%s survived (err=%v)", path, err)
	}
}

// Defect cell: seeded legacy file must be gone BEFORE the reload that
// deletes every VPN, so charon loads nothing stale afterwards.
func TestLegacyBpfrxRemovedBeforeClear16852(t *testing.T) {
	dir := t.TempDir()
	legacy := mustWriteLegacy(t, dir, LegacyBPFRXConfFile, legacySnippet16852)
	rec := &legacyRecorder16852{dir: dir}
	m := NewWithConfigDir(dir)
	m.swanctl = rec.run

	// Apply one live VPN first (the upgrade-time state: both files on disk).
	if err := m.Apply(vpnCfg("vpn1")); err != nil {
		t.Fatalf("Apply(vpn1): %v", err)
	}
	assertAbsent16852(t, legacy)
	if rec.loadAll == 0 || hasFile(rec.atLoad[len(rec.atLoad)-1], LegacyBPFRXConfFile) {
		t.Fatalf("legacy file was present at the Apply reload charon globbed: %v", rec.atLoad)
	}
	// Re-seed (simulating that the first Apply above started clean) and
	// delete ALL IPsec: the graded cell is [vpn1] -> [] -> peer FAILED.
	mustWriteLegacy(t, dir, LegacyBPFRXConfFile, legacySnippet16852)
	if err := m.Apply(nil); err != nil {
		t.Fatalf("Apply(nil) deleting all IPsec: %v", err)
	}
	assertAbsent16852(t, legacy)
	if hasFile(rec.atLoad[len(rec.atLoad)-1], LegacyBPFRXConfFile) {
		t.Fatalf("legacy file was present at the clear reload: %v", rec.atLoad)
	}
	// The connections charon would report after that reload (via the
	// Manager's own ListLoadedConns) must not contain the legacy conn.
	loaded, err := m.ListLoadedConns()
	if err != nil {
		t.Fatalf("ListLoadedConns: %v", err)
	}
	if _, ok := loaded["vpn-old"]; ok {
		t.Fatalf("charon still loads vpn-old after deleting all IPsec: %v", loaded)
	}
}

// Merge cell: a same-named live VPN must not merge stale legacy children —
// after Apply the only snippet charon can glob is xpf.conf.
func TestLegacyBpfrxRemovedBeforeApply16852(t *testing.T) {
	dir := t.TempDir()
	legacy := mustWriteLegacy(t, dir, LegacyBPFRXConfFile, legacySnippet16852)
	foreign := mustWriteLegacy(t, dir, "operator.conf", "connections { }\n")
	rec := &legacyRecorder16852{dir: dir}
	m := NewWithConfigDir(dir)
	m.swanctl = rec.run

	if err := m.Apply(vpnCfg("vpn1")); err != nil {
		t.Fatalf("Apply(vpn1): %v", err)
	}
	assertAbsent16852(t, legacy)
	last := rec.atLoad[len(rec.atLoad)-1]
	if hasFile(last, LegacyBPFRXConfFile) || !hasFile(last, BPFRXConfFile) {
		t.Fatalf("at Apply reload charon globbed %v, want only %s (+ operator.conf)", last, BPFRXConfFile)
	}
	// Foreign operator file is never xpf's to remove.
	if _, err := os.Lstat(foreign); err != nil {
		t.Fatalf("foreign operator.conf must survive xpf Apply: %v", err)
	}
	// xpf.conf carries exactly the rendered vpn1, no legacy merge source.
	body, err := os.ReadFile(filepath.Join(dir, BPFRXConfFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "vpn-old") || strings.Contains(string(body), "legacy-psk") {
		t.Fatalf("xpf.conf unexpectedly carries legacy content:\n%s", body)
	}
}

// Factory-reset leg through the Manager: Clear must also remove the file
// (and its crash temps) before reloading.
func TestLegacyBpfrxRemovedByClear16852(t *testing.T) {
	dir := t.TempDir()
	legacy := mustWriteLegacy(t, dir, LegacyBPFRXConfFile, legacySnippet16852)
	temp := mustWriteLegacy(t, dir, "."+LegacyBPFRXConfFile+".tmp-16852", legacySnippet16852)
	otherTemp := mustWriteLegacy(t, dir, ".xpf.conf.tmp-999", "x")
	rec := &legacyRecorder16852{dir: dir}
	m := NewWithConfigDir(dir)
	m.swanctl = rec.run

	if err := m.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	assertAbsent16852(t, legacy)
	assertAbsent16852(t, temp)
	if _, err := os.Lstat(otherTemp); err != nil {
		t.Fatalf("another base's crash temp must survive the legacy sweep: %v", err)
	}
	if rec.loadAll == 0 || hasFile(rec.atLoad[len(rec.atLoad)-1], LegacyBPFRXConfFile) {
		t.Fatalf("legacy file was present at the Clear reload: %v", rec.atLoad)
	}
}

// Removal failure must fail closed: Apply/Clear error, no --load-all, and
// the prior xpf.conf is untouched (charon still runs the old generation).
func TestLegacyRemovalFailureFailsClosed16852(t *testing.T) {
	dir := t.TempDir()
	// A non-empty directory at the legacy path makes os.Remove fail.
	legacyDir := filepath.Join(dir, LegacyBPFRXConfFile)
	if err := os.MkdirAll(legacyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	mustWriteLegacy(t, legacyDir, "child", "x")
	rec := &legacyRecorder16852{dir: dir}
	m := NewWithConfigDir(dir)
	m.swanctl = rec.run

	prior := []byte("connections { prior { } }\n")
	if err := os.WriteFile(m.configPath, prior, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.Apply(vpnCfg("vpn1")); err == nil {
		t.Fatal("Apply must fail when the legacy snippet cannot be removed (fail-open otherwise)")
	}
	if err := m.Clear(); err == nil {
		t.Fatal("Clear must fail when the legacy snippet cannot be removed")
	}
	if rec.loadAll != 0 {
		t.Fatalf("no --load-all may run while the legacy file is still in conf.d, got %d", rec.loadAll)
	}
	got, err := os.ReadFile(m.configPath)
	if err != nil || string(got) != string(prior) {
		t.Fatalf("prior xpf.conf must be untouched on legacy-removal failure: %q err=%v", got, err)
	}
}

// No-files control: a clean conf.d behaves exactly as before (the
// [INFERENCE]-free positive control — same Apply/Clear outcomes, no error
// invented for mere absence).
func TestNoLegacyFileIsCleanNoOp16852(t *testing.T) {
	dir := t.TempDir()
	rec := &legacyRecorder16852{dir: dir}
	m := NewWithConfigDir(dir)
	m.swanctl = rec.run
	if err := m.Apply(vpnCfg("vpn1")); err != nil {
		t.Fatalf("clean Apply: %v", err)
	}
	if err := m.Apply(nil); err != nil {
		t.Fatalf("clean clear: %v", err)
	}
	if err := m.Clear(); err != nil {
		t.Fatalf("clean Clear: %v", err)
	}
	// Reload still failing propagates exactly as before (#4898) with no
	// legacy file involved.
	rec.failLoad = true
	rec.loadErr = errors.New("charon down")
	if err := m.Apply(vpnCfg("vpn1")); err == nil {
		t.Fatal("reload failure must still propagate on a clean conf.d")
	}
}
