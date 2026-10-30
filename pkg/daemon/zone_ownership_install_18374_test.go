package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

// #18374: the daemon's ownership install carries a digest of what the
// ingress fold closes over (the store's canonical config text digest and the
// ifindex->name table), so a content-equal re-install keeps the session-sync
// ownership generation and an in-flight bulk keeps its reconcile.

func ifaces18374(pairs ...any) []net.Interface {
	var out []net.Interface
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, net.Interface{Index: pairs[i].(int), Name: pairs[i+1].(string)})
	}
	return out
}

func TestIngressFoldDigestCoversExactlyWhatTheFoldClosesOver18374(t *testing.T) {
	const cfgDigest = "sha256:cfg-a"
	base := ingressFoldDigest(cfgDigest, ingressFoldNameTable(ifaces18374(2, "fxp0", 5, "ge-0-0-1", 6, "ge-0-0-2")))
	if !base.Known() {
		t.Fatal("a known config digest produced the unknown resolver digest")
	}
	same := ingressFoldDigest(cfgDigest, ingressFoldNameTable(ifaces18374(6, "ge-0-0-2", 2, "fxp0", 5, "ge-0-0-1")))
	if same != base {
		t.Error("the digest depends on interface listing order; the fold closure does not")
	}
	// Fields the closure never reads must not move the digest: a link-state
	// refresh changes exactly these.
	flapped := ifaces18374(2, "fxp0", 5, "ge-0-0-1", 6, "ge-0-0-2")
	for i := range flapped {
		flapped[i].Flags = net.FlagUp | net.FlagRunning
		flapped[i].MTU = 9000
		flapped[i].HardwareAddr = net.HardwareAddr{2, 0xbf, 0x72, 0, 0, byte(i)}
	}
	if ingressFoldDigest(cfgDigest, ingressFoldNameTable(flapped)) != base {
		t.Error("a link-state change (flags/MTU/MAC) moved the digest; an em0 carrier event would void the bulk")
	}
	for name, d := range map[string]cluster.ResolverDigest{
		"renumbered device (#15263 recreation)": ingressFoldDigest(cfgDigest, ingressFoldNameTable(ifaces18374(2, "fxp0", 9, "ge-0-0-1", 6, "ge-0-0-2"))),
		"renumbered device, name order kept":    ingressFoldDigest(cfgDigest, ingressFoldNameTable(ifaces18374(2, "fxp0", 5, "ge-0-0-1", 7, "ge-0-0-2"))),
		"renamed device":                        ingressFoldDigest(cfgDigest, ingressFoldNameTable(ifaces18374(2, "fxp0", 5, "ge-0-0-9", 6, "ge-0-0-2"))),
		"device appeared":                       ingressFoldDigest(cfgDigest, ingressFoldNameTable(ifaces18374(2, "fxp0", 5, "ge-0-0-1", 6, "ge-0-0-2", 7, "fab1"))),
		"different config":                      ingressFoldDigest("sha256:cfg-b", ingressFoldNameTable(ifaces18374(2, "fxp0", 5, "ge-0-0-1", 6, "ge-0-0-2"))),
	} {
		if d == base {
			t.Errorf("%s left the digest unchanged; the fold closure answers differently", name)
		}
	}
	if ingressFoldDigest("", ingressFoldNameTable(ifaces18374(2, "fxp0"))).Known() {
		t.Error("an unidentified config (ActiveDigestFor == \"\") must yield the unknown digest")
	}
}

func linkRefreshDaemon18374(t *testing.T) (*Daemon, *cluster.SessionSync, *config.Config) {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	cfg, err := store.SyncApply("interfaces { ge-0/0/1 { unit 0 { family inet { address 10.0.61.1/24; } } } }\n"+
		"security { zones { security-zone lan { interfaces { ge-0/0/1.0; } } } }\n", nil)
	if err != nil {
		t.Fatalf("SyncApply: %v", err)
	}
	if store.ActiveDigestFor(cfg) == "" {
		t.Fatal("fixture: the applied config is not the store's compiled active config")
	}
	ss := cluster.NewSessionSync(":0", ":0", nil)
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: store}
	d.sessionSync = ss
	return d, ss, cfg
}

// The issue's 06:17:06.477 event, through the production link-refresh path:
// an em0 link-state refresh with the config and the device table unchanged.
func TestLinkRefreshWithUnchangedTableKeepsTheOwnershipGeneration18374(t *testing.T) {
	d, ss, cfg := linkRefreshDaemon18374(t)
	table := func() ([]net.Interface, error) {
		return ifaces18374(2, "fxp0", 3, "em0", 5, "ge-0-0-1"), nil
	}
	d.refreshIngressFoldClosures(cfg, nil, table)
	g := ss.ZoneOwnershipGeneration()
	flapped := func() ([]net.Interface, error) {
		devs := ifaces18374(2, "fxp0", 3, "em0", 5, "ge-0-0-1")
		devs[1].Flags = net.FlagUp | net.FlagRunning // em0 carrier came up
		return devs, nil
	}
	d.refreshIngressFoldClosures(cfg, nil, flapped)
	if got := ss.ZoneOwnershipGeneration(); got != g {
		t.Fatalf("#18374: a link refresh that changed neither the config nor the ifindex->name table advanced "+
			"the ownership generation %d -> %d; a bulk in flight loses its reconcile and its BulkAck", g, got)
	}
	renumbered := func() ([]net.Interface, error) {
		return ifaces18374(2, "fxp0", 3, "em0", 29, "ge-0-0-1"), nil
	}
	d.refreshIngressFoldClosures(cfg, nil, renumbered)
	if got := ss.ZoneOwnershipGeneration(); got == g {
		t.Fatal("#15263/#9655: a recreated netdev changes what the fold resolves, and the generation did not advance")
	}
}

// A config the store cannot identify (not its compiled active object) has no
// provable content, so its install must advance — the pre-#18374 behaviour.
func TestUnidentifiedConfigInstallAlwaysAdvances18374(t *testing.T) {
	d, ss, _ := linkRefreshDaemon18374(t)
	table := func() ([]net.Interface, error) { return ifaces18374(5, "ge-0-0-1"), nil }
	other := &config.Config{}
	d.refreshIngressFoldClosures(other, nil, table)
	g := ss.ZoneOwnershipGeneration()
	d.refreshIngressFoldClosures(other, nil, table)
	if ss.ZoneOwnershipGeneration() == g {
		t.Fatal("an install whose config has no store digest was judged unchanged")
	}
}

// Every production ownership install must carry a digest, i.e. go through
// InstallZoneOwnership. The legacy setters are exported, so the walk covers
// the module, not this package. Positive control: the walk must SEE the
// InstallZoneOwnership call sites, or a blind walk would pass vacuously.
func TestProductionInstallsOwnershipOnlyThroughInstallZoneOwnership18374(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	legacy := map[string]bool{"SetZoneOwnership": true, "SetIngressFoldFn": true, "SetNatScopeFoldFn": true}
	var bad []string
	installs := 0
	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(path string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() {
			switch e.Name() {
			case ".git", "vendor", "node_modules", "target", "userspace-dp", "userspace-xdp", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !strings.Contains(string(src), "Fold") && !strings.Contains(string(src), "ZoneOwnership") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			return nil // not this cell's subject; the build reports it
		}
		rel, _ := filepath.Rel(root, path)
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch {
			case sel.Sel.Name == "InstallZoneOwnership":
				installs++
			case legacy[sel.Sel.Name] && rel != filepath.Join("pkg", "cluster", "test_seams.go"):
				bad = append(bad, rel+": "+sel.Sel.Name)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if installs < 4 {
		t.Fatalf("positive control: found %d InstallZoneOwnership call sites, want >= 4 (apply, seed, install, link refresh); "+
			"the walk is not seeing the daemon", installs)
	}
	if len(bad) > 0 {
		t.Fatalf("#18374: production code installs ownership without a resolver digest, which voids every "+
			"in-flight bulk reconcile on each call:\n  %s", strings.Join(bad, "\n  "))
	}
}
