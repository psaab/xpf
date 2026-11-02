package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// #18730: test/incus/apply-cos-config.sh refuses a CoS set whose filters
// have no terminal catch-all, keyed on the target's commit-check warnings
// (cos_refuse_catchall_less in test/incus/cos-apply-lib.sh). These cells pin
// the two facts that shell guard depends on, with the real compiler.

// cosApplyCatchAllPattern18730 is the shell guard's matcher, for one filter
// name. Keep in sync with cos_refuse_catchall_less.
func cosApplyCatchAllPattern18730(name string) *regexp.Regexp {
	return regexp.MustCompile(`^warning: .*filter [A-Za-z0-9-]+ "` + regexp.QuoteMeta(name) + `" has no terminal catch-all term`)
}

func loadLabCoS18730(t *testing.T, conf, set string) *ConfigTree {
	t.Helper()
	raw, err := os.ReadFile(conf)
	if err != nil {
		t.Fatalf("read %s: %v", conf, err)
	}
	tree, errs := NewParser(string(raw)).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse %s: %v", conf, errs)
	}
	sets, err := os.ReadFile(set)
	if err != nil {
		t.Fatalf("read %s: %v", set, err)
	}
	for _, line := range strings.Split(string(sets), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "set ") {
			continue
		}
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("%s: %q: %v", set, line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("%s: %q: %v", set, line, err)
		}
	}
	return tree
}

// Every lab cluster conf with every CoS fixture apply-cos-config.sh can
// select compiles with ZERO catch-all warnings, so the guard never refuses a
// current master set. The bandwidth-output filters must be present and
// attached (positive control: a set that defined no filter would also give
// zero warnings).
func TestCoSApplyLabSetsHaveCatchAll18730(t *testing.T) {
	root := filepath.Join("..", "..")
	confs := []string{"ha-cluster-userspace.conf", "ha-cluster-tcp.conf", "ha-cluster-udp.conf"}
	sets := []string{"cos-iperf-config.set", "cos-iperf-symmetric.set", "cos-iperf-same-class.set"}
	for _, conf := range confs {
		for _, set := range sets {
			tree := loadLabCoS18730(t, filepath.Join(root, "docs", conf), filepath.Join(root, "test", "incus", set))
			for _, node := range []int{0, 1} {
				cfg, err := CompileConfigForNode(tree, node)
				if err != nil {
					t.Fatalf("%s + %s node%d: %v", conf, set, node, err)
				}
				for _, w := range ValidateConfig(cfg) {
					if strings.Contains(w, "no terminal catch-all term") {
						t.Errorf("%s + %s node%d: %s", conf, set, node, w)
					}
				}
				for _, fam := range []map[string]*FirewallFilter{cfg.Firewall.FiltersInet, cfg.Firewall.FiltersInet6} {
					f := fam["bandwidth-output"]
					if f == nil {
						t.Fatalf("%s + %s node%d: bandwidth-output missing (the zero-warning result would be vacuous)", conf, set, node)
					}
					if !FirewallFilterHasCatchAll(f) {
						t.Errorf("%s + %s node%d: bandwidth-output has no catch-all", conf, set, node)
					}
				}
			}
		}
	}
}

// The commit-check warning for a catch-all-less set, as the remote CLI
// prints it (`warning: <text>`), matches the shell guard's pattern for the
// flagged filter, on both families, and not for a filter whose name merely
// extends it.
func TestCoSApplyCatchAllWarningShape18730(t *testing.T) {
	root := filepath.Join("..", "..")
	tree := loadLabCoS18730(t, filepath.Join(root, "docs", "ha-cluster-userspace.conf"),
		filepath.Join(root, "test", "incus", "cos-iperf-config.set"))
	// Make the set stale: drop the catch-all the way a pre-#18730 set lacks it.
	for _, fam := range []string{"inet", "inet6"} {
		path, err := ParseSetCommand("delete firewall family " + fam + " filter bandwidth-output term default")
		if err != nil {
			t.Fatalf("parse delete: %v", err)
		}
		if err := tree.DeletePath(path); err != nil {
			t.Fatalf("delete %s term default: %v", fam, err)
		}
	}
	cfg, err := CompileConfigForNode(tree, 0)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	var lines []string
	for _, w := range ValidateConfig(cfg) {
		lines = append(lines, "warning: "+w)
	}
	match := func(name string) int {
		n := 0
		for _, l := range lines {
			if cosApplyCatchAllPattern18730(name).MatchString(l) {
				n++
			}
		}
		return n
	}
	if got := match("bandwidth-output"); got != 2 {
		t.Fatalf("the shell guard must see bandwidth-output flagged once per family (2), got %d in %q", got, lines)
	}
	if got := match("bandwidth-outpu"); got != 0 {
		t.Fatalf("a name prefix must not match: %d", got)
	}
}
