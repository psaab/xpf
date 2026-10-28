package daemon

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6781/#17086 STRUCTURAL binding for the pkg/daemon RG-ownership
// readers: the ref→RG question has ONE answer, config.Config's
// InterfaceRefRG / RefRG / RethRGOwners (#17086), and no pkg/daemon
// file may re-derive it from a raw `.RedundancyGroup` field read.
//
// The pre-#17086 guard enumerated five hand-listed functions and
// checked each called RethRGOwners; rpmProbeTestGating was not in
// the list, kept its `reth*` name test through two rewrites, and
// gated a structural bond0 RETH on the wrong RG. An enumeration
// guard protects exactly the sites someone remembered to list. This
// version greps instead: EVERY non-test .go file in pkg/daemon is
// scanned, and any `.RedundancyGroup` field read outside the
// documented classification predicates below fails the build.
//
// Exemptions are whole-file and each names why the read is NOT the
// ref→RG ownership question:
//
//   - daemon_ha_sync.go: `currentRedundancyGroups` returns the
//     []*config.RedundancyGroup TYPE (chassis RG definitions), never
//     an interface's field.
//   - rxvlan_audit_11446.go: `rxVlanParentNames` classifies physical
//     parents for the RX-VLAN audit — "carries any group OR is named
//     reth*" excludes a parent from audit, it does not answer which
//     RG owns a ref. A stray group correctly excludes there.
//
// The scan strips //-comments first, so prose quoting the pattern
// neither satisfies nor trips it. New interface-field reads must go
// through the SSOT; if a future read is genuinely not the ownership
// question, it joins the exemption list WITH its reason.
func TestDaemonRGReadersUseTheSharedPredicate(t *testing.T) {
	exempt := map[string]string{
		"daemon_ha_sync.go":     "returns []*config.RedundancyGroup (RG definitions), not an interface field read",
		"rxvlan_audit_11446.go": "rxVlanParentNames classification predicate, not the ref→RG question",
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read pkg/daemon dir: %v", err)
	}
	fieldRead := regexp.MustCompile(`\.(RedundancyGroup)\b`)
	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		if _, ok := exempt[name]; ok {
			continue
		}
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		scanned++
		if m := fieldRead.FindString(stripGoLineComments(string(raw))); m != "" {
			t.Errorf("%s reads %s directly; interface→RG ownership must come from "+
				"config.InterfaceRefRG / RefRG / RethRGOwners (#6781/#17086). If this "+
				"read is not the ownership question, exempt the file above with its reason", name, m)
		}
	}
	if scanned == 0 {
		t.Fatal("scanned no pkg/daemon files — the guard is anchored on the package directory")
	}
}

// stripGoLineComments removes //-comments so the scan cannot be satisfied — or
// tripped — by prose quoting the very pattern it looks for.
func stripGoLineComments(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

// TestAllRGReadersAgreeOnStructuralPair is the BEHAVIOURAL half for the daemon
// readers: on a structurally valid redundant pair NOT spelled `reth*`, the
// membership walk must resolve it, exactly as the two ownership modes now do.
//
// This is the shape the name tests dropped. Before #6781 the group got VIPs
// installed by the ownership modes and then nothing else: no GARP, no stable
// link-local, no blackhole routes on BACKUP — so return traffic escaped via the
// default route while VRRP mastered an interface nothing else managed.
//
// FAIL-ON-REVERT: restore `strings.HasPrefix(name, "reth")` in
// rethInterfacesMatchingRG and this reds, naming what it resolved instead.
func TestAllRGReadersAgreeOnStructuralPair(t *testing.T) {
	cfg := rgOwnerTestConfig(t)

	// Precondition: the shared predicate owns bond0 at group 1, so a failure
	// below is about this reader and not about the fixture.
	if rg, ok := cfg.RethRGOwners()["bond0"]; !ok || rg != 1 {
		t.Fatalf("fixture: bond0 must own group 1, got rg=%d ok=%v (owners=%v)",
			rg, ok, cfg.RethRGOwners())
	}

	names := rethInterfacesMatchingRG(cfg, func(rgID int) bool { return rgID == 1 })
	found := false
	for _, n := range names {
		if n == "ge-0-0-1" { // bond0 resolves to its local member port
			found = true
		}
	}
	if !found {
		t.Errorf("RG membership did not resolve the structurally valid pair "+
			"bond0 to its member ge-0-0-1; got %v. Its group would get VIPs "+
			"from both ownership modes and then no GARP, no stable link-local "+
			"and no blackhole routes", names)
	}
}

// rgOwnerTestConfig builds a cluster config whose redundant pair is owned by
// `bond0` — structurally a reth (ports name it as their redundant-parent) but
// not spelled `reth*`.
func rgOwnerTestConfig(t *testing.T) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, l := range []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-6781",
		"set chassis cluster reth-count 2",
		"set chassis cluster no-private-rg-election",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 1 priority 100",
		"set interfaces ge-0/0/1 gigether-options redundant-parent bond0",
		"set interfaces bond0 redundant-ether-options redundancy-group 1",
		"set interfaces bond0 unit 0 family inet address 10.0.61.1/24",
	} {
		path, err := config.ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", l, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("a structurally valid pair must commit: %v", err)
	}
	return cfg
}
