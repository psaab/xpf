package daemon

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6781 STRUCTURAL binding for the pkg/daemon RG-ownership readers.
//
// These five decide "which interfaces belong to redundancy group N" for stable
// RETH link-local add/remove, the direct-mode GARP / router-LL burst, DHCP
// RG-scoping, and BACKUP blackhole routes. Each carried its own
// `strings.HasPrefix(name, "reth")` reading, so a structurally valid redundant
// pair not spelled `reth*` got VIPs from both ownership modes and then no GARP,
// no stable link-local and no blackhole routes — VRRP mastering an interface
// nothing else manages.
//
// rethInterfacesMatchingRG's own doc comment (#6520) already states the rule
// this enforces: "Deriving the two from one walker is not a style preference: a
// divergence between them is ALWAYS a bug."
//
// A behavioural test alone is probe-bounded — it covers the shapes someone
// thought to write down. This asserts the MECHANISM: none of these functions
// may re-derive RG membership from a name test or a raw RedundancyGroup
// comparison; all must read config.Config.RethRGOwners.
func TestDaemonRGReadersUseTheSharedPredicate(t *testing.T) {
	for _, tc := range []struct{ file, fn string }{
		{"daemon_ha_vip.go", "addStableRethLinkLocal"},
		{"daemon_ha_vip.go", "removeStableRethLinkLocal"},
		{"daemon_ha_vip.go", "directSendGARPs"},
		{"daemon_ha.go", "rethInterfacesMatchingRG"},
		{"daemon_ha.go", "injectBlackholeRoutesFor"},
	} {
		t.Run(tc.fn, func(t *testing.T) {
			raw, err := os.ReadFile(tc.file)
			if err != nil {
				t.Fatalf("read %s: %v", tc.file, err)
			}
			body, ok := rgFuncBody(stripGoLineComments(string(raw)), tc.fn)
			if !ok {
				t.Fatalf("could not locate %s in %s — this guard is anchored on "+
					"the function name; rename it here too", tc.fn, tc.file)
			}
			if !strings.Contains(body, "RethRGOwners()") {
				t.Errorf("%s does not call cfg.RethRGOwners(); RETH "+
					"redundancy-group membership must come from the one shared "+
					"predicate (#6781/#6520)", tc.fn)
			}
			if strings.Contains(body, `HasPrefix(name, "reth")`) ||
				strings.Contains(body, `HasPrefix(ifName, "reth")`) {
				t.Errorf("%s name-tests for \"reth\". That reading excluded a "+
					"structurally valid pair not spelled reth*, leaving its "+
					"group with VIPs but no GARP, link-local or blackhole "+
					"routes (#6781)", tc.fn)
			}
			if m := regexp.MustCompile(`\.RedundancyGroup\s*(<=|>=|==|!=|>|<)`).FindString(body); m != "" {
				t.Errorf("%s compares .RedundancyGroup directly (%q); membership "+
					"is decided by config.RethRGOwners", tc.fn, m)
			}
		})
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

// rgFuncBody returns the brace-matched body of the named func (method or not).
func rgFuncBody(src, name string) (string, bool) {
	idx := strings.Index(src, ") "+name+"(")
	if idx < 0 {
		idx = strings.Index(src, "func "+name+"(")
		if idx < 0 {
			return "", false
		}
	}
	open := strings.Index(src[idx:], "{")
	if open < 0 {
		return "", false
	}
	open += idx
	depth := 0
	for i := open; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[open : i+1], true
			}
		}
	}
	return "", false
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
