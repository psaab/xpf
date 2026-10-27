package vrrp

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// #6781 STRUCTURAL half of the binding. TestRethOwnershipModesAgree is
// behavioural and therefore probe-bounded: it proves the two ownership modes
// agree on the shapes I thought to write down. It cannot prove they still read
// the decision from ONE place — a future edit could reintroduce a private
// reading that happens to agree on those three fixtures and diverge on a fourth.
//
// This test asserts the mechanism instead: neither RETH ownership collector may
// decide ownership from a `RedundancyGroup` comparison or a `"reth"` name test
// of its own. Both must route through config.RethRGOwners.
//
// #17140 re-anchor: the ONE RETH VIP walk is Config.RethVIPsByRG in
// pkg/config/reth_vips.go. Config.RethVIPsForRG is an index into it and
// vrrp.CollectRethInstances only wraps its entries in Instances. The census
// therefore scans RethVIPsByRG in ../config/reth_vips.go (the walk) and
// CollectRethInstances in vrrp.go (the wrapper, which must delegate to it
// and carry no private ownership reading or sub-interface construction),
//
// The two tests fail in different ways on purpose. Deleting the shared
// predicate and hand-rolling an equivalent reading in both collectors keeps the
// behavioural test GREEN and reds this one.
func TestRethOwnershipCollectorsUseTheSharedPredicate(t *testing.T) {
	src, err := os.ReadFile("vrrp.go")
	if err != nil {
		t.Fatalf("read vrrp.go: %v", err)
	}
	body := stripLineComments(string(src))

	cfgSrc, err := os.ReadFile("../config/reth_vips.go")
	if err != nil {
		t.Fatalf("read ../config/reth_vips.go: %v", err)
	}
	cfgBody := stripLineComments(string(cfgSrc))

	// #17140: the ONE walk is Config.RethVIPsByRG in pkg/config/reth_vips.go.
	// It must route ownership through RethRGOwners and must be the only
	// function in the repo that builds a RETH sub-interface name.
	t.Run("RethVIPsByRG walk", func(t *testing.T) {
		b, ok := funcBody(cfgBody, "(c *Config) RethVIPsByRG")
		if !ok {
			t.Fatalf("could not locate func (c *Config) RethVIPsByRG in ../config/reth_vips.go — this guard is anchored on the function name; rename it here too")
		}
		if !strings.Contains(b, "RethRGOwners()") {
			t.Errorf("RethVIPsByRG does not call RethRGOwners(); RETH redundancy-group ownership must come from the one shared predicate (#6781), or the two ownership modes drift apart again")
		}
		if m := regexp.MustCompile(`\.RedundancyGroup\s*(<=|>=|==|!=|>|<)`).FindString(b); m != "" {
			t.Errorf("RethVIPsByRG compares .RedundancyGroup directly (%q). Ownership is decided by config.RethRGOwners; a local comparison is the divergence #6781 fixed", m)
		}
		if strings.Contains(b, `HasPrefix(name, "reth")`) || strings.Contains(b, `HasPrefix(ifName, "reth")`) {
			t.Errorf("RethVIPsByRG name-tests for \"reth\"; use config.RethRGOwners (#6781)")
		}
		if !strings.Contains(b, "dedupeVRRPVIPs") {
			t.Errorf("RethVIPsByRG does not apply the #11482 canonical dedupe (dedupeVRRPVIPs); alias spellings would again feed duplicate VIPs to the direct path (#17140)")
		}
	})

	// CollectRethInstances must stay a wrapper over the shared walk: it
	// delegates to RethVIPsByRG and must not grow a private ownership
	// reading, sub-interface construction, or unit-address walk.
	t.Run("CollectRethInstances wrapper", func(t *testing.T) {
		b, ok := funcBody(body, "CollectRethInstances")
		if !ok {
			t.Fatalf("could not locate func CollectRethInstances in vrrp.go — this guard is anchored on the function name; rename it here too")
		}
		if !strings.Contains(b, "RethVIPsByRG()") {
			t.Errorf("CollectRethInstances does not delegate to cfg.RethVIPsByRG(); the VRRP collector must wrap the one shared walk (#17140)")
		}
		if m := regexp.MustCompile(`\.RedundancyGroup\s*(<=|>=|==|!=|>|<)`).FindString(b); m != "" {
			t.Errorf("CollectRethInstances compares .RedundancyGroup directly (%q); ownership is decided by config.RethRGOwners (#6781)", m)
		}
		if strings.Contains(b, `HasPrefix(name, "reth")`) || strings.Contains(b, `HasPrefix(ifName, "reth")`) {
			t.Errorf("CollectRethInstances name-tests for \"reth\"; use config.RethRGOwners (#6781)")
		}
		if strings.Contains(b, "RethRGOwners()") {
			t.Errorf("CollectRethInstances calls RethRGOwners() directly; it must consume RethVIPsByRG so there is one walk (#17140)")
		}
		if strings.Contains(b, "LinuxIfName") || strings.Contains(b, ".VlanID") || strings.Contains(b, "TaggingEnabled") {
			t.Errorf("CollectRethInstances builds a RETH sub-interface name or walks VLAN units itself; that construction belongs only in Config.RethVIPsByRG (#17140)")
		}
	})

	// The vrrp.RethVIPsForRG delegate must stay a delegate: it routes to
	// Config.RethVIPsForRG and must not grow a private ownership reading
	// (a RedundancyGroup comparison or a "reth" name test) of its own.
	t.Run("RethVIPsForRG delegate", func(t *testing.T) {
		b, ok := funcBody(body, "RethVIPsForRG")
		if !ok {
			t.Fatalf("could not locate func RethVIPsForRG in vrrp.go — this guard is " +
				"anchored on the function name; rename it here too")
		}
		if !strings.Contains(b, "cfg.RethVIPsForRG(rgID)") {
			t.Errorf("vrrp.RethVIPsForRG does not delegate to cfg.RethVIPsForRG(rgID); " +
				"the direct-mode collector must stay the pkg/config body (#15038)")
		}
		if m := regexp.MustCompile(`\.RedundancyGroup\s*(<=|>=|==|!=|>|<)`).FindString(b); m != "" {
			t.Errorf("vrrp.RethVIPsForRG compares .RedundancyGroup directly (%q); "+
				"ownership is decided by config.RethRGOwners (#6781)", m)
		}
		if strings.Contains(b, `HasPrefix(name, "reth")`) ||
			strings.Contains(b, `HasPrefix(ifName, "reth")`) {
			t.Errorf("vrrp.RethVIPsForRG name-tests for \"reth\"; use config.RethRGOwners (#6781)")
		}
	})

	// Config.RethVIPsForRG must stay an index into the shared walk.
	t.Run("RethVIPsForRG index", func(t *testing.T) {
		b, ok := funcBody(cfgBody, "(c *Config) RethVIPsForRG")
		if !ok {
			t.Fatalf("could not locate func (c *Config) RethVIPsForRG in ../config/reth_vips.go — this guard is anchored on the function name; rename it here too")
		}
		if !strings.Contains(b, "RethVIPsByRG()") {
			t.Errorf("Config.RethVIPsForRG does not index into RethVIPsByRG(); it must not grow a second walk (#17140)")
		}
	})
}

// stripLineComments removes //-comments so the scan cannot be satisfied — or
// tripped — by prose that merely quotes the pattern it looks for.
func stripLineComments(s string) string {
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

// funcBody returns the body of the named top-level func by brace matching.
func funcBody(src, name string) (string, bool) {
	idx := strings.Index(src, "func "+name+"(")
	if idx < 0 {
		return "", false
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
