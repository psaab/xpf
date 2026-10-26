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
// #16723 re-anchor: the direct-mode collector's body moved to pkg/config
// (Config.RethVIPsForRG in reth_vips.go, #15038) and the vrrp.RethVIPsForRG
// spelling kept here is a one-line delegate to it. Scanning only the
// delegate for RethRGOwners() therefore names the wrapper, not the
// collector: the census now scans CollectRethInstances in vrrp.go AND
// Config.RethVIPsForRG in ../config/reth_vips.go, and separately pins
// that the delegate routes to the config collector and carries no
// private ownership reading of its own.
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

	// Each collector is scanned in the file that now owns its body:
	// CollectRethInstances stayed in vrrp.go; the direct-mode collector
	// is Config.RethVIPsForRG in pkg/config/reth_vips.go (#15038/#16723).
	collectors := []struct {
		fn   string
		src  string
		file string
	}{
		{"CollectRethInstances", body, "vrrp.go"},
		{"(c *Config) RethVIPsForRG", cfgBody, "../config/reth_vips.go"},
	}
	for _, col := range collectors {
		fn := col.fn
		t.Run(fn, func(t *testing.T) {
			b, ok := funcBody(col.src, fn)
			if !ok {
				t.Fatalf("could not locate func %s in %s — this guard is "+
					"anchored on the function name; rename it here too", fn, col.file)
			}
			if !strings.Contains(b, "RethRGOwners()") {
				t.Errorf("%s does not call cfg.RethRGOwners(); RETH redundancy-"+
					"group ownership must come from the one shared predicate "+
					"(#6781), or the two ownership modes drift apart again", fn)
			}
			// A private re-reading of the same decision.
			if m := regexp.MustCompile(`\.RedundancyGroup\s*(<=|>=|==|!=|>|<)`).FindString(b); m != "" {
				t.Errorf("%s compares .RedundancyGroup directly (%q). Ownership "+
					"is decided by config.RethRGOwners; a local comparison is "+
					"the divergence #6781 fixed", fn, m)
			}
			if strings.Contains(b, `HasPrefix(name, "reth")`) ||
				strings.Contains(b, `HasPrefix(ifName, "reth")`) {
				t.Errorf("%s name-tests for \"reth\". That reading excluded a "+
					"structurally valid pair not spelled reth* and left its "+
					"group with no VIPs (#6781); use config.RethRGOwners", fn)
			}
		})
	}

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
