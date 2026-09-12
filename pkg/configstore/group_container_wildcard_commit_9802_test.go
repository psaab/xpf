package configstore

import (
	"sort"
	"strings"
	"testing"
)

// #9802 at the operator commit path. A `<*>` group under a container the
// configuration lacks was adopted wholesale, so `CheckText` compiled a zone
// literally named `<*>` and accepted it — the #9423 phantom reached by the
// route that issue's fixtures cannot take. With the zones in a SECOND
// `security` stanza, the group's body landed in the first stanza instead, so
// the real zone never received it. Measured at master ef390f3ac.
func TestGroupWildcardContainerAtCommit9802(t *testing.T) {
	const screen = `security { screen { ids-option edge { icmp { ping-death; } } } } `
	const zoneGroup = `groups { G { security { zones { security-zone <*> { tcp-rst; } } } } } apply-groups G; `
	t.Run("no phantom zone reaches the commit path", func(t *testing.T) {
		cfg, err := CheckText(zoneGroup+screen, -1)
		if err != nil {
			t.Fatalf("strict commit: %v", err)
		}
		var names []string
		for z := range cfg.Security.Zones {
			names = append(names, z)
		}
		sort.Strings(names)
		for _, n := range names {
			if strings.ContainsAny(n, "<>*") {
				t.Errorf("a phantom zone reached the operator commit path: zones=%v (#9802, #9423)", names)
			}
		}
	})
	t.Run("zones in a second security stanza receive the group", func(t *testing.T) {
		cfg, err := CheckText(zoneGroup+screen+`security { zones { security-zone trust { } } }`, -1)
		if err != nil {
			t.Fatalf("strict commit: %v", err)
		}
		z := cfg.Security.Zones["trust"]
		if z == nil {
			t.Fatalf("zone trust did not compile")
		}
		if !z.TCPRst {
			t.Errorf("zone trust compiled without the group's tcp-rst: a group must reach every same-keyed stanza (#9802)")
		}
		for n := range cfg.Security.Zones {
			if strings.ContainsAny(n, "<>*") {
				t.Errorf("a phantom zone reached the operator commit path beside the real one (#9802)")
			}
		}
	})
}
