package config

import (
	"fmt"
	"testing"
)

// Regression pin for the apply-groups half of the #8800 review (Codex finding 2).
// Declaring the pool `address` leaf with multi:true would make it
// leaf-list-ELIGIBLE (isLeafListSchema requires multi), flipping apply-groups
// from OVERRIDE to token UNION for a spelling that already worked. On the
// DESTINATION pool, whose grammar carries the port on the same statement, that
// union corrupted the value: inheriting `address 10.0.0.2/32 port 8080;` over an
// inline `address 10.0.0.1/32 port 80;` compiled the ADDRESS as "8080".
func TestNATPoolAddressGroupOverride8800(t *testing.T) {
	g := "groups { g1 { security { nat { destination { pool p1 { address 10.0.0.2/32 port 8080; } } } } } } " +
		"apply-groups g1; " +
		"security { zones { security-zone z1 { host-inbound-traffic { system-services ping; } } } " +
		"nat { destination { pool p1 { address 10.0.0.1/32 port 80; } " +
		"rule-set rs1 { from zone z1; rule r1 { match { destination-address 10.0.0.0/8; } " +
		"then { destination-nat { pool p1; } } } } } } }"
	tr, perrs := NewParser(g).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := compileConfigWithOpts(tr, lenientCompileOpts())
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	var got string
	if cfg.Security.NAT.Destination != nil {
		for _, p := range cfg.Security.NAT.Destination.Pools {
			if p.Name == "p1" {
				got = fmt.Sprintf("addr=%q port=%d", p.Address, p.Port)
			}
		}
	}
	const want = `addr="10.0.0.1/32" port=80`
	if got != want {
		t.Errorf("apply-groups over a destination NAT pool address: got %s, want %s\n"+
			"The inline statement must OVERRIDE the inherited one. If the address "+
			"has become the PORT value (addr=\"8080\"), the `address` leaf has "+
			"regained multi:true and is being token-UNIONed as a leaf-list "+
			"(isLeafListSchema in ast_groups.go requires multi). #8800 leaves it "+
			"unset deliberately: it buys nothing for validation and this is what "+
			"it costs.", got, want)
	}
	if _, serr := compileConfigWithOpts(tr, compileOpts{}); serr != nil {
		t.Errorf("strict compile rejected a valid group-inherited destination pool: %v", serr)
	}
}
