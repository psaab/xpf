package policymatch

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9524 — `show security match-policies` on the tolerant path. Before #9524 a
// `deny` naming a mixed address denied only the prefix, so a host the object's
// range-address names was PERMITTED by a later default. It now reports the
// helper's refusal. Channel: config.CompileConfigLenient.
func TestMixedAddressSimulatorReportsTheRefusal9524(t *testing.T) {
	text := func(book string) string {
		return `security { address-book { global { ` + book + ` } } zones { security-zone trust; security-zone untrust; } policies { default-policy { permit-all; } from-zone trust to-zone untrust { policy d1 { match { source-address mixed; destination-address any; application any; } then { deny; } } } } }`
	}
	q := func(src string) Query {
		return Query{FromZone: "trust", ToZone: "untrust", SrcIP: net.ParseIP(src), DstIP: net.ParseIP("10.0.2.5"), Protocol: "tcp", SrcPort: 40000, DstPort: 80}
	}
	mixed := lenientHier9571(t, text(`address mixed { 10.10.0.0/24; range-address 192.0.2.1 { to { 192.0.2.9; } } }`))
	if res := Match(mixed, q("192.0.2.5")); !res.ContentRejected || res.Matched {
		t.Fatalf("#9524: a host the object names fell through the deny to the default instead of the refusal being reported: %+v", res)
	}
	sole := lenientHier9571(t, text(`address mixed 10.10.0.0/24;`))
	if res := Match(sole, q("10.10.0.5")); res.ContentRejected || !res.Matched || res.Action != config.PolicyDeny {
		t.Fatalf("control: a sole-prefix deny must still match its prefix, got %+v", res)
	}
	if res := Match(sole, q("192.0.2.5")); res.ContentRejected || res.Matched || !res.DefaultUsed {
		t.Fatalf("control: traffic outside a sole-prefix deny uses the default, got %+v", res)
	}
}
