package policymatch

import (
	"net"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9525 at the verdict: on the tolerant path the simulator reported a concrete
// verdict for an application the dataplane installs as something other than
// what was authored. It now reports the refusal the helper enforces.

func lenientPolicy9525(t *testing.T, apps, action, def string) *config.Config {
	t.Helper()
	text := `applications { ` + apps + ` } security { zones { security-zone trust; security-zone untrust; } ` +
		`policies { default-policy { ` + def + `; } from-zone trust to-zone untrust { policy p1 { ` +
		`match { source-address any; destination-address any; application a; } then { ` + action + `; } } } } }`
	tree, errs := config.NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	return cfg
}

func icmpQuery9525(icmpType uint8, ident int) Query {
	return Query{FromZone: "trust", ToZone: "untrust",
		SrcIP: net.ParseIP("10.0.1.5"), DstIP: net.ParseIP("10.0.2.5"),
		Protocol: "icmp", SrcPort: ident, ICMPType: &icmpType}
}

func TestTolerantApplicationDropIsReportedAsRefused9525(t *testing.T) {
	cases := []struct {
		name, apps, action, def string
		q                       Query
		before                  string
	}{
		{"V3: a deny on icmp destination-port 80 never fired", `application a { protocol icmp; destination-port 80; }`,
			"deny", "permit-all", icmpQuery9525(8, 0), "echo fell through to permit-all"},
		{"V4: a permit on icmp-type 999 admitted every type", `application a { term t1 { protocol icmp; icmp-type 999; } }`,
			"permit", "deny-all", icmpQuery9525(13, 0), "timestamp was permitted"},
		{"a deny on icmp source-port 80 fired only for Identifier 80", `application a { protocol icmp; source-port 80; }`,
			"deny", "permit-all", icmpQuery9525(8, 81), "Identifier 81 fell through to permit-all"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := Match(lenientPolicy9525(t, c.apps, c.action, c.def), c.q)
			if !res.ContentRejected {
				t.Fatalf("want ContentRejected (before #9525: %s); got matched=%v action=%v default_used=%v",
					c.before, res.Matched, res.Action, res.DefaultUsed)
			}
			if !strings.Contains(strings.Join(res.ContentRejectionReasons, "\n"), `application "a"`) {
				t.Fatalf("the refusal must name application \"a\"; reasons %q", res.ContentRejectionReasons)
			}
		})
	}
}

func TestTolerantApplicationControlsKeepTheirVerdicts9525(t *testing.T) {
	cfg := lenientPolicy9525(t, `application a { term t1 { protocol icmp; icmp-type 8; } }`, "permit", "deny-all")
	if res := Match(cfg, icmpQuery9525(8, 0)); res.ContentRejected || !res.Matched || res.DefaultUsed || res.Action != config.PolicyPermit {
		t.Fatalf("icmp-type 8 control: echo must match the permit; got %+v", res)
	}
	if res := Match(cfg, icmpQuery9525(13, 0)); res.ContentRejected || !res.DefaultUsed || res.Action != config.PolicyDeny {
		t.Fatalf("icmp-type 8 control: timestamp must fall to deny-all; got %+v", res)
	}
	timeout := lenientPolicy9525(t, `application a { protocol tcp; destination-port 22; inactivity-timeout thirty; }`, "permit", "deny-all")
	q := Query{FromZone: "trust", ToZone: "untrust", SrcIP: net.ParseIP("10.0.1.5"), DstIP: net.ParseIP("10.0.2.5"),
		Protocol: "tcp", SrcPort: 40000, DstPort: 22}
	if res := Match(timeout, q); res.ContentRejected || !res.Matched || res.DefaultUsed || res.Action != config.PolicyPermit {
		t.Fatalf("settings-only control: tcp/22 must still match the permit; got %+v", res)
	}
}
