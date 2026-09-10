package policymatch

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9595 at the verdict: a misspelled `destination-poort 22` used to permit
// every TCP port, and a misspelled set member left a deny that no longer
// covered it.

func tcpQuery9595(port int) Query {
	return Query{FromZone: "trust", ToZone: "untrust",
		SrcIP: net.ParseIP("10.0.1.5"), DstIP: net.ParseIP("10.0.2.5"),
		Protocol: "tcp", SrcPort: 40000, DstPort: port}
}

func TestLostConstraintStatementIsReportedAsRefused9595(t *testing.T) {
	permit := lenientPolicyText9595(t, `application a { protocol tcp; destination-poort 22; }`, "permit", "deny-all")
	if res := Match(permit, tcpQuery9595(9999)); !res.ContentRejected {
		t.Fatalf("tcp/9999 must be refused, not permitted by a tcp-any term (before #9595 it was permitted); got %+v", res)
	}
	deny := lenientPolicyText9595(t, `application-set a { application junos-telnet; applicaton junos-ssh; }`, "deny", "permit-all")
	if res := Match(deny, tcpQuery9595(22)); !res.ContentRejected {
		t.Fatalf("tcp/22 must be refused, not fall through to permit-all past a set that lost junos-ssh; got %+v", res)
	}
}

func TestStrayStatementBesideARetainedPortKeepsItsVerdict9595(t *testing.T) {
	cfg := lenientPolicyText9595(t, `application a { protocol tcp; destination-port 8080; bogus value; }`, "permit", "deny-all")
	if res := Match(cfg, tcpQuery9595(8080)); res.ContentRejected || !res.Matched || res.Action != config.PolicyPermit {
		t.Fatalf("#6524: tcp/8080 must still match the permit; got %+v", res)
	}
	if res := Match(cfg, tcpQuery9595(22)); res.ContentRejected || !res.DefaultUsed {
		t.Fatalf("#6524: tcp/22 must still fall to the default; got %+v", res)
	}
}

func lenientPolicyText9595(t *testing.T, apps, action, def string) *config.Config {
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
