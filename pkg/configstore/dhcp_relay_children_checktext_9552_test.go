package configstore

import (
	"strings"
	"testing"
)

// #9552 on the operator commit channel: an undeclared dhcp-relay child is
// refused naming the token, and the DHCPv4 relay control in the same run
// commits, so the refusal is not the fixture being refused for another reason.
func TestCheckTextRefusesUndeclaredDHCPRelayChild9552(t *testing.T) {
	if _, err := CheckText("forwarding-options { dhcp-relay { xpfbogus9552 { foo 1; } } }", 0); err == nil ||
		!strings.Contains(err.Error(), "xpfbogus9552") {
		t.Fatalf("CheckText committed an undeclared dhcp-relay child: %v", err)
	}
	control := "forwarding-options { dhcp-relay { server-group isp { 10.0.0.5; } " +
		"group g1 { active-server-group isp; interface ge-0/0/0.0; } } }"
	cfg, err := CheckText(control, 0)
	if err != nil {
		t.Fatalf("control: a valid DHCPv4 relay was refused: %v", err)
	}
	if r := cfg.ForwardingOptions.DHCPRelay; r == nil || len(r.ServerGroups) != 1 || len(r.Groups) != 1 {
		t.Fatalf("control compiled %+v, want 1 server-group and 1 group", r)
	}
}
