package ipsec

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestLenientInvalidBindInterfaceSkipsLiveSA10681 proves the #10681 boundary
// end to end: CompileConfigLenient keeps an invalid bind-interface bootable
// and reports that its VPN carries no traffic, so the renderer must not emit
// the otherwise-live if_id-less connection/CHILD SA. An explicit traffic
// selector makes the pre-fix output a real CHILD SA rather than relying on an
// implicit default. A valid sibling must remain rendered.
//
// FAIL-ON-REVERT: removing the invalid-bind skip in renderConfig lets "bad"
// through into swanctl despite if_id_in/out being omitted, so rendered["bad"]
// becomes true and the connection-presence assertion goes RED.
func TestLenientInvalidBindInterfaceSkipsLiveSA10681(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set security ipsec vpn bad gateway 192.0.2.1",
		"set security ipsec vpn bad bind-interface secure0",
		"set security ipsec vpn bad traffic-selector ts1 local-ip 10.0.0.0/24",
		"set security ipsec vpn bad traffic-selector ts1 remote-ip 10.1.0.0/24",
		"set security ipsec vpn good gateway 192.0.2.2",
		"set security ipsec vpn good bind-interface st0.1",
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}

	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	bad := cfg.Security.IPsec.VPNs["bad"]
	if bad == nil || bad.BindInterface != "secure0" || len(bad.TrafficSelectors) != 1 {
		t.Fatalf("invalid VPN fixture did not compile with an explicit selector: %+v", bad)
	}
	var noTrafficWarning bool
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "#5297") && strings.Contains(warning, "carries no traffic") {
			noTrafficWarning = true
			break
		}
	}
	if !noTrafficWarning {
		t.Fatalf("lenient compile did not report the #5297 no-traffic consequence: %v", cfg.Warnings)
	}

	text, rendered, err := (&Manager{}).renderConfig(&cfg.Security.IPsec)
	if err != nil {
		t.Fatalf("renderConfig: %v", err)
	}
	if rendered["bad"] {
		t.Fatalf("VPN with invalid bind-interface was rendered as a live if_id-less SA:\n%s", text)
	}
	if !rendered["good"] {
		t.Fatalf("healthy sibling VPN was dropped with invalid VPN:\n%s", text)
	}
	doc := parseSwanctlDoc(t, text)
	doc.at(t, "connections").hasNoChild(t, "bad")
	doc.at(t, "connections", "good")
}
