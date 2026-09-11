package ipsec

import (
	"testing"

	"github.com/psaab/xpf/pkg/termsafe"
)

// #9623: the VPN name reaches strongSwan raw (sanitizeSwanctlValue replaces only C0 controls and
// DEL), but GetSAStatus display-sanitizes every SAStatus field once, at parse (#6584). For a name
// that is not termsafe.DisplaySafe, ActiveConnectionNames publishes, and TerminateAllSAs
// terminates, a DIFFERENT string than the one swanctl knows. The pkg/config commit gate
// (validateIPsecSANamesDisplaySafeStrict) admits exactly the display-safe names. These cells
// pin why: through the real parse and sanitize pipeline, the published and terminated names
// equal the rendered name exactly when DisplaySafe holds.

// listSAs9623 is `swanctl --list-sas` for a VPN with no traffic selector, whose IKE SA and child
// SA both carry the VPN name (shape from TestActiveSANamesPublishesResolvableChildNames9511).
func listSAs9623(vpn string) string {
	return vpn + ": #1, ESTABLISHED, IKEv2, 8f7c1c8e3a2b1234_i* 4d3c2b1a09876543_r\n" +
		"  local  '10.0.1.1' @ 10.0.1.1[500]\n" +
		"  remote '10.0.2.1' @ 10.0.2.1[500]\n" +
		"  " + vpn + ": #1, reqid 1, INSTALLED, TUNNEL, ESP:AES_CBC-256/HMAC_SHA2_256_128\n" +
		"    local  10.0.1.0/24\n" +
		"    remote 10.9.1.0/24\n"
}

// parsedSAs9623 is GetSAStatus without the exec: parseSAOutput, then the #6584 sanitize-once.
func parsedSAs9623(vpn string) []SAStatus {
	sas := parseSAOutput(listSAs9623(vpn))
	for i := range sas {
		sanitizeSAStatus(&sas[i])
	}
	return sas
}

func TestPublishedAndTerminatedSANamesMatchTheRenderOnlyWhenDisplaySafe9623(t *testing.T) {
	for _, tc := range []struct {
		name string
		vpn  string
		safe bool
	}{
		{"C1 control (CSI)", "vpn\u009bx", false},
		{"line separator", "vpn\u2028x", false},
		{"paragraph separator", "vpn\u2029x", false},
		{"invalid UTF-8", "vpn\xffx", false},
		{"bidi override (display-safe)", "vpn\u202ex", true},
		{"plain", "vpnplain", true},
	} {
		if got := termsafe.DisplaySafe(tc.vpn); got != tc.safe {
			t.Fatalf("FIXTURE %s: DisplaySafe = %v, want %v", tc.name, got, tc.safe)
		}
		rendered := sanitizeSwanctlValue(tc.vpn)
		if rendered != tc.vpn {
			t.Fatalf("FIXTURE %s: the render must keep the name raw, got %q", tc.name, rendered)
		}
		sas := parsedSAs9623(tc.vpn)
		if len(sas) == 0 {
			t.Fatalf("FIXTURE %s: the listing must parse", tc.name)
		}

		published := activeSANames(sas)
		if equal := len(published) == 1 && published[0] == rendered; equal != tc.safe {
			t.Errorf("%s: ActiveConnectionNames published %q for the rendered name %q; equal = %v, "+
				"want %v", tc.name, published, rendered, equal, tc.safe)
		}
		terminated := terminateIKENames(sas)
		if equal := len(terminated) == 1 && terminated[0] == rendered; equal != tc.safe {
			t.Errorf("%s: TerminateAllSAs would terminate %q for the rendered name %q; equal = %v, "+
				"want %v", tc.name, terminated, rendered, equal, tc.safe)
		}
	}
}
