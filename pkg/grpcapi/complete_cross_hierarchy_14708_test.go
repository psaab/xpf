package grpcapi

import (
	"path/filepath"
	"strings"
	"testing"
)

// #14708 (D15-03): #14144 gated Complete's live values only on the CURSOR
// path. Cross-hierarchy ValueHints read a FIXED subtree regardless of the
// cursor (interface names from `protocols ospf … interface`, address-book
// names/CIDRs from `security policies … source-address`), and operational
// `test policy from-zone` evaluated confRules against "policy from-zone",
// which no ^security deny matches. Both leaked denied-subtree names,
// descriptions and CIDRs to a restricted principal.

const complete14708Config = `
system {
    login {
        class deny-interfaces {
            permissions [ view ];
            deny-configuration "^interfaces";
        }
        class deny-address-book {
            permissions [ view ];
            deny-configuration "^security address-book";
        }
        class deny-applications {
            permissions [ view ];
            deny-configuration "^applications";
        }
        class deny-security {
            permissions [ view ];
            deny-configuration "^security";
        }
        class deny-interfaces-only {
            permissions [ view ];
            deny-configuration "^interfaces";
        }
        class open-view {
            permissions [ view ];
        }
        user a { class deny-interfaces; }
        user b { class deny-address-book; }
        user c { class deny-applications; }
        user d { class deny-security; }
        user e { class deny-interfaces-only; }
        user f { class open-view; }
    }
}
security {
    zones {
        security-zone trust {
            description "SECRET-TRUST-DESC";
            host-inbound-traffic { system-services [ ssh ]; }
            interfaces [ ge-0/0/0.0 ];
        }
        security-zone untrust {
            description "SECRET-UNTRUST-DESC";
            host-inbound-traffic { system-services [ https ]; }
            interfaces [ ge-0/0/1.0 ];
        }
    }
    address-book {
        global {
            address web-net 203.0.113.0/24;
            address db-net 198.51.100.0/24;
        }
    }
    policies {
        from-zone trust to-zone untrust {
            policy allow-web {
                description "SECRET-POLICY-DESC";
                match { source-address web-net; destination-address db-net; application junos-http; }
                then { permit; }
            }
        }
    }
}
applications {
    application secret-app {
        description "SECRET-APP-DESC";
        protocol tcp;
        destination-port 8443;
    }
}
interfaces {
    ge-0/0/0 { unit 0 { description "SECRET-IFACE-DESC"; family inet { address 10.0.0.1/24; } } }
    ge-0/0/1 { unit 0 { family inet { address 10.0.1.1/24; } } }
}
`

func complete14708Server(t *testing.T) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(complete14708Config); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	store.ExitConfigure()
	if store.ActiveConfig() == nil {
		t.Fatal("no active config")
	}
	return &Server{store: store}
}

func TestCompleteCrossHierarchyValueHints14708(t *testing.T) {
	s := complete14708Server(t)

	// Non-vacuity controls: the open class receives the live values at the
	// exact cross-hierarchy cursors used below.
	controls := []struct{ line, want string }{
		{"set protocols ospf area 0.0.0.0 interface ", "ge-0/0/0"},
		{"set security policies from-zone trust to-zone untrust policy allow-web match source-address ", "web-net"},
		{"set security policies from-zone trust to-zone untrust policy allow-web match application ", "secret-app"},
	}
	for _, c := range controls {
		resp := doComplete14144(t, s, "open-view", c.line, true)
		if !hasCand14144(resp, c.want) {
			t.Fatalf("control open-view %q: missing %q, got %v (test would be vacuous)", c.line, c.want, resp.Candidates)
		}
	}
	opControl := doComplete14144(t, s, "open-view", "test policy from-zone ", false)
	if !hasCand14144(opControl, "trust") {
		t.Fatalf("control open-view test policy: missing trust, got %v (test would be vacuous)", opControl.Candidates)
	}

	// Arm 1a: deny ^interfaces must conceal interface names/descriptions at
	// a protocols cursor the class may otherwise complete.
	resp := doComplete14144(t, s, "deny-interfaces", "set protocols ospf area 0.0.0.0 interface ", true)
	blob := strings.Join(resp.Candidates, " ") + " " + strings.Join(resp.Descriptions, " ")
	for _, secret := range []string{"ge-0/0/0", "ge-0/0/1", "SECRET-IFACE-DESC"} {
		if strings.Contains(blob, secret) {
			t.Errorf("deny-interfaces at ospf cursor leaked %q: candidates=%v descriptions=%v", secret, resp.Candidates, resp.Descriptions)
		}
	}

	// Arm 1b: deny ^security address-book must conceal address names/CIDRs
	// at a security policies cursor outside the address-book subtree.
	resp = doComplete14144(t, s, "deny-address-book", "set security policies from-zone trust to-zone untrust policy allow-web match source-address ", true)
	blob = strings.Join(resp.Candidates, " ") + " " + strings.Join(resp.Descriptions, " ")
	for _, secret := range []string{"web-net", "db-net", "203.0.113.0/24", "198.51.100.0/24"} {
		if strings.Contains(blob, secret) {
			t.Errorf("deny-address-book at policy cursor leaked %q: candidates=%v descriptions=%v", secret, resp.Candidates, resp.Descriptions)
		}
	}

	// Arm 1c: deny ^applications must conceal application names/descriptions
	// at a security policies application cursor.
	resp = doComplete14144(t, s, "deny-applications", "set security policies from-zone trust to-zone untrust policy allow-web match application ", true)
	blob = strings.Join(resp.Candidates, " ") + " " + strings.Join(resp.Descriptions, " ")
	for _, secret := range []string{"secret-app", "SECRET-APP-DESC"} {
		if strings.Contains(blob, secret) {
			t.Errorf("deny-applications at policy cursor leaked %q: candidates=%v descriptions=%v", secret, resp.Candidates, resp.Descriptions)
		}
	}

	// Arm 2: deny ^security must conceal zone names offered by the
	// operational `test policy from-zone` DynamicFn. The pre-fix gate
	// evaluated "policy from-zone", which the deny never matches.
	resp = doComplete14144(t, s, "deny-security", "test policy from-zone ", false)
	blob = strings.Join(resp.Candidates, " ") + " " + strings.Join(resp.Descriptions, " ")
	for _, secret := range []string{"trust", "untrust"} {
		if strings.Contains(blob, secret) {
			t.Errorf("deny-security at test policy leaked zone %q: candidates=%v descriptions=%v", secret, resp.Candidates, resp.Descriptions)
		}
	}
	resp = doComplete14144(t, s, "deny-security", "test policy from-zone trust to-zone ", false)
	blob = strings.Join(resp.Candidates, " ") + " " + strings.Join(resp.Descriptions, " ")
	for _, secret := range []string{"trust", "untrust"} {
		if strings.Contains(blob, secret) {
			t.Errorf("deny-security at test policy to-zone leaked zone %q: candidates=%v descriptions=%v", secret, resp.Candidates, resp.Descriptions)
		}
	}

	// No over-denial: a class denying only ^interfaces still receives zone
	// names from test policy, and interface completion at an interfaces
	// cursor remains available to a class that does not deny interfaces.
	resp = doComplete14144(t, s, "deny-interfaces-only", "test policy from-zone ", false)
	if !hasCand14144(resp, "trust") {
		t.Errorf("deny-interfaces-only lost test-policy zone completion: %v", resp.Candidates)
	}
	resp = doComplete14144(t, s, "deny-address-book", "set interfaces ", true)
	if !hasCand14144(resp, "ge-0/0/0") {
		t.Errorf("deny-address-book lost non-denied interface completion: %v", resp.Candidates)
	}
	resp = doComplete14144(t, s, "deny-interfaces", "set security zones security-zone ", true)
	if !hasCand14144(resp, "trust") {
		t.Errorf("deny-interfaces lost non-denied zone completion: %v", resp.Candidates)
	}
}
