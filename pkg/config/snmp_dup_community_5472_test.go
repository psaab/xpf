package config

import (
	"testing"
)

// #5472 (security, fail-open): compileSNMP built each `community <name>` block
// into a fresh &SNMPCommunity and stored it with a plain map overwrite
// (snmp.Communities[name] = comm) — no same-name merge. Two hierarchical
// `community public { ... }` siblings where the SECOND has no `clients` meant
// the second (empty) entry overwrote the first, dropping its source-IP
// allowlist. AllowsSource treats an empty allowlist as allow-all, so the
// restriction was silently erased and any source could query the community.
//
// The fix MERGES same-name community blocks (accumulate Clients, carry
// authorization) before the immutable client-prefix cache is built, so a later
// block cannot erase an earlier block's allowlist.
//
// RED-on-revert: with the compileSNMP merge reverted (a plain
// snmp.Communities[name] = comm overwrite), the second empty block wins,
// c.Clients is empty, AllowsSource returns allow-all, and the 8.8.8.8 deny
// assertion below flips to true — the test fails.

// TestSNMPDupCommunityEmptySecondBlockKeepsAllowlist is the core RED-on-revert
// proof: block 1 carries the allowlist, block 2 (same name) carries none, and
// the merged community must still enforce block 1's restriction.
func TestSNMPDupCommunityEmptySecondBlockKeepsAllowlist(t *testing.T) {
	c := communityFrom(t, parseHier(t, `
snmp {
    community public {
        authorization read-only;
        clients {
            10.0.0.0/24;
        }
    }
    community public {
        authorization read-only;
    }
}
`), "public")

	if len(c.Clients) == 0 {
		t.Fatalf("merged community lost block-1's clients allowlist: %+v", c.Clients)
	}
	cases := map[string]bool{
		"10.0.0.5": true,  // inside block-1's 10.0.0.0/24 allowlist
		"8.8.8.8":  false, // not allowlisted → must be denied (fail-open guard)
	}
	for src, want := range cases {
		if got := c.AllowsSource(snmpClientTestSource10687(src)); got != want {
			t.Errorf("AllowsSource(%s) = %v, want %v (a later empty duplicate must not erase the allowlist)", src, got, want)
		}
	}
}

// TestSNMPDupCommunityUnionsClients: when BOTH duplicate blocks carry clients,
// the merged allowlist is the union of the two — neither block is dropped.
func TestSNMPDupCommunityUnionsClients(t *testing.T) {
	c := communityFrom(t, parseHier(t, `
snmp {
    community mgmt {
        authorization read-only;
        clients {
            10.1.0.0/16;
        }
    }
    community mgmt {
        clients {
            192.168.5.0/24;
        }
    }
}
`), "mgmt")

	cases := map[string]bool{
		"10.1.2.3":    true,  // block 1 prefix
		"192.168.5.9": true,  // block 2 prefix
		"172.16.0.1":  false, // neither → default-deny
	}
	for src, want := range cases {
		if got := c.AllowsSource(snmpClientTestSource10687(src)); got != want {
			t.Errorf("AllowsSource(%s) = %v, want %v (merged allowlist must be the union)", src, got, want)
		}
	}
}

// TestSNMPDupCommunityAuthorizationNotCleared: a later block that omits
// `authorization` must not downgrade an earlier read-write to the read-only
// default. An explicit later authorization does update.
func TestSNMPDupCommunityAuthorizationNotCleared(t *testing.T) {
	// Block 1 sets read-write; block 2 omits authorization entirely.
	c := communityFrom(t, parseHier(t, `
snmp {
    community rw {
        authorization read-write;
        clients {
            10.0.0.0/24;
        }
    }
    community rw {
        clients {
            10.0.1.0/24;
        }
    }
}
`), "rw")
	if c.Authorization != "read-write" {
		t.Errorf("authorization = %q, want %q (an empty duplicate must not clear an earlier authorization)", c.Authorization, "read-write")
	}

	// An explicit later authorization DOES win (last explicit value).
	c2 := communityFrom(t, parseHier(t, `
snmp {
    community upd {
        authorization read-only;
    }
    community upd {
        authorization read-write;
    }
}
`), "upd")
	if c2.Authorization != "read-write" {
		t.Errorf("authorization = %q, want %q (an explicit later authorization updates)", c2.Authorization, "read-write")
	}
}

// TestSNMPSingleCommunityUnchanged guards against a false merge / behavior
// change on the common single-block case: one community with an allowlist
// still enforces exactly as before.
func TestSNMPSingleCommunityUnchanged(t *testing.T) {
	c := communityFrom(t, parseHier(t, `
snmp {
    community solo {
        authorization read-only;
        clients {
            10.0.0.0/24;
            0.0.0.0/0 restrict;
        }
    }
}
`), "solo")
	if c.Authorization != "read-only" {
		t.Errorf("authorization = %q, want read-only", c.Authorization)
	}
	if len(c.Clients) != 2 {
		t.Fatalf("expected 2 client entries, got %+v", c.Clients)
	}
	if !c.AllowsSource(snmpClientTestSource10687("10.0.0.5")) {
		t.Error("AllowsSource(10.0.0.5) = false, want true (in 10.0.0.0/24)")
	}
	if c.AllowsSource(snmpClientTestSource10687("8.8.8.8")) {
		t.Error("AllowsSource(8.8.8.8) = true, want false (only 0.0.0.0/0 restrict matches)")
	}
}
