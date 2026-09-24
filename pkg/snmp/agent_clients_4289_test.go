package snmp

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #4289 (fable-review-167 S-3): an SNMP community scoped with `clients
// <prefix>` must be answered ONLY from a permitted source. Before the fix the
// agent served every source (the restriction was silently ignored — a security
// fail-open). handleV2cPacket now enforces SNMPCommunity.AllowsSource against
// the UDP source before serving.

// A GET from a source inside the community's clients allowlist is served; a GET
// from a source outside it is dropped (nil response, as with an unknown
// community). RED-on-revert: without the source check, the outside-source GET
// is answered — the enforcement is gone.
func TestV2cCommunityClientsSourceEnforced(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"scoped": {
				Name:          "scoped",
				Authorization: "read-only",
				Clients: []config.SNMPClient{
					{Prefix: "10.0.0.0/24"},
				},
			},
		},
	})

	pkt := buildV2cGetRequest("scoped", 1, oidSysDescr)

	// Permitted source (inside 10.0.0.0/24): served.
	if resp := a.handlePacketFrom(pkt, snmpSource10687("10.0.0.9")); resp == nil {
		t.Fatal("GET from a permitted source (10.0.0.9 in 10.0.0.0/24) was dropped; want a response")
	}

	// Non-permitted source (outside the allowlist): dropped.
	if resp := a.handlePacketFrom(pkt, snmpSource10687("192.0.2.5")); resp != nil {
		t.Fatal("GET from a non-permitted source (192.0.2.5, not in 10.0.0.0/24) was answered; want no response (fail-open)")
	}
}

// A community with NO clients is allow-all (Junos default) — any source is
// served. The enforcement must not break the common unscoped community.
func TestV2cCommunityNoClientsAllowAll(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"public": {Name: "public", Authorization: "read-only"},
		},
	})

	pkt := buildV2cGetRequest("public", 2, oidSysDescr)
	for _, src := range []string{"10.0.0.9", "192.0.2.5", "203.0.113.7"} {
		if resp := a.handlePacketFrom(pkt, snmpSource10687(src)); resp == nil {
			t.Fatalf("GET from %s to an unscoped (allow-all) community was dropped; want a response", src)
		}
	}
}

// The `restrict` deny modifier: a source matched by a restrict entry (longest
// prefix) is denied even though a broader allow entry would otherwise permit it.
func TestV2cCommunityClientsRestrictDenies(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"mgmt": {
				Name:          "mgmt",
				Authorization: "read-only",
				Clients: []config.SNMPClient{
					{Prefix: "10.1.0.0/16"},
					{Prefix: "10.1.2.0/24", Restrict: true},
				},
			},
		},
	})

	pkt := buildV2cGetRequest("mgmt", 3, oidSysDescr)

	if resp := a.handlePacketFrom(pkt, snmpSource10687("10.1.5.1")); resp == nil {
		t.Fatal("GET from 10.1.5.1 (allowed by 10.1.0.0/16) was dropped; want a response")
	}
	if resp := a.handlePacketFrom(pkt, snmpSource10687("10.1.2.9")); resp != nil {
		t.Fatal("GET from 10.1.2.9 (restricted by 10.1.2.0/24) was answered; want no response")
	}
}
