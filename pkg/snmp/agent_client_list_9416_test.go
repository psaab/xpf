package snmp

import (
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #9416 ON THE WIRE. The compile-side cells prove the named client-list
// resolves; this one drives a real v2c GET through the agent, because "the
// allowlist compiled" and "the agent refuses the query" are different claims,
// and #4289 exists precisely because the second did not follow from the first.
//
// The config goes through `configstore.CheckText` rather than being hand-built,
// so the resolution the agent depends on is exercised end to end. A hand-built
// `SNMPCommunity{Clients: ...}` would test the enforcement path #4289 already
// pins and say nothing about whether a named list ever reaches it.
//
// Every deny is scored against a PERMITTED control in the same run: a dropped
// packet and a broken fixture are the same observation (both are "no
// response"), so a deny row alone cannot distinguish "the firewall refused it"
// from "my request was never valid".
func agentFromText9416(t *testing.T, text string) *Agent {
	t.Helper()
	cfg, err := configstore.CheckText(text, -1)
	if err != nil {
		t.Fatalf("CheckText: %v\nconfig:\n%s", err, text)
	}
	if cfg.System.SNMP == nil {
		t.Fatalf("no SNMP stanza compiled from:\n%s", text)
	}
	return NewAgent(cfg.System.SNMP)
}

func TestV2cNamedClientListSourceEnforced9416(t *testing.T) {
	a := agentFromText9416(t, `system { host-name fw; }
snmp {
    client-list trusted { 10.0.0.0/24; }
    community scoped { authorization read-only; client-list-name trusted; }
}
`)
	pkt := buildV2cGetRequest("scoped", 1, oidSysDescr)

	// POSITIVE CONTROL, same address family, same run: a listed source IS
	// served. Without it the deny below is unreadable — an agent that answers
	// nothing at all would pass a deny-only assertion.
	if resp := a.handlePacketFrom(pkt, snmpSource10687("10.0.0.9")); resp == nil {
		t.Fatal("CONTROL: a GET from a source the named list ADMITS (10.0.0.9 in 10.0.0.0/24) was " +
			"dropped. The denial below cannot be interpreted without this")
	}
	// UNDER TEST: an unlisted source is refused. Before #9416 the named list
	// compiled to nothing, the community had an empty allowlist, and
	// AllowsSource read that as allow-all — so this GET was ANSWERED.
	if resp := a.handlePacketFrom(pkt, snmpSource10687("192.0.2.5")); resp != nil {
		t.Fatal("#9416: a GET from 192.0.2.5 — outside the client-list the operator named — was " +
			"ANSWERED. The named spelling of the source restriction is failing open on the wire")
	}
}

// `restrict` inside a NAMED list reaches the wire with the same longest-prefix
// deny semantics it has inline.
func TestV2cNamedClientListRestrictDenies9416(t *testing.T) {
	a := agentFromText9416(t, `system { host-name fw; }
snmp {
    client-list mgmt { 10.1.0.0/16; 10.1.2.0/24 restrict; }
    community scoped { authorization read-only; client-list-name mgmt; }
}
`)
	pkt := buildV2cGetRequest("scoped", 2, oidSysDescr)

	if resp := a.handlePacketFrom(pkt, snmpSource10687("10.1.3.7")); resp == nil {
		t.Fatal("CONTROL: 10.1.3.7 is inside the /16 allow and outside the restricted /24 — it must be served")
	}
	if resp := a.handlePacketFrom(pkt, snmpSource10687("10.1.2.7")); resp != nil {
		t.Fatal("#9416: 10.1.2.7 is inside the `restrict` /24, which is longer-prefix than the /16 allow — " +
			"it must be refused. A named list that drops `restrict` degrades a deny-except entry into an " +
			"unrestricted allow for every community referencing it")
	}
}

// The SIXTH spelling on the wire: a routing-instance-scoped restriction.
func TestV2cRoutingInstanceScopedRestrictionEnforced9416(t *testing.T) {
	a := agentFromText9416(t, `system { host-name fw; }
snmp {
    community scoped { authorization read-only; routing-instance ri1 { clients 10.0.0.0/24; } }
}
`)
	pkt := buildV2cGetRequest("scoped", 3, oidSysDescr)

	if resp := a.handlePacketFrom(pkt, snmpSource10687("10.0.0.9")); resp == nil {
		t.Fatal("CONTROL: a listed source must be served")
	}
	if resp := a.handlePacketFrom(pkt, snmpSource10687("192.0.2.5")); resp != nil {
		t.Fatal("#9416: a restriction written inside a `routing-instance` block was ignored on the wire. " +
			"xpf cannot honour the SCOPING (one socket, default instance) and says so at commit — but " +
			"dropping the restriction entirely turns a narrowing into an allow-all")
	}
}

// The community with NO restriction is still allow-all. This is the row that
// keeps every deny above from being satisfied by an agent that refuses
// everything, and it is driven through the same compile path.
func TestV2cNoRestrictionStillAllowAll9416(t *testing.T) {
	a := agentFromText9416(t, `system { host-name fw; }
snmp { community open { authorization read-only; } }
`)
	pkt := buildV2cGetRequest("open", 4, oidSysDescr)
	for _, src := range []string{"10.0.0.9", "192.0.2.5", "203.0.113.7"} {
		if resp := a.handlePacketFrom(pkt, snmpSource10687(src)); resp == nil {
			t.Fatalf("CONTROL: an unscoped community must answer %s — allow-all is the correct Junos "+
				"default with no restriction authored, and a fix that closed it would be an availability "+
				"regression wearing the shape of a security fix", src)
		}
	}
}
