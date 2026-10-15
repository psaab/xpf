package config

import "testing"

// #13218 (D3-12): SetPath on a `groups` body whose dhcpv6-client (or
// forwarding-options sampling) stanza is a compact elided leaf must not
// destroy the packed statement it braces. braceCompactStatement12508 used
// to wrap the whole packed tail in ONE IsLeaf child
// (Keys=[update-router-advertisement interface ge-0/0/1.0]), so
// packedBody saw len(Keys)==1 on the braced dhcpv6-client and compiled
// UpdateRAInterface="". The braced form must expand the tail through the
// container schema into the nested shape the parser would have produced.

func TestSetPathGroupCompactDHCPv6ClientPreservesUpdateRA(t *testing.T) {
	input := `groups { g1 { interfaces { ge-0/0/0 { unit 0 { family inet6 {
		dhcpv6-client update-router-advertisement interface ge-0/0/1.0;
	} } } } } }
	interfaces { ge-0/0/0 { unit 0 { family inet6 { address 2001:db8::1/64; } } } }
	apply-groups g1;`
	tree := tree12714(t, input)
	if got := dhcpv6Client12714(compileTree12714(t, tree)); got == nil || got.UpdateRAInterface != "ge-0/0/1.0" {
		t.Fatalf("precondition UpdateRAInterface = %+v, want ge-0/0/1.0", got)
	}
	must12714(t, tree.SetPath([]string{
		"groups", "g1", "interfaces", "ge-0/0/0", "unit", "0", "family", "inet6",
		"dhcpv6-client", "client-type", "stateful",
	}))
	got := dhcpv6Client12714(compileTree12714(t, tree))
	if got == nil {
		t.Fatal("after group set: DHCPv6Client is nil")
	}
	if got.UpdateRAInterface != "ge-0/0/1.0" {
		t.Errorf("after group set UpdateRAInterface = %q, want ge-0/0/1.0 (compact statement must survive bracing)", got.UpdateRAInterface)
	}
	if got.ClientType != "stateful" {
		t.Errorf("after group set ClientType = %q, want stateful", got.ClientType)
	}
}

func TestSetPathGroupCompactDHCPv6ClientPreservesPrefixDelegating(t *testing.T) {
	input := `groups { g1 { interfaces { ge-0/0/0 { unit 0 { family inet6 {
		dhcpv6-client prefix-delegating preferred-prefix-length 48;
	} } } } } }
	interfaces { ge-0/0/0 { unit 0 { family inet6 { address 2001:db8::1/64; } } } }
	apply-groups g1;`
	tree := tree12714(t, input)
	if got := dhcpv6Client12714(compileTree12714(t, tree)); got == nil || got.PrefixDelegatingPrefixLen != 48 {
		t.Fatalf("precondition PrefixDelegatingPrefixLen = %+v, want 48", got)
	}
	must12714(t, tree.SetPath([]string{
		"groups", "g1", "interfaces", "ge-0/0/0", "unit", "0", "family", "inet6",
		"dhcpv6-client", "client-type", "stateful",
	}))
	got := dhcpv6Client12714(compileTree12714(t, tree))
	if got == nil {
		t.Fatal("after group set: DHCPv6Client is nil")
	}
	if got.PrefixDelegatingPrefixLen != 48 {
		t.Errorf("after group set PrefixDelegatingPrefixLen = %d, want 48", got.PrefixDelegatingPrefixLen)
	}
	if got.ClientType != "stateful" {
		t.Errorf("after group set ClientType = %q, want stateful", got.ClientType)
	}
}

func TestSetPathGroupCompactSamplingPreservesInstance(t *testing.T) {
	input := `groups { g1 { forwarding-options {
		sampling instance i1 input rate 100;
	} } }
	apply-groups g1;`
	tree := tree12714(t, input)
	if got := samplingInstance12714(compileTree12714(t, tree), "i1"); got == nil || got.InputRate != 100 {
		t.Fatalf("precondition i1 = %+v, want rate 100", got)
	}
	must12714(t, tree.SetPath([]string{
		"groups", "g1", "forwarding-options", "sampling", "instance", "i2", "input", "rate", "200",
	}))
	cfg := compileTree12714(t, tree)
	if got := samplingInstance12714(cfg, "i1"); got == nil || got.InputRate != 100 {
		t.Errorf("after group set i1 = %+v, want rate 100 (compact instance must survive bracing)", got)
	}
	if got := samplingInstance12714(cfg, "i2"); got == nil || got.InputRate != 200 {
		t.Errorf("after group set i2 = %+v, want rate 200", got)
	}
}

func TestSetPathCompactDHCPv6ClientPreservesUpdateRA(t *testing.T) {
	// Same loss outside groups (last-wins selection, non-group path).
	input := `interfaces { ge-0/0/0 { unit 0 { family inet6 {
		dhcpv6-client update-router-advertisement interface ge-0/0/1.0;
	} } } }`
	tree := tree12714(t, input)
	if got := dhcpv6Client12714(compileTree12714(t, tree)); got == nil || got.UpdateRAInterface != "ge-0/0/1.0" {
		t.Fatalf("precondition UpdateRAInterface = %+v, want ge-0/0/1.0", got)
	}
	must12714(t, tree.SetPath([]string{
		"interfaces", "ge-0/0/0", "unit", "0", "family", "inet6",
		"dhcpv6-client", "client-type", "stateful",
	}))
	got := dhcpv6Client12714(compileTree12714(t, tree))
	if got == nil || got.UpdateRAInterface != "ge-0/0/1.0" || got.ClientType != "stateful" {
		t.Errorf("after set = %+v, want UpdateRAInterface ge-0/0/1.0 and ClientType stateful", got)
	}
}

// Nil-guard half of D3-12: deepRepeatedSiblingSchema12761 dereferenced
// schemaForwardingOptions without the nil guard its twin
// editorRepeatedSiblingSchema12714 has. With the variable nil (the
// zero-value state before schema init in any future/embedder context),
// the old code panics; the guard must make it return false.
func TestDeepRepeatedSiblingSchemaNilForwardingOptions13218(t *testing.T) {
	saved := schemaForwardingOptions
	schemaForwardingOptions = nil
	defer func() { schemaForwardingOptions = saved }()
	if deepRepeatedSiblingSchema12761(nil) {
		t.Error("deepRepeatedSiblingSchema12761(nil) = true with nil schemaForwardingOptions, want false")
	}
	if editorRepeatedSiblingSchema12714(nil) {
		t.Error("editorRepeatedSiblingSchema12714(nil) = true, want false")
	}
}
