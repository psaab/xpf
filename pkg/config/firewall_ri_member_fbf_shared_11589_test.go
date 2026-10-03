package config

import (
	"strings"
	"testing"
)

// #11589: when one filter feeds BOTH a VRF-member unit and a non-member unit,
// lenient suppression must isolate to the member attachment. The authored
// filter stays intact (the non-member steer still installs on every plane);
// only the member attachment is rebound to a stripped synthesized clone.
//
// FAIL-ON-REVERT: restore the global strip (mutating the shared filter's
// terms) and the original-intact + non-member-binding assertions go RED;
// drop the rebind and the member-binding + clone assertions go RED.
func TestMemberFBFSharedFilterSuppressesOnlyMemberAttachment11589(t *testing.T) {
	tree := buildFilterTree(t,
		"set routing-instances member-ri instance-type vrf",
		"set routing-instances member-ri interface ge-0/0/1.0",
		"set routing-instances steer-ri instance-type forwarding",
		"set firewall family inet filter shared-fbf term steer from source-address 192.0.2.0/24",
		"set firewall family inet filter shared-fbf term steer then routing-instance steer-ri",
		"set interfaces ge-0/0/1 unit 0 family inet filter input shared-fbf",
		"set interfaces ge-0/0/2 unit 0 family inet filter input shared-fbf",
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant load must keep the prior config bootable: %v", err)
	}

	// The authored filter is shared with a non-member attachment: it must
	// stay verbatim so the valid non-member steer survives on every plane.
	orig := cfg.Firewall.FiltersInet["shared-fbf"]
	if orig == nil || len(orig.Terms) != 1 {
		t.Fatalf("authored filter shared-fbf missing or mangled: %+v", orig)
	}
	if got := orig.Terms[0]; got.RoutingInstance != "steer-ri" {
		t.Fatalf("shared filter must stay intact for the non-member attachment: got routing-instance %q, want steer-ri", got.RoutingInstance)
	}

	memberUnit := cfg.Interfaces.Interfaces["ge-0/0/1"].Units[0]
	plainUnit := cfg.Interfaces.Interfaces["ge-0/0/2"].Units[0]
	if plainUnit.FilterInputV4 != "shared-fbf" {
		t.Fatalf("non-member unit must keep the authored filter: got %q", plainUnit.FilterInputV4)
	}
	cloneName := memberUnit.FilterInputV4
	if cloneName == "" || cloneName == "shared-fbf" {
		t.Fatalf("member unit must be rebound to a stripped clone: got %q", cloneName)
	}
	clone := cfg.Firewall.FiltersInet[cloneName]
	if clone == nil {
		t.Fatalf("member unit rebound to %q, but no such filter was synthesized", cloneName)
	}
	source, terms := clone.SuppressedMemberFBF11321()
	if source != "shared-fbf" || len(terms) != 1 || terms[0] != "steer" {
		t.Fatalf("clone %q must record its authored filter and suppressed term: source=%q terms=%v",
			cloneName, source, terms)
	}
	if len(clone.Terms) != 1 {
		t.Fatalf("clone %q must carry the same single term: %+v", cloneName, clone.Terms)
	}
	if got := clone.Terms[0]; got.RoutingInstance != "" || got.Action != "accept" {
		t.Fatalf("clone %q must strip the FBF override as terminal accept: got routing-instance %q action %q",
			cloneName, got.RoutingInstance, got.Action)
	}

	found := false
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "#11321") &&
			strings.Contains(warning, `filter "shared-fbf"`) &&
			strings.Contains(warning, `term "steer"`) &&
			strings.Contains(warning, "ge-0/0/1.0") {
			found = true
		}
		if strings.Contains(warning, "#11321") && strings.Contains(warning, "ge-0/0/2.0") {
			t.Fatalf("non-member attachment must not be diagnosed: %q", warning)
		}
	}
	if !found {
		t.Fatalf("tolerant config lacks the member-FBF warning for ge-0/0/1.0: %v", cfg.Warnings)
	}
}

// #11589: the member-only shape keeps the same per-attachment contract — the
// authored filter is never mutated; the member unit moves to the clone.
func TestMemberFBFMemberOnlyAttachmentRebindsToClone11589(t *testing.T) {
	tree := memberFBFTree11321(t, "inet", "vrf")
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant load must keep the prior config bootable: %v", err)
	}
	orig := cfg.Firewall.FiltersInet["member-fbf"]
	if orig == nil || len(orig.Terms) != 1 || orig.Terms[0].RoutingInstance != "steer-ri" {
		t.Fatalf("authored filter must stay intact on the tolerant path: %+v", orig)
	}
	got := cfg.Interfaces.Interfaces["ge-0/0/1"].Units[0].FilterInputV4
	if got == "" || got == "member-fbf" {
		t.Fatalf("member unit must be rebound to a stripped clone: got %q", got)
	}
	clone := cfg.Firewall.FiltersInet[got]
	if clone == nil || len(clone.Terms) != 1 {
		t.Fatalf("stripped clone %q missing: %+v", got, clone)
	}
	if term := clone.Terms[0]; term.RoutingInstance != "" || term.Action != "accept" {
		t.Fatalf("clone %q must strip the FBF override as terminal accept: got routing-instance %q action %q",
			got, term.RoutingInstance, term.Action)
	}
}
