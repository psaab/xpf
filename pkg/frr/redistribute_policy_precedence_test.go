package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14369 (DR3-H2): `redistributeEntriesAt` took the bare-protocol branch
// (`knownRedistProtocol`) BEFORE the defined-policy-statement branch, so
// `protocols ospf export static` with a policy-statement named `static`
// rendered a bare, unfiltered `redistribute static` and the policy's
// route-map was dead. The BGP renderer in the same package resolves the
// same token policy-first. Defined-policy must win for every IGP
// redistributor (OSPF/OSPFv3/RIP/IS-IS funnel through
// redistributeEntriesAt); the bare-token reading is kept only when no
// policy-statement of that name is defined.

func keywordNamedPolicy14369(name string) *config.PolicyOptionsConfig {
	return &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			name: {
				Name: name,
				Terms: []*config.PolicyTerm{
					// #14698: an accept term (was reject-only). A
					// reject-only `from protocol` term is a filter,
					// never a redistribution request, so it no longer
					// enrols static; the #14369 precedence property
					// (defined policy wins over the bare token, filtered
					// map not bare line) is exercised identically with
					// a positive term.
					{Name: "accept-good", FromProtocols: []string{"static"}, Action: "accept"},
				},
			},
		},
	}
}

// bareRedistributeStatic14369 reports whether got contains an
// OSPF/RIP-shaped `redistribute static` line with no route-map clause.
func hasBareLine14369(got, bare string) bool {
	for _, ln := range strings.Split(got, "\n") {
		if ln == bare {
			return true
		}
	}
	return false
}

func TestIGPExportPolicyNamedStaticOSPF14369(t *testing.T) {
	fc := &FullConfig{
		PolicyOptions: keywordNamedPolicy14369("static"),
		OSPF: &config.OSPFConfig{
			Areas:  []*config.OSPFArea{{ID: "0.0.0.0"}},
			Export: []string{"static"},
		},
	}
	got := New().buildManagedSection(fc)
	if !strings.Contains(got, "redistribute static route-map static-static-xpf-redist\n") {
		t.Errorf("missing filtered redistribute for policy named static:\n%s", got)
	}
	if hasBareLine14369(got, " redistribute static") {
		t.Errorf("policy named static rendered bare unfiltered redistribute static:\n%s", got)
	}
}

func TestIGPExportPolicyNamedStaticRIP14369(t *testing.T) {
	fc := &FullConfig{
		PolicyOptions: keywordNamedPolicy14369("static"),
		RIP: &config.RIPConfig{
			Redistribute: []string{"static"},
		},
	}
	got := New().buildManagedSection(fc)
	if !strings.Contains(got, "redistribute static route-map static-static-xpf-redist\n") {
		t.Errorf("missing filtered redistribute for policy named static under RIP:\n%s", got)
	}
	if hasBareLine14369(got, " redistribute static") {
		t.Errorf("policy named static rendered bare unfiltered redistribute static under RIP:\n%s", got)
	}
}

func TestIGPExportPolicyNamedStaticISIS14369(t *testing.T) {
	fc := &FullConfig{
		PolicyOptions: keywordNamedPolicy14369("static"),
		ISIS:          &config.ISISConfig{Export: []string{"static"}},
	}
	got := New().buildManagedSection(fc)
	for _, want := range []string{
		"redistribute ipv4 static level-2 route-map static-static-xpf-redist\n",
		"redistribute ipv6 static level-2 route-map static-static-xpf-redist\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q:\n%s", want, got)
		}
	}
	for _, bare := range []string{
		" redistribute ipv4 static level-2",
		" redistribute ipv6 static level-2",
	} {
		if hasBareLine14369(got, bare) {
			t.Errorf("policy named static rendered bare unfiltered %q under IS-IS:\n%s", bare, got)
		}
	}
}

// Negative control: no policy-statement named `static` — the bare-token
// reading is preserved exactly as before.
func TestIGPExportBareStaticNoPolicy14369(t *testing.T) {
	fc := &FullConfig{
		OSPF: &config.OSPFConfig{
			Areas:  []*config.OSPFArea{{ID: "0.0.0.0"}},
			Export: []string{"static"},
		},
	}
	got := New().buildManagedSection(fc)
	if !hasBareLine14369(got, " redistribute static") {
		t.Errorf("bare export static with no such policy must render bare redistribute static:\n%s", got)
	}
	if strings.Contains(got, "static-static-xpf-redist") {
		t.Errorf("no-policy bare token must not gain a route-map:\n%s", got)
	}
}

// A policy literally named `direct` must be honored as a policy: the
// policy lookup uses the raw export name, before the bare-token
// direct->connected normalization.
func TestIGPExportPolicyNamedDirect14369(t *testing.T) {
	m := New()
	got := m.resolveRedistribute("direct", keywordNamedPolicy14369("direct"), "ospf", nil)
	want := " redistribute static route-map direct-static-xpf-redist\n"
	if got != want {
		t.Errorf("policy named direct: got %q, want %q", got, want)
	}
	// Bare-token control: no policy named direct still maps to connected.
	if got := m.resolveRedistribute("direct", nil, "ospf", nil); got != " redistribute connected\n" {
		t.Errorf("bare direct token: got %q, want bare connected", got)
	}
}

// Companion (#14369 spec): with a defined policy named `static`, the QNH
// metric attachment must use the policy arm (policyMaps), not clobber the
// policy route-map with the bare-protocol staticMap.
func TestIGPExportPolicyNamedStaticQNHUsesPolicyMap14369(t *testing.T) {
	m := New()
	metrics := &qnhMetricScope11447{
		staticMap:  "QNH-STATIC-MAP",
		policyMaps: map[string]string{"static": "QNH-POLICY-MAP"},
	}
	entries := m.redistributeEntries("static", keywordNamedPolicy14369("static"), "ospf", metrics)
	if len(entries) != 1 || entries[0].proto != "static" {
		t.Fatalf("policy named static entries = %+v, want one static entry", entries)
	}
	if entries[0].routeMap != "QNH-POLICY-MAP" {
		t.Errorf("defined policy named static must use the QNH policy map, got %q", entries[0].routeMap)
	}
	// Bare-token control: no defined policy keeps the staticMap behavior.
	entries = m.redistributeEntries("static", nil, "ospf", metrics)
	if len(entries) != 1 || entries[0].routeMap != "QNH-STATIC-MAP" {
		t.Errorf("bare static token must use the QNH static map, got %+v", entries)
	}
}
