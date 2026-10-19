package api

import (
	"strings"
	"testing"
)

// #15725: REST show-text (pkg/api/show_text.go) dropped SNMPv3 USM users,
// nested address-set members, dynamic-address bindings & shrink-guard
// state, and (pre-#15649) flow acceleration knobs, while the gRPC ShowText
// renderers carry all of them. This test drives the live REST handler and
// pins the gRPC wording (pkg/grpcapi showSNMP / showAddressBook /
// showDynamicAddress / config.RenderFlowTimeouts) on each topic.
//
// Note on the issue's fixture: its flow legs used the non-existent spelling
// `power-mode-ipsec-disable` and the non-gRPC strings "GRE performance
// acceleration: enabled" / "Power mode IPsec: disabled". The real knob is
// `power-mode-disable` and the shared SSOT wording (which gRPC also uses)
// is asserted instead — rendering the issue's literal strings would
// re-diverge REST from gRPC.
func TestShowTextHandler_ParityWithGRPC15725(t *testing.T) {
	s := stageShowTextConfig(t, []string{
		`set snmp v3 usm local-engine user ops authentication-sha authentication-password "secret123"`,
		"set security address-book global address h1 10.0.0.1/32",
		"set security address-book global address-set s1 address h1",
		"set security address-book global address-set s2 address-set s1",
		"set security dynamic-address feed-server threat url https://feeds.example/threat.txt",
		"set security dynamic-address feed-server threat shrink-guard-min-old-count 128",
		"set security dynamic-address feed-server threat shrink-guard-min-retain-percent 65",
		"set security dynamic-address feed-server threat shrink-guard-min-drop 24",
		"set security dynamic-address address-name badhosts profile feed-name threat",
		"set security flow gre-performance-acceleration",
		"set security flow power-mode-disable",
	})

	for _, tc := range []struct {
		topic string
		want  string
	}{
		{"snmp", "SNMPv3 USM users:\n"},
		{"snmp", "  ops: auth=sha priv=none"},
		{"address-book", "members: set:s1"},
		{"dynamic-address", "  Shrink guard: high-water >= 128 prefixes; refuse candidates below 65% of baseline with a drop of at least 24"},
		{"dynamic-address", "  Content churn guard: installed >= 128 prefixes; refuse below 65% exact-prefix overlap"},
		{"dynamic-address", "Dynamic Address Bindings:\n"},
		{"dynamic-address", "  badhosts: feeds threat, fail-mode retain"},
		{"dynamic-address", "    Enforced: unknown (no runtime feed status)"},
		{"flow-timeouts", "gre-performance-acceleration:"},
		{"flow-timeouts", "#7188"},
		{"flow-timeouts", "power-mode-disable:"},
	} {
		out := renderShowTextBody(t, s, tc.topic)
		if !strings.Contains(out, tc.want) {
			t.Errorf("topic %s missing %q in:\n%s", tc.topic, tc.want, out)
		}
	}

	// The SNMPv3 auth password must never leak through the new USM section
	// (gRPC renders protocols only; the password is config.Secret-typed).
	if out := renderShowTextBody(t, s, "snmp"); strings.Contains(out, "secret123") {
		t.Errorf("snmp topic leaked SNMPv3 auth password:\n%s", out)
	}
}
