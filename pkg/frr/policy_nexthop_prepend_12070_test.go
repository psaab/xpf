package frr

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12070 RED-before: a leniently-loaded / peer-synced `then next-hop`
// carrying a Junos-only keyword or a malformed literal must be omitted
// (fail-closed) — never rendered as a reload-poisoning `set` line. Valid
// literals and the rendered keywords keep their exact lines.
func TestPolicyThenNextHop_InvalidOmitted_12070(t *testing.T) {
	m := &Manager{frrConf: "/dev/null"}
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {
				Name: "P",
				Terms: []*config.PolicyTerm{
					{Name: "t_discard", NextHop: "discard", Action: "accept"},
					{Name: "t_reject", NextHop: "reject", Action: "accept"},
					{Name: "t_table", NextHop: "next-table", Action: "accept"},
					{Name: "t_not_ip", NextHop: "not-an-ip", Action: "accept"},
					{Name: "t_badip", NextHop: "10.0.0.300", Action: "accept"},
					{Name: "t_bad6", NextHop: "2001:db8::garbage", Action: "accept"},
					{Name: "t4", NextHop: "192.0.2.1", Action: "accept"},
					{Name: "t6", NextHop: "2001:db8::1", Action: "accept"},
					{Name: "t_peer", NextHop: "peer-address", Action: "accept"},
					{Name: "t_self", NextHop: "self", Action: "accept"},
				},
			},
		},
	}
	var logs strings.Builder
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	got := m.generatePolicyOptions(po)
	for _, bad := range []string{
		"set ip next-hop discard", "set ip next-hop reject", "set ip next-hop next-table",
		"set ip next-hop not-an-ip", "set ip next-hop 10.0.0.300",
		"set ipv6 next-hop global 2001:db8::garbage",
	} {
		if strings.Contains(got, bad) {
			t.Errorf("renderer emitted invalid %q; output:\n%s", bad, got)
		}
	}
	for _, want := range []string{
		" set ip next-hop 192.0.2.1\n",
		" set ipv6 next-hop global 2001:db8::1\n",
		" set ip next-hop peer-address\n",
		" set ipv6 next-hop peer-address\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("renderer dropped valid %q; output:\n%s", want, got)
		}
	}
	for _, want := range []string{
		"omitting invalid then next-hop", "discard", "reject", "next-table",
		"not-an-ip", "10.0.0.300", "2001:db8::garbage",
	} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("render warnings %q do not include %q", logs.String(), want)
		}
	}
}

// #12070 RED-before: a leniently-loaded `then as-path-prepend` carrying a
// non-ASN token must be omitted (fail-closed) — never rendered as
// `set as-path prepend 65001 abc`. A fully-valid list keeps its exact
// line, and sibling set clauses on the same term still render.
func TestPolicyThenASPathPrepend_InvalidOmitted_12070(t *testing.T) {
	m := &Manager{frrConf: "/dev/null"}
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {
				Name: "P",
				Terms: []*config.PolicyTerm{
					{Name: "t_bad", ASPathPrepend: []string{"65001", "abc"}, LocalPreference: 100, HasLocalPreference: true, Action: "accept"},
					{Name: "t_zero", ASPathPrepend: []string{"0"}, Action: "accept"},
					{Name: "t_overflow", ASPathPrepend: []string{"4294967296"}, Action: "accept"},
					{Name: "t_good", ASPathPrepend: []string{"65001", "65001"}, Action: "accept"},
				},
			},
		},
	}
	var logs strings.Builder
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	got := m.generatePolicyOptions(po)
	for _, bad := range []string{
		"set as-path prepend 65001 abc", "set as-path prepend 0",
		"set as-path prepend 4294967296",
	} {
		if strings.Contains(got, bad) {
			t.Errorf("renderer emitted invalid %q; output:\n%s", bad, got)
		}
	}
	if !strings.Contains(got, " set as-path prepend 65001 65001\n") {
		t.Errorf("renderer dropped the valid prepend line; output:\n%s", got)
	}
	// The t_bad term's sibling clause must survive the omission.
	if !strings.Contains(got, " set local-preference 100\n") {
		t.Errorf("renderer dropped the sibling local-preference clause while omitting the bad prepend; output:\n%s", got)
	}
	for _, want := range []string{"omitting invalid then as-path-prepend", "abc", "0", "4294967296"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("render warnings %q do not include %q", logs.String(), want)
		}
	}
}
