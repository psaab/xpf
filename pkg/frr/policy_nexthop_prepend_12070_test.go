package frr

import (
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
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
					{Name: "t_zero4", NextHop: "0.0.0.0", Action: "accept"},
					{Name: "t_zero4prefix", NextHop: "0.1.2.3", Action: "accept"},
					{Name: "t_loopback4", NextHop: "127.0.0.1", Action: "accept"},
					{Name: "t_zero6", NextHop: "::", Action: "accept"},
					{Name: "t_loopback6", NextHop: "::1", Action: "accept"},
					{Name: "t_linklocal6", NextHop: "fe80::1", Action: "accept"},
					{Name: "t_multicast6", NextHop: "ff02::1", Action: "accept"},
					{Name: "t_multicast4", NextHop: "224.0.0.1", Action: "accept"},
					{Name: "t_valid_linklocal4", NextHop: "169.254.1.1", Action: "accept"},
					{Name: "t_valid_v4_reserved", NextHop: "240.0.0.1", Action: "accept"},
					{Name: "t_valid_v4_broadcast", NextHop: "255.255.255.255", Action: "accept"},
					{Name: "t_valid_mapped6", NextHop: "::ffff:192.0.2.1", Action: "accept"},
					{Name: "t4", NextHop: "192.0.2.1", Action: "accept"},
					{Name: "t6", NextHop: "2001:db8::1", Action: "accept"},
					{Name: "t_peer", NextHop: "peer-address", Action: "accept"},
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
		"set ipv6 next-hop global 2001:db8::garbage", "set ip next-hop 0.0.0.0",
		"set ip next-hop 0.1.2.3", "set ip next-hop 127.0.0.1",
		"set ipv6 next-hop global ::\n", "set ipv6 next-hop global ::1",
		"set ipv6 next-hop global fe80::1", "set ipv6 next-hop global ff02::1",
		"set ip next-hop 224.0.0.1",
	} {
		if strings.Contains(got, bad) {
			t.Errorf("renderer emitted invalid %q; output:\n%s", bad, got)
		}
	}
	for _, want := range []string{
		" set ip next-hop 192.0.2.1\n",
		" set ipv6 next-hop global 2001:db8::1\n",
		" set ip next-hop 169.254.1.1\n",
		" set ip next-hop 240.0.0.1\n",
		" set ip next-hop 255.255.255.255\n",
		" set ipv6 next-hop global ::ffff:192.0.2.1\n",
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

func TestPolicyThenNextHopSelfRenders_12070(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {
				Name: "P",
				Terms: []*config.PolicyTerm{
					{Name: "t_self", NextHop: "self", Action: "accept"},
				},
			},
		},
	}
	got := (&Manager{frrConf: "/dev/null"}).generatePolicyOptions(po)
	for _, want := range []string{
		" set ip next-hop peer-address\n",
		" set ipv6 next-hop peer-address\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("then next-hop self did not render %q; output:\n%s", want, got)
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
					{Name: "t_leading_zero", ASPathPrepend: []string{"065001"}, Action: "accept"},
					{Name: "t_leading_zero2", ASPathPrepend: []string{"00001"}, Action: "accept"},
					{Name: "t_asdot", ASPathPrepend: []string{"1.10"}, Action: "accept"},
					{Name: "t_second_bad", ASPathPrepend: []string{"65001", "bad"}, Action: "accept"},
					{Name: "t_good", ASPathPrepend: []string{"65001", "65001"}, Action: "accept"},
					{Name: "t_unparsed_quoted", ASPathPrepend: []string{"65100 65100"}, Action: "accept"},
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
		"set as-path prepend 4294967296", "set as-path prepend 065001",
		"set as-path prepend 00001", "set as-path prepend 1.10",
		"set as-path prepend 65001 bad",
	} {
		if strings.Contains(got, bad) {
			t.Errorf("renderer emitted invalid %q; output:\n%s", bad, got)
		}
	}
	if !strings.Contains(got, " set as-path prepend 65001 65001\n") {
		t.Errorf("renderer dropped the valid prepend line; output:\n%s", got)
	}
	if !strings.Contains(got, " set as-path prepend 65100 65100\n") {
		t.Errorf("renderer did not split a quoted multi-ASN value; output:\n%s", got)
	}
	// The t_bad term's sibling clause must survive the omission.
	if !strings.Contains(got, " set local-preference 100\n") {
		t.Errorf("renderer dropped the sibling local-preference clause while omitting the bad prepend; output:\n%s", got)
	}
	for _, want := range []string{
		"omitting invalid then as-path-prepend",
		`value="65001 abc"`, "value=0", "value=4294967296", "value=065001",
		"value=00001", "value=1.10", `value="65001 bad"`,
	} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("render warnings %q do not include %q", logs.String(), want)
		}
	}
}

func TestPolicyThenASPathPrependQuotedCommitCheckRenders_12070(t *testing.T) {
	for _, tc := range []struct{ name, text string }{
		{
			"hierarchical",
			`policy-options {
    policy-statement P {
        term t1 {
            from { protocol bgp; }
            then {
                as-path-prepend "65001 65001";
                accept;
            }
        }
    }
}`,
		},
		{
			"flat-set",
			`set policy-options policy-statement P term t1 from protocol bgp
set policy-options policy-statement P term t1 then as-path-prepend "65001 65001"
set policy-options policy-statement P term t1 then accept`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			compiled, err := configstore.CheckText(tc.text, -1)
			if err != nil {
				t.Fatalf("commit-check rejected documented quoted prepend syntax: %v", err)
			}
			term := compiled.PolicyOptions.PolicyStatements["P"].Terms[0]
			if len(term.ASPathPrepend) != 2 || term.ASPathPrepend[0] != "65001" || term.ASPathPrepend[1] != "65001" {
				t.Fatalf("CheckText ASPathPrepend = %q, want [65001 65001]", term.ASPathPrepend)
			}
			got := (&Manager{frrConf: "/dev/null"}).generatePolicyOptions(&compiled.PolicyOptions)
			if !strings.Contains(got, " set as-path prepend 65001 65001\n") {
				t.Fatalf("quoted prepend did not render as two ASN operands; output:\n%s", got)
			}
		})
	}
}

func TestPolicyThenASPathPrependQuotedOperatorCommitCheckRenders_12070(t *testing.T) {
	store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("create config store: %v", err)
	}
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, input := range []string{
		`policy-options policy-statement P term t1 from protocol bgp`,
		`policy-options policy-statement P term t1 then as-path-prepend "65001 65001"`,
		`policy-options policy-statement P term t1 then accept`,
	} {
		if err := store.SetFromInputAs("", input); err != nil {
			t.Fatalf("SetFromInputAs(%q): %v", input, err)
		}
	}
	compiled, err := store.CommitCheck()
	if err != nil {
		t.Fatalf("Store.CommitCheck rejected quoted prepend operator input: %v", err)
	}
	term := compiled.PolicyOptions.PolicyStatements["P"].Terms[0]
	if len(term.ASPathPrepend) != 2 || term.ASPathPrepend[0] != "65001" || term.ASPathPrepend[1] != "65001" {
		t.Fatalf("CommitCheck ASPathPrepend = %q, want [65001 65001]", term.ASPathPrepend)
	}
	got := (&Manager{frrConf: "/dev/null"}).generatePolicyOptions(&compiled.PolicyOptions)
	if !strings.Contains(got, " set as-path prepend 65001 65001\n") {
		t.Fatalf("committed quoted prepend did not render as two ASN operands; output:\n%s", got)
	}
}
