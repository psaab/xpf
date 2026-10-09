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

func TestPolicyThenFlatRunInvalidOperandsRejected_12070(t *testing.T) {
	for _, tc := range []struct {
		name, command, leaf, value string
	}{
		{
			name:    "unsupported next-hop",
			command: "policy-options policy-statement P term t then accept next-hop discard",
			leaf:    "next-hop",
			value:   "discard",
		},
		{
			name:    "malformed next-hop",
			command: "policy-options policy-statement P term t then accept next-hop 10.0.0.300",
			leaf:    "next-hop",
			value:   "10.0.0.300",
		},
		{
			name:    "invalid prepend operand",
			command: "policy-options policy-statement P term t then accept as-path-prepend 65001 abc",
			leaf:    "as-path-prepend",
			value:   "abc",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkError := func(err error) {
				t.Helper()
				if err == nil {
					t.Fatal("commit-check accepted invalid flat-run operand")
				}
				const wantPath = "policy-options policy-statement P term t "
				if !strings.Contains(err.Error(), wantPath) {
					t.Errorf("commit-check error %q does not name policy and term via %q", err, wantPath)
				}
				for _, want := range []string{tc.leaf, tc.value} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("commit-check error %q does not name %q", err, want)
					}
				}
			}

			if _, err := configstore.CheckText("set "+tc.command, -1); err == nil {
				t.Fatal("CheckText accepted invalid flat-run operand")
			} else {
				checkError(err)
			}

			store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
			if err != nil {
				t.Fatalf("create config store: %v", err)
			}
			if err := store.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			if err := store.SetFromInputAs("", tc.command); err != nil {
				t.Fatalf("SetFromInputAs(%q): %v", tc.command, err)
			}
			_, err = store.CommitCheck()
			checkError(err)
		})
	}
}

func TestPolicyThenFlatRunValidControlsCommitAndRender_12070(t *testing.T) {
	for _, tc := range []struct {
		name, command, rendered string
		check                   func(*testing.T, *config.PolicyTerm)
	}{
		{
			name:     "next-hop after accept",
			command:  "policy-options policy-statement P term t then accept next-hop 192.0.2.1",
			rendered: " set ip next-hop 192.0.2.1\n",
			check: func(t *testing.T, term *config.PolicyTerm) {
				if term.Action != "accept" || term.NextHop != "192.0.2.1" {
					t.Fatalf("compiled term = %+v, want accept with next-hop 192.0.2.1", term)
				}
			},
		},
		{
			name:     "prepend after accept",
			command:  `policy-options policy-statement P term t then accept as-path-prepend "65001 65001"`,
			rendered: " set as-path prepend 65001 65001\n",
			check: func(t *testing.T, term *config.PolicyTerm) {
				if term.Action != "accept" || strings.Join(term.ASPathPrepend, " ") != "65001 65001" {
					t.Fatalf("compiled term = %+v, want accept with prepend [65001 65001]", term)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertCompiled := func(t *testing.T, compiled *config.Config) {
				t.Helper()
				term := compiled.PolicyOptions.PolicyStatements["P"].Terms[0]
				tc.check(t, term)
				got := (&Manager{frrConf: "/dev/null"}).generatePolicyOptions(&compiled.PolicyOptions)
				if !strings.Contains(got, tc.rendered) {
					t.Fatalf("flat-run clause did not render; output:\n%s", got)
				}
			}

			compiled, err := configstore.CheckText("set "+tc.command, -1)
			if err != nil {
				t.Fatalf("CheckText rejected valid flat-run input: %v", err)
			}
			assertCompiled(t, compiled)

			store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
			if err != nil {
				t.Fatalf("create config store: %v", err)
			}
			if err := store.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			if err := store.SetFromInputAs("", tc.command); err != nil {
				t.Fatalf("SetFromInputAs(%q): %v", tc.command, err)
			}
			compiled, err = store.CommitCheck()
			if err != nil {
				t.Fatalf("Store.CommitCheck rejected valid flat-run input: %v", err)
			}
			assertCompiled(t, compiled)
		})
	}
}

func TestPolicyThenCompactAndTermLineOperandsRejected_12070(t *testing.T) {
	for _, tc := range []struct {
		name, text, leaf, value, wantMessage string
	}{
		{
			name:  "compact unsupported next-hop",
			text:  "policy-options { policy-statement P { term t { then accept next-hop discard; } } }",
			leaf:  "next-hop",
			value: "discard",
		},
		{
			name:  "compact malformed next-hop",
			text:  "policy-options { policy-statement P { term t { then accept next-hop 10.0.0.300; } } }",
			leaf:  "next-hop",
			value: "10.0.0.300",
		},
		{
			name:  "compact invalid prepend",
			text:  "policy-options { policy-statement P { term t { then accept as-path-prepend 65001 abc; } } }",
			leaf:  "as-path-prepend",
			value: "abc",
		},
		{
			name:  "term-line unsupported next-hop",
			text:  "policy-options { policy-statement P { term t then accept next-hop discard; } }",
			leaf:  "next-hop",
			value: "discard",
		},
		{
			name:  "term-line malformed next-hop",
			text:  "policy-options { policy-statement P { term t then accept next-hop 10.0.0.300; } }",
			leaf:  "next-hop",
			value: "10.0.0.300",
		},
		{
			name:  "term-line invalid prepend",
			text:  "policy-options { policy-statement P { term t then accept as-path-prepend 65001 abc; } }",
			leaf:  "as-path-prepend",
			value: "abc",
		},
		{
			name:  "compact quoted invalid prepend",
			text:  `policy-options { policy-statement P { term t { then accept as-path-prepend "65001 abc"; } } }`,
			leaf:  "as-path-prepend",
			value: "abc",
		},
		{
			name:  "term-line quoted invalid prepend",
			text:  `policy-options { policy-statement P { term t then accept as-path-prepend "65001 abc"; } }`,
			leaf:  "as-path-prepend",
			value: "abc",
		},
		{
			name:        "compact empty next-hop",
			text:        `policy-options { policy-statement P { term t { then accept next-hop ""; } } }`,
			leaf:        "next-hop",
			wantMessage: `invalid value ""`,
		},
		{
			name:        "term-line empty next-hop",
			text:        `policy-options { policy-statement P { term t then accept next-hop ""; } }`,
			leaf:        "next-hop",
			wantMessage: `invalid value ""`,
		},
		{
			name:        "compact whitespace-only prepend",
			text:        `policy-options { policy-statement P { term t { then accept as-path-prepend " "; } } }`,
			leaf:        "as-path-prepend",
			wantMessage: `invalid value " "`,
		},
		{
			name:        "term-line whitespace-only prepend",
			text:        `policy-options { policy-statement P { term t then accept as-path-prepend " "; } }`,
			leaf:        "as-path-prepend",
			wantMessage: `invalid value " "`,
		},
		{
			name:        "compact empty prepend list",
			text:        `policy-options { policy-statement P { term t { then accept as-path-prepend [ ]; } } }`,
			leaf:        "as-path-prepend",
			wantMessage: `invalid value ""`,
		},
		{
			name:        "term-line empty prepend list",
			text:        `policy-options { policy-statement P { term t then accept as-path-prepend [ ]; } }`,
			leaf:        "as-path-prepend",
			wantMessage: `invalid value ""`,
		},
		{
			name:        "compact bracketed whitespace prepend",
			text:        `policy-options { policy-statement P { term t { then accept as-path-prepend [ " " ]; } } }`,
			leaf:        "as-path-prepend",
			wantMessage: `invalid value " "`,
		},
		{
			name:        "term-line bracketed whitespace prepend",
			text:        `policy-options { policy-statement P { term t then accept as-path-prepend [ " " ]; } }`,
			leaf:        "as-path-prepend",
			wantMessage: `invalid value " "`,
		},
		{
			name:        "compact keyword-valued prepend tag",
			text:        `policy-options { policy-statement P { term t { then accept as-path-prepend tag; } } }`,
			leaf:        "as-path-prepend",
			value:       "tag",
			wantMessage: `invalid value "tag"`,
		},
		{
			name:        "term-line keyword-valued prepend tag",
			text:        `policy-options { policy-statement P { term t then accept as-path-prepend tag; } }`,
			leaf:        "as-path-prepend",
			value:       "tag",
			wantMessage: `invalid value "tag"`,
		},
		{
			name:        "compact keyword-valued prepend area",
			text:        `policy-options { policy-statement P { term t { then accept as-path-prepend area; } } }`,
			leaf:        "as-path-prepend",
			value:       "area",
			wantMessage: `invalid value "area"`,
		},
		{
			name:        "term-line keyword-valued prepend area",
			text:        `policy-options { policy-statement P { term t then accept as-path-prepend area; } }`,
			leaf:        "as-path-prepend",
			value:       "area",
			wantMessage: `invalid value "area"`,
		},
		{
			name:  "compact loopback next-hop",
			text:  "policy-options { policy-statement P { term t { then accept next-hop 127.0.0.1; } } }",
			leaf:  "next-hop",
			value: "127.0.0.1",
		},
		{
			name:  "compact chained local-preference next-hop",
			text:  "policy-options { policy-statement P { term t { then accept local-preference 200 next-hop discard; } } }",
			leaf:  "next-hop",
			value: "discard",
		},
		{
			name:  "compact chained next-policy next-hop",
			text:  "policy-options { policy-statement P { term t { then next policy next-hop discard; } } }",
			leaf:  "next-hop",
			value: "discard",
		},
		{
			name:  "compact reject chained next-hop",
			text:  "policy-options { policy-statement P { term t { then reject next-hop discard; } } }",
			leaf:  "next-hop",
			value: "discard",
		},
		{
			name:  "compact leading-zero prepend",
			text:  "policy-options { policy-statement P { term t { then accept as-path-prepend 065001; } } }",
			leaf:  "as-path-prepend",
			value: "065001",
		},
		{
			name:  "term-line from-protocol next-hop",
			text:  "policy-options { policy-statement P { term t from protocol bgp then accept next-hop discard; } }",
			leaf:  "next-hop",
			value: "discard",
		},
		{
			name:  "bare term-line unsupported next-hop",
			text:  "policy-options { policy-statement P { term t then next-hop discard; } }",
			leaf:  "next-hop",
			value: "discard",
		},
		{
			name:  "bare term-line malformed next-hop",
			text:  "policy-options { policy-statement P { term t then next-hop 10.0.0.300; } }",
			leaf:  "next-hop",
			value: "10.0.0.300",
		},
		{
			name:  "bare term-line invalid prepend",
			text:  "policy-options { policy-statement P { term t then as-path-prepend 65001 abc; } }",
			leaf:  "as-path-prepend",
			value: "abc",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkError := func(channel string, err error, checkMessage bool) {
				t.Helper()
				if err == nil {
					t.Fatalf("%s accepted invalid %s value %q", channel, tc.leaf, tc.value)
				}
				message := err.Error()
				if !strings.Contains(message, `policy-statement "P"`) &&
					!strings.Contains(message, "policy-statement P") {
					t.Errorf("%s error %q does not name policy-statement P", channel, err)
				}
				if !strings.Contains(message, `term "t"`) && !strings.Contains(message, "term t") {
					t.Errorf("%s error %q does not name term t", channel, err)
				}
				if !strings.Contains(message, tc.leaf) {
					t.Errorf("%s error %q does not name %q", channel, err, tc.leaf)
				}
				if tc.value != "" && !strings.Contains(err.Error(), tc.value) {
					t.Errorf("%s error %q does not name %q", channel, err, tc.value)
				}
				if checkMessage && tc.wantMessage != "" && !strings.Contains(message, tc.wantMessage) {
					t.Errorf("%s error %q does not include %q", channel, err, tc.wantMessage)
				}
			}

			_, err := configstore.CheckText(tc.text, -1)
			checkError("CheckText", err, true)

			store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
			if err != nil {
				t.Fatalf("create config store: %v", err)
			}
			if err := store.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			if err := store.LoadOverride(tc.text); err != nil {
				t.Fatalf("LoadOverride(%q): %v", tc.text, err)
			}
			_, err = store.CommitCheck()
			checkError("LoadOverride + CommitCheck", err, true)
			_, err = store.Commit()
			checkError("LoadOverride + Commit", err, true)
			// The degenerate operands that motivated R4-F1 must also fail
			// after LoadMerge converts the hierarchical input back to SetPath.
			// Keep this check specific to those rows: the legacy from-protocol
			// term-line control has a separate known LoadMerge normalization
			// discrepancy and is not part of this fold.
			if tc.wantMessage != "" {
				mergeStore, err := configstore.New(filepath.Join(t.TempDir(), "merge.conf"))
				if err != nil {
					t.Fatalf("create load-merge store: %v", err)
				}
				if err := mergeStore.EnterConfigure(); err != nil {
					t.Fatalf("LoadMerge EnterConfigure: %v", err)
				}
				if err := mergeStore.LoadMerge(tc.text); err != nil {
					t.Fatalf("LoadMerge(%q): %v", tc.text, err)
				}
				_, err = mergeStore.CommitCheck()
				// LoadMerge can report the empty list as "missing value" rather
				// than the compiled gate's exact `wantMessage`; it still must name
				// the policy, term, and leaf.
				checkError("LoadMerge + CommitCheck", err, false)
			}
		})
	}
}

func TestPolicyThenBareOperandsCommitAndRender_12070(t *testing.T) {
	for _, tc := range []struct {
		name, command, termLine, rendered, renderedAlso string
		check                                           func(*testing.T, *config.PolicyTerm)
	}{
		{
			name:     "next-hop",
			command:  "policy-options policy-statement P term t then next-hop 192.0.2.1",
			rendered: " set ip next-hop 192.0.2.1\n",
			check: func(t *testing.T, term *config.PolicyTerm) {
				if term.Action != "" || term.NextHop != "192.0.2.1" {
					t.Fatalf("compiled term = %+v, want bare next-hop 192.0.2.1", term)
				}
			},
		},
		{
			name:     "as-path-prepend",
			command:  "policy-options policy-statement P term t then as-path-prepend 65001 65002",
			rendered: " set as-path prepend 65001 65002\n",
			check: func(t *testing.T, term *config.PolicyTerm) {
				if term.Action != "" || strings.Join(term.ASPathPrepend, " ") != "65001 65002" {
					t.Fatalf("compiled term = %+v, want bare prepend [65001 65002]", term)
				}
			},
		},
		{
			name:     "next-hop then prepend chain",
			command:  "policy-options policy-statement P term t then next-hop 192.0.2.1 as-path-prepend 65001 65002",
			rendered: " set ip next-hop 192.0.2.1\n set as-path prepend 65001 65002\n",
			check: func(t *testing.T, term *config.PolicyTerm) {
				if term.Action != "" || term.NextHop != "192.0.2.1" ||
					strings.Join(term.ASPathPrepend, " ") != "65001 65002" {
					t.Fatalf("compiled term = %+v, want bare next-hop and prepend chain", term)
				}
			},
		},
		{
			name:     "term-line next-hop",
			termLine: `policy-options { policy-statement P { term t then next-hop 192.0.2.1; } }`,
			rendered: " set ip next-hop 192.0.2.1\n",
			check: func(t *testing.T, term *config.PolicyTerm) {
				if term.Action != "" || term.NextHop != "192.0.2.1" {
					t.Fatalf("compiled term = %+v, want bare term-line next-hop", term)
				}
			},
		},
		{
			name:         "term-line self alias",
			termLine:     `policy-options { policy-statement P { term t then next-hop self; } }`,
			rendered:     " set ip next-hop peer-address\n",
			renderedAlso: " set ipv6 next-hop peer-address\n",
			check: func(t *testing.T, term *config.PolicyTerm) {
				if term.Action != "" || term.NextHop != "self" {
					t.Fatalf("compiled term = %+v, want bare term-line next-hop self", term)
				}
			},
		},
		{
			name:     "term-line IPv6 next-hop",
			termLine: `policy-options { policy-statement P { term t then next-hop 2001:db8::1; } }`,
			rendered: " set ipv6 next-hop global 2001:db8::1\n",
			check: func(t *testing.T, term *config.PolicyTerm) {
				if term.Action != "" || term.NextHop != "2001:db8::1" {
					t.Fatalf("compiled term = %+v, want bare term-line IPv6 next-hop", term)
				}
			},
		},
		{
			name:     "term-line prepend",
			termLine: `policy-options { policy-statement P { term t then as-path-prepend 65001 65002; } }`,
			rendered: " set as-path prepend 65001 65002\n",
			check: func(t *testing.T, term *config.PolicyTerm) {
				if term.Action != "" || strings.Join(term.ASPathPrepend, " ") != "65001 65002" {
					t.Fatalf("compiled term = %+v, want bare term-line prepend", term)
				}
			},
		},
		{
			name:     "term-line quoted prepend",
			termLine: `policy-options { policy-statement P { term t then as-path-prepend "65001 65002"; } }`,
			rendered: " set as-path prepend 65001 65002\n",
			check: func(t *testing.T, term *config.PolicyTerm) {
				if term.Action != "" || strings.Join(term.ASPathPrepend, " ") != "65001 65002" {
					t.Fatalf("compiled term = %+v, want bare term-line quoted prepend", term)
				}
			},
		},
		{
			name:     "term-line next-hop and prepend chain",
			termLine: `policy-options { policy-statement P { term t then next-hop 192.0.2.1 as-path-prepend 65001 65002; } }`,
			rendered: " set ip next-hop 192.0.2.1\n set as-path prepend 65001 65002\n",
			check: func(t *testing.T, term *config.PolicyTerm) {
				if term.Action != "" || term.NextHop != "192.0.2.1" ||
					strings.Join(term.ASPathPrepend, " ") != "65001 65002" {
					t.Fatalf("compiled term = %+v, want bare term-line next-hop/prepend chain", term)
				}
			},
		},
		{
			name:     "term-line next-hop then next policy",
			termLine: `policy-options { policy-statement P { term t then next-hop 192.0.2.1 next policy; } }`,
			rendered: " set ip next-hop 192.0.2.1\n",
			check: func(t *testing.T, term *config.PolicyTerm) {
				if term.Action != "" || term.NextHop != "192.0.2.1" || !term.NextPolicy {
					t.Fatalf("compiled term = %+v, want next-hop followed by next policy", term)
				}
			},
		},
		{
			name:     "term-line from-protocol next-hop accept",
			termLine: `policy-options { policy-statement P { term t from protocol bgp then next-hop 192.0.2.1 accept; } }`,
			rendered: " set ip next-hop 192.0.2.1\n",
			check: func(t *testing.T, term *config.PolicyTerm) {
				if term.Action != "accept" || term.NextHop != "192.0.2.1" ||
					len(term.FromProtocols) != 1 || term.FromProtocols[0] != "bgp" {
					t.Fatalf("compiled term = %+v, want bgp match with accepted next-hop", term)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertCompiled := func(t *testing.T, compiled *config.Config) {
				t.Helper()
				term := compiled.PolicyOptions.PolicyStatements["P"].Terms[0]
				tc.check(t, term)
				got := (&Manager{frrConf: "/dev/null"}).generatePolicyOptions(&compiled.PolicyOptions)
				if !strings.Contains(got, tc.rendered) {
					t.Fatalf("policy operand did not render; output:\n%s", got)
				}
				if tc.renderedAlso != "" && !strings.Contains(got, tc.renderedAlso) {
					t.Fatalf("policy operand did not render additional clause %q; output:\n%s",
						tc.renderedAlso, got)
				}
			}

			if tc.command != "" {
				compiled, err := configstore.CheckText("set "+tc.command, -1)
				if err != nil {
					t.Fatalf("CheckText rejected valid bare operand: %v", err)
				}
				assertCompiled(t, compiled)

				store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
				if err != nil {
					t.Fatalf("create config store: %v", err)
				}
				if err := store.EnterConfigure(); err != nil {
					t.Fatalf("EnterConfigure: %v", err)
				}
				if err := store.SetFromInputAs("", tc.command); err != nil {
					t.Fatalf("SetFromInputAs(%q): %v", tc.command, err)
				}
				compiled, err = store.CommitCheck()
				if err != nil {
					t.Fatalf("CommitCheck rejected valid bare operand: %v", err)
				}
				assertCompiled(t, compiled)
				if _, err := store.Commit(); err != nil {
					t.Fatalf("Commit rejected valid bare operand: %v", err)
				}
			}

			if tc.termLine != "" {
				store, err := configstore.New(filepath.Join(t.TempDir(), "xpf-term-line.conf"))
				if err != nil {
					t.Fatalf("create term-line config store: %v", err)
				}
				if err := store.EnterConfigure(); err != nil {
					t.Fatalf("term-line EnterConfigure: %v", err)
				}
				if err := store.LoadOverride(tc.termLine); err != nil {
					t.Fatalf("LoadOverride rejected valid term-line operand: %v", err)
				}
				compiled, err := store.CommitCheck()
				if err != nil {
					t.Fatalf("LoadOverride + CommitCheck rejected valid term-line operand: %v", err)
				}
				assertCompiled(t, compiled)
				if _, err := store.Commit(); err != nil {
					t.Fatalf("LoadOverride + Commit rejected valid term-line operand: %v", err)
				}
			}
		})
	}
}

// TestPolicyThenOperandsSyncApplyDowngradesAndOmits_12070 pins both tolerant
// compile routes (#1960) and the renderer's fail-closed belt together. RED on
// M7 (remove lenientPolicyThenOperands from lenientCompileOpts): both routes
// reject instead of accepting with the downgrade warning.
func TestPolicyThenOperandsSyncApplyDowngradesAndOmits_12070(t *testing.T) {
	for _, tc := range []struct {
		name, text, bad string
		forbidden       []string
	}{
		{
			name: "compact next-hop",
			text: `policy-options { policy-statement P { term t { then accept next-hop discard; } } }`,
			bad:  "discard",
			forbidden: []string{
				"set ip next-hop ",
				"set ipv6 next-hop ",
			},
		},
		{
			name:      "term-line prepend",
			text:      `policy-options { policy-statement P { term t then accept as-path-prepend 65001 abc; } }`,
			bad:       "abc",
			forbidden: []string{"set as-path prepend "},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree, parseErrors := config.NewParser(tc.text).Parse()
			if len(parseErrors) != 0 {
				t.Fatalf("parse policy operand: %v", parseErrors)
			}
			lenient, err := config.CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("CompileConfigLenient rejected existing policy operand: %v", err)
			}
			checkTolerant := func(path string, warnings []string, options *config.PolicyOptionsConfig) {
				t.Helper()
				term := options.PolicyStatements["P"].Terms[0]
				if term.Action != "accept" {
					t.Fatalf("%s compiled term action = %q, want accept", path, term.Action)
				}
				found := false
				for _, warning := range warnings {
					if strings.Contains(warning, "policy then operand (downgraded to warning on tolerant path)") &&
						strings.Contains(warning, tc.bad) {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("%s warnings %q do not include downgraded operand %q",
						path, warnings, tc.bad)
				}
				rendered := (&Manager{frrConf: "/dev/null"}).generatePolicyOptions(options)
				if !strings.Contains(rendered, "route-map P permit") {
					t.Fatalf("%s render omitted the valid accept route-map:\n%s", path, rendered)
				}
				for _, prefix := range tc.forbidden {
					if strings.Contains(rendered, prefix) {
						t.Fatalf("%s render emitted invalid policy clause prefix %q:\n%s",
							path, prefix, rendered)
					}
				}
			}
			checkTolerant("CompileConfigLenient", lenient.Warnings, &lenient.PolicyOptions)

			store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
			if err != nil {
				t.Fatalf("create config store: %v", err)
			}
			synced, err := store.SyncApply(tc.text, nil)
			if err != nil {
				t.Fatalf("SyncApply rejected existing policy operand: %v", err)
			}
			checkTolerant("SyncApply", synced.Warnings, &synced.PolicyOptions)
		})
	}
}
