package firewallshow

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15173 (B18-02): the raw `show firewall` view dropped except-ports,
// tcp-flags, is-fragment, flexible-match-range, reject type, policer and
// syslog, and printed every empty-action term as a terminating accept.
// Each field below must produce a line; dropping any renderer arm reds
// its cell.

func renderTerm15173(term *config.FirewallFilterTerm) string {
	var b strings.Builder
	WriteTerm(&b, term, false)
	return b.String()
}

func TestRawTermRendersEveryField15173(t *testing.T) {
	term := &config.FirewallFilterTerm{
		Name:              "full",
		DSCPs:             []string{"ef"},
		Protocols:         []string{"tcp"},
		SourceAddresses:   []string{"10.0.0.0/8"},
		DestAddresses:     []string{"192.0.2.0/24"},
		SourcePrefixLists: []config.PrefixListRef{{Name: "pl-src"}},
		DestPrefixLists:   []config.PrefixListRef{{Name: "pl-dst", Except: true}},
		SourcePorts:       []string{"1024-2048"},
		DestinationPorts:  []string{"443"},
		SourcePortsExcept: []string{"25"},
		DestPortsExcept:   []string{"22"},
		ICMPTypes:         []int{8},
		ICMPCodes:         []int{0},
		TCPFlags:          []string{"syn", "!ack"},
		IsFragment:        true,
		FlexMatch:         &config.FlexMatchConfig{MatchStart: "layer-3", ByteOffset: 9, BitLength: 8, Value: 0x11, Mask: 0xff},
		ForwardingClass:   "fc1",
		LossPriority:      "high",
		DSCPRewrite:       "ef",
		Log:               true,
		Syslog:            true,
		Count:             "hits",
		Policer:           "p1",
		Action:            "discard",
	}
	out := renderTerm15173(term)
	for _, want := range []string{
		"  Term: full\n",
		"    from dscp ef\n",
		"    from protocol tcp\n",
		"    from source-address 10.0.0.0/8\n",
		"    from destination-address 192.0.2.0/24\n",
		"    from source-prefix-list pl-src\n",
		"    from destination-prefix-list pl-dst except\n",
		"    from source-port 1024-2048\n",
		"    from destination-port 443\n",
		"    from source-port-except 25\n",
		"    from destination-port-except 22\n",
		"    from icmp-type 8\n",
		"    from icmp-code 0\n",
		"    from tcp-flags syn, !ack\n",
		"    from is-fragment\n",
		"    from flexible-match-range match-start layer-3 offset 9 length 8 value 0x11 mask 0xff\n",
		"    then forwarding-class fc1\n",
		"    then loss-priority high\n",
		"    then dscp ef\n",
		"    then log\n",
		"    then syslog\n",
		"    then count hits\n",
		"    then policer p1\n",
		"    then discard\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("raw term render missing %q:\n%s", want, out)
		}
	}
}

// The issue's headline example: `ssh-only` (tcp except port 22, discard)
// must not read as "discard all TCP".
func TestRawTermExceptPortDiscardNotBroad15173(t *testing.T) {
	out := renderTerm15173(&config.FirewallFilterTerm{
		Name: "ssh-only", Protocols: []string{"tcp"},
		DestPortsExcept: []string{"22"}, Action: "discard",
	})
	if !strings.Contains(out, "    from destination-port-except 22\n") {
		t.Errorf("except-port predicate dropped; narrow discard reads as broad discard:\n%s", out)
	}
	if !strings.Contains(out, "    then discard\n") {
		t.Errorf("discard action lost:\n%s", out)
	}
}

func TestRawTermActionHonesty15173(t *testing.T) {
	cases := []struct {
		name string
		term *config.FirewallFilterTerm
		want []string
		not  []string
	}{
		{
			name: "explicit next term falls through, never accept",
			term: &config.FirewallFilterTerm{Name: "pass-on", NextTerm: true},
			want: []string{"    then next term\n"},
			not:  []string{"then accept"},
		},
		{
			name: "count-only next term falls through",
			term: &config.FirewallFilterTerm{Name: "pass-on", Count: "c", NextTerm: true},
			want: []string{"    then count c\n", "    then next term\n"},
			not:  []string{"then accept"},
		},
		{
			name: "modifier-only terminates as implicit accept",
			term: &config.FirewallFilterTerm{Name: "count-only", Count: "c"},
			want: []string{"    then count c\n", "    then accept\n"},
			not:  []string{"next term"},
		},
		{
			name: "reject renders its message type",
			term: &config.FirewallFilterTerm{Name: "rej", Action: "reject", RejectMessageType: "tcp-reset"},
			want: []string{"    then reject tcp-reset\n"},
		},
		{
			name: "plain reject has no phantom type",
			term: &config.FirewallFilterTerm{Name: "rej", Action: "reject"},
			want: []string{"    then reject\n"},
			not:  []string{"tcp-reset"},
		},
		{
			name: "contradictory discard+next-term terminates and discloses",
			term: &config.FirewallFilterTerm{Name: "bad", Action: "discard", NextTerm: true},
			want: []string{"    then discard\n", "    then next term (ignored"},
			not:  []string{"    then next term\n"},
		},
		{
			name: "routing-instance terminates without phantom accept",
			term: &config.FirewallFilterTerm{Name: "steer", RoutingInstance: "mgmt-vrf"},
			want: []string{"    then routing-instance mgmt-vrf\n"},
			not:  []string{"then accept", "next term"},
		},
		{
			name: "routing-instance+next-term discloses ignored bit",
			term: &config.FirewallFilterTerm{Name: "steer", RoutingInstance: "mgmt-vrf", NextTerm: true},
			want: []string{"    then routing-instance mgmt-vrf\n", "    then next term (ignored"},
			not:  []string{"then accept"},
		},
		{
			name: "explicit accept unchanged (control)",
			term: &config.FirewallFilterTerm{Name: "ok", Action: "accept"},
			want: []string{"    then accept\n"},
			not:  []string{"next term"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := renderTerm15173(tc.term)
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("missing %q:\n%s", w, out)
				}
			}
			for _, n := range tc.not {
				if strings.Contains(out, n) {
					t.Errorf("must not contain %q:\n%s", n, out)
				}
			}
		})
	}
}

func TestWriteAllFiltersSortedAndNilSafe15173(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"zzz":  {Terms: []*config.FirewallFilterTerm{{Name: "t", Action: "accept"}, nil}},
		"aaa":  {Terms: []*config.FirewallFilterTerm{{Name: "t", Action: "discard"}}},
		"nilf": nil,
	}
	var b strings.Builder
	WriteAllFilters(&b, cfg)
	out := b.String()
	if strings.Index(out, "Filter: aaa") > strings.Index(out, "Filter: zzz") {
		t.Errorf("filters not sorted:\n%s", out)
	}
	if strings.Contains(out, "nilf") {
		t.Errorf("nil filter rendered:\n%s", out)
	}
	var empty strings.Builder
	WriteAllFilters(&empty, nil)
	if empty.String() != "No firewall filters configured\n" {
		t.Errorf("nil cfg = %q", empty.String())
	}
}
