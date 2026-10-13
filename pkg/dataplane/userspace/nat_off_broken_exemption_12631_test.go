package userspace

// #12631: a broken `off` exemption (typo'd / dangling / dropped-constraint
// application reference, or an invalid rule-level destination-port) must
// OVER-EXEMPT — match-all on the application/port axis — not install the
// never-match sentinel. Per #3844/#9877 skipping or narrowing an exemption
// translates traffic the operator said not to translate (fail-open); the
// #12440 protocol-less preservation is the same doctrine. Broken TRANSLATE
// rules keep the never-match sentinel (fail-closed narrowing).
//
// Match-all on this axis is bounded by the rule's other authored dimensions
// (source/destination addresses, zone/interface scope, rule order): only the
// broken axis widens.

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// --- SNAT (buildSourceNATAppTerms via buildSourceNATSnapshots) ---

func snatOffCfg12631(apps map[string]*config.Application, appNames []string, off bool) *config.Config {
	cfg := &config.Config{}
	cfg.Applications.Applications = apps
	cfg.Security.NAT.Source = []*config.NATRuleSet{{
		Name: "rs", FromZone: "trust", ToZone: "untrust",
		Rules: []*config.NATRule{{
			Name:  "r1",
			Match: config.NATMatch{Applications: appNames, SourceAddresses: []string{"10.0.0.0/8"}},
			Then:  config.NATThen{Type: config.NATSource, Off: off, Interface: !off},
		}},
	}}
	return cfg
}

func TestSNATBrokenOffExemptionOverExempts12631(t *testing.T) {
	cases := []struct {
		name string
		cfg  *config.Config
	}{
		{"typo dangling only", snatOffCfg12631(map[string]*config.Application{
			"web": {Name: "web", Protocol: "tcp", DestinationPort: "80"},
		}, []string{"no-such-app"}, true)},
		{"mixed good and typo", snatOffCfg12631(map[string]*config.Application{
			"web": {Name: "web", Protocol: "tcp", DestinationPort: "80"},
		}, []string{"web", "no-such-app"}, true)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snaps := buildSourceNATSnapshots(tc.cfg, nil)
			if len(snaps) != 1 || !snaps[0].Off {
				t.Fatalf("snaps = %+v, want one off snapshot", snaps)
			}
			terms := snaps[0].MatchApplications
			for _, term := range terms {
				if term.Protocol == natProtoNever {
					t.Fatalf("broken off exemption emitted never-match sentinel: %+v", terms)
				}
			}
			foundAny := false
			for _, term := range terms {
				if term.Protocol == natProtoAny && len(term.Ports) == 0 && len(term.SrcPorts) == 0 {
					foundAny = true
				}
			}
			if !foundAny {
				t.Fatalf("broken off exemption terms = %+v, want a match-all (proto-any, no ports) term", terms)
			}
			// Bounded by other authored dimensions.
			if len(snaps[0].SourceAddresses) != 1 || snaps[0].SourceAddresses[0] != "10.0.0.0/8" {
				t.Fatalf("source scope lost: %+v", snaps[0])
			}
		})
	}
}

func TestSNATProtocolLessOffOverExemptsProtocolButKeepsPort12631(t *testing.T) {
	cfg := snatOffCfg12631(map[string]*config.Application{
		"np": {Name: "np", DestinationPort: "8080"},
	}, []string{"np"}, true)
	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps) != 1 || !snaps[0].Off {
		t.Fatalf("snaps=%+v", snaps)
	}
	terms := snaps[0].MatchApplications
	if len(terms) != 1 || terms[0].Protocol != natProtoAny ||
		len(terms[0].Ports) != 1 || terms[0].Ports[0] != (NatPortRangeWire{Low: 8080, High: 8080}) {
		t.Fatalf("protocol-less off terms=%+v; want proto-any with destination port 8080 retained", terms)
	}
}

func TestSNATBrokenTranslateKeepsNeverMatch12631(t *testing.T) {
	cfg := snatOffCfg12631(map[string]*config.Application{
		"web": {Name: "web", Protocol: "tcp", DestinationPort: "80"},
	}, []string{"no-such-app"}, false)
	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("snaps = %+v", snaps)
	}
	found := false
	for _, term := range snaps[0].MatchApplications {
		if term.Protocol == natProtoNever {
			found = true
		}
		if term.Protocol == natProtoAny {
			t.Fatalf("broken translate emitted match-all: %+v", snaps[0].MatchApplications)
		}
	}
	if !found {
		t.Fatalf("broken translate terms = %+v, want natProtoNever", snaps[0].MatchApplications)
	}
}

func TestSNATDroppedConstraintOffExemptionOverExempts12631(t *testing.T) {
	cfg := compileNATApplication11587(t, `protocol icmp; icmp-type bogus;`)
	// off rule referencing the dropped-constraint app
	cfg.Security.NAT.Source = []*config.NATRuleSet{{
		Name: "rs", FromZone: "trust", ToZone: "untrust",
		Rules: []*config.NATRule{{
			Name: "r1", Match: config.NATMatch{Applications: []string{"bad"}},
			Then: config.NATThen{Type: config.NATSource, Off: true},
		}},
	}}
	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("snaps=%+v", snaps)
	}
	for _, term := range snaps[0].MatchApplications {
		if term.Protocol == natProtoNever {
			t.Fatalf("dropped-constraint off exemption emitted never-match: %+v", snaps[0].MatchApplications)
		}
	}
	foundAny := false
	for _, term := range snaps[0].MatchApplications {
		if term.Protocol == natProtoAny {
			foundAny = true
		}
	}
	if !foundAny {
		t.Fatalf("terms=%+v want proto-any", snaps[0].MatchApplications)
	}
	// translate control
	cfg.Security.NAT.Source[0].Rules[0].Then = config.NATThen{Type: config.NATSource, Interface: true}
	snaps = buildSourceNATSnapshots(cfg, nil)
	foundNever := false
	for _, term := range snaps[0].MatchApplications {
		if term.Protocol == natProtoNever {
			foundNever = true
		}
	}
	if !foundNever {
		t.Fatalf("translate dropped-constraint terms=%+v want never", snaps[0].MatchApplications)
	}
}

// --- DNAT ---

func dnatCfg12631(appNames []string, off bool) *config.Config {
	cfg := &config.Config{}
	cfg.Applications.Applications = map[string]*config.Application{
		"web": {Name: "web", Protocol: "tcp", DestinationPort: "80"},
	}
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{"p1": {Name: "p1", Address: "192.168.1.10"}},
		RuleSets: []*config.NATRuleSet{{
			Name: "rs", FromZone: "untrust",
			Rules: []*config.NATRule{{
				Name: "r1",
				Match: config.NATMatch{
					DestinationAddress: "203.0.113.10",
					Applications:       appNames,
				},
				Then: dnatThen12631(off),
			}},
		}},
	}
	return cfg
}
func dnatThen12631(off bool) config.NATThen {
	if off {
		return config.NATThen{Type: config.NATDestination, Off: true}
	}
	return config.NATThen{Type: config.NATDestination, PoolName: "p1"}
}

func isNeverRow12631(s DestinationNATRuleSnapshot) bool {
	for _, r := range s.MatchSourcePorts {
		if r == natNeverMatchPortRange {
			return true
		}
	}
	return false
}
func isMatchAllRow12631(s DestinationNATRuleSnapshot) bool {
	// DNAT match-all: wildcard proto (""), wildcard port 0, no never ranges, no icmp constraint
	return s.Protocol == "" && s.DestinationPort == 0 && len(s.MatchDestinationPorts) == 0 &&
		len(s.MatchSourcePorts) == 0 && s.MatchICMPType == nil && s.MatchICMPCode == nil
}

func TestDNATBrokenOffExemptionOverExempts12631(t *testing.T) {
	for _, tc := range []struct {
		name string
		apps []string
	}{
		{"typo only", []string{"no-such-app"}},
		{"mixed good typo", []string{"web", "no-such-app"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snaps := buildDestinationNATSnapshots(dnatCfg12631(tc.apps, true), nil)
			if len(snaps) == 0 {
				t.Fatalf("no off snapshots")
			}
			for _, s := range snaps {
				if !s.Off {
					t.Fatalf("snap not off: %+v", s)
				}
				if isNeverRow12631(s) {
					t.Fatalf("broken off exemption emitted never-match row: %+v", snaps)
				}
				if s.DestinationAddress != "203.0.113.10" {
					t.Fatalf("destination bound lost: %+v", s)
				}
			}
			found := false
			for _, s := range snaps {
				if isMatchAllRow12631(s) {
					found = true
				}
			}
			if !found {
				t.Fatalf("broken off snaps=%+v want a match-all row", snaps)
			}
		})
	}
}

func TestDNATBrokenTranslateKeepsNeverMatch12631(t *testing.T) {
	snaps := buildDestinationNATSnapshots(dnatCfg12631([]string{"no-such-app"}, false), nil)
	if len(snaps) != 1 || !isNeverRow12631(snaps[0]) {
		t.Fatalf("broken translate snaps=%+v want one never-match row", snaps)
	}
	if isMatchAllRow12631(snaps[0]) {
		t.Fatalf("broken translate emitted match-all")
	}
}

func TestDNATDroppedConstraintOffExemptionOverExempts12631(t *testing.T) {
	cfg := compileNATApplication11587(t, `protocol icmp; icmp-type bogus;`)
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{"p1": {Name: "p1", Address: "192.168.1.10"}},
		RuleSets: []*config.NATRuleSet{{
			Name: "rs", FromZone: "untrust",
			Rules: []*config.NATRule{{
				Name:  "r1",
				Match: config.NATMatch{DestinationAddress: "203.0.113.10", Applications: []string{"bad"}},
				Then:  config.NATThen{Type: config.NATDestination, Off: true},
			}},
		}},
	}
	snaps := buildDestinationNATSnapshots(cfg, nil)
	for _, s := range snaps {
		if isNeverRow12631(s) {
			t.Fatalf("dropped-constraint off emitted never-match: %+v", snaps)
		}
	}
	found := false
	for _, s := range snaps {
		if isMatchAllRow12631(s) {
			found = true
		}
	}
	if !found {
		t.Fatalf("snaps=%+v want match-all row", snaps)
	}
}

func TestDNATProtocollessOffStillBoundedRows12631(t *testing.T) {
	// #12440 control: protocol-less ported app on off keeps tcp/8080+udp/8080, not widened to match-all.
	cfg := dnatCfg12631([]string{"np"}, true)
	cfg.Applications.Applications["np"] = &config.Application{Name: "np", DestinationPort: "8080"}
	snaps := buildDestinationNATSnapshots(cfg, nil)
	ports := map[string]map[uint16]bool{}
	for _, s := range snaps {
		if ports[s.Protocol] == nil {
			ports[s.Protocol] = map[uint16]bool{}
		}
		ports[s.Protocol][s.DestinationPort] = true
		if isMatchAllRow12631(s) {
			t.Fatalf("protocol-less off widened to match-all: %+v", snaps)
		}
	}
	if !ports["tcp"][8080] || !ports["udp"][8080] {
		t.Fatalf("ports=%v want tcp/udp 8080", ports)
	}
}

func TestDNATInvalidRuleDstPortOffOverExemptsTranslateFailsClosed12631(t *testing.T) {
	mk := func(off bool) *config.Config {
		cfg := dnatCfg12631(nil, off)
		r := cfg.Security.NAT.Destination.RuleSets[0].Rules[0]
		r.Match.DestinationPorts = []int{70000}
		r.Match.InvalidDestinationPorts = []string{"70000"}
		return cfg
	}
	offSnaps := buildDestinationNATSnapshots(mk(true), nil)
	found := false
	for _, s := range offSnaps {
		if isMatchAllRow12631(s) {
			found = true
		}
	}
	if !found {
		t.Fatalf("off invalid dstport snaps=%+v want match-all row", offSnaps)
	}
	trSnaps := buildDestinationNATSnapshots(mk(false), nil)
	if len(trSnaps) != 0 {
		t.Fatalf("translate invalid dstport snaps=%+v want none (fail-closed)", trSnaps)
	}
}

func TestSNATInvalidRuleDstPortOffOverExemptsTranslateFailsClosed12631(t *testing.T) {
	mk := func(off bool) *config.Config {
		cfg := snatOffCfg12631(nil, nil, off)
		r := cfg.Security.NAT.Source[0].Rules[0]
		r.Match.DestinationPorts = []int{70000}
		r.Match.InvalidDestinationPorts = []string{"70000"}
		return cfg
	}
	offSnaps := buildSourceNATSnapshots(mk(true), nil)
	if len(offSnaps) != 1 || !offSnaps[0].Off || len(offSnaps[0].MatchDestinationPorts) != 0 {
		t.Fatalf("off invalid dport snaps=%+v; want unconstrained port axis", offSnaps)
	}
	trSnaps := buildSourceNATSnapshots(mk(false), nil)
	if len(trSnaps) != 1 || len(trSnaps[0].MatchDestinationPorts) != 1 ||
		trSnaps[0].MatchDestinationPorts[0] != natNeverMatchPortRange {
		t.Fatalf("translate invalid dport snaps=%+v; want never-match port sentinel", trSnaps)
	}
}

func TestBrokenExemptionKeepsRuleOrderAndBuildIsIdempotent12631(t *testing.T) {
	t.Run("SNAT", func(t *testing.T) {
		cfg := snatOffCfg12631(nil, []string{"typo"}, true)
		rules := cfg.Security.NAT.Source[0].Rules
		rules = append(rules, &config.NATRule{
			Name: "later", Match: config.NATMatch{SourceAddresses: []string{"10.0.0.0/8"}},
			Then: config.NATThen{Type: config.NATSource, Interface: true},
		})
		cfg.Security.NAT.Source[0].Rules = rules
		a, b := buildSourceNATSnapshots(cfg, nil), buildSourceNATSnapshots(cfg, nil)
		if !reflect.DeepEqual(a, b) || len(a) != 2 || a[0].Name != "r1" || !a[0].Off || a[1].Name != "later" {
			t.Fatalf("SNAT snapshots changed/order wrong: first=%+v second=%+v", a, b)
		}
	})
	t.Run("DNAT", func(t *testing.T) {
		cfg := dnatCfg12631([]string{"typo"}, true)
		rs := cfg.Security.NAT.Destination.RuleSets[0]
		rs.Rules = append(rs.Rules, &config.NATRule{
			Name: "later", Match: config.NATMatch{DestinationAddress: "203.0.113.10"},
			Then: config.NATThen{Type: config.NATDestination, PoolName: "p1"},
		})
		a, b := buildDestinationNATSnapshots(cfg, nil), buildDestinationNATSnapshots(cfg, nil)
		if !reflect.DeepEqual(a, b) || len(a) != 2 || a[0].Name != "r1" || !a[0].Off || a[1].Name != "later" {
			t.Fatalf("DNAT snapshots changed/order wrong: first=%+v second=%+v", a, b)
		}
	})
}

func TestSNATBrokenAppPortOffOverExemptsPortOnly12631(t *testing.T) {
	// App-level broken port axis (valid protocol, unrepresentable port):
	// off widens only the port axis; translate keeps never-match.
	cfg := snatOffCfg12631(map[string]*config.Application{
		"badport": {Name: "badport", Protocol: "tcp", DestinationPort: "99999"},
	}, []string{"badport"}, true)
	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("snaps=%+v", snaps)
	}
	found := false
	for _, term := range snaps[0].MatchApplications {
		if term.Protocol == natProtoNever {
			t.Fatalf("broken-port off emitted never-match: %+v", snaps[0].MatchApplications)
		}
		if len(term.Ports) == 0 {
			found = true
		}
	}
	if !found {
		t.Fatalf("broken-port off terms=%+v want a wildcard-port term", snaps[0].MatchApplications)
	}
}

func TestDNATBrokenAppPortOffOverExemptsPortOnly12631(t *testing.T) {
	cfg := dnatCfg12631([]string{"badport"}, true)
	cfg.Applications.Applications["badport"] = &config.Application{Name: "badport", Protocol: "tcp", DestinationPort: "99999"}
	snaps := buildDestinationNATSnapshots(cfg, nil)
	for _, s := range snaps {
		if isNeverRow12631(s) {
			t.Fatalf("broken-port DNAT off emitted never-match: %+v", snaps)
		}
	}
	found := false
	for _, s := range snaps {
		if s.Protocol == "tcp" && s.DestinationPort == 0 {
			found = true
		}
	}
	if !found {
		t.Fatalf("broken-port DNAT off snaps=%+v want tcp with wildcard port", snaps)
	}
}
