package config

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// #16141: CoS string-underlying types + tunnel-mode consts.
//
//   - LossPriority (7 decls: six CoS entries in types_cos.go plus
//     FirewallFilterTerm in types_system.go) and CoSScheduler.Priority
//     (SchedulerPriority) are string-underlying types with consts and
//     one Valid() each; uint8 enums were rejected (they would serialize
//     numbers and reintroduce the #11798 marshal-slip class).
//   - TunnelConfig.Mode is TunnelMode with consts for
//     gre/ipip/ip6gre/wireguard; AddrFamily enum deferred and the
//     TunnelConfig struct split rejected (applied record, daemon-built).
//
// FAIL-ON-REVERT: revert any field to plain string, change a const
// token, or make Valid() accept a typo, and the tests below go RED.

func TestCoSTunnelTypedMarshalDiff16141(t *testing.T) {
	// Pre-change (string-typed) marshal bytes for the same logical
	// values. The typed forms must produce byte-identical tokens,
	// including the empty-string defaults.
	cases := []struct {
		name string
		v    any
		want string
	}{
		{"dscp classifier entry", CoSDSCPClassifierEntry{ForwardingClass: "voice", LossPriority: LossPriorityHigh}, `{"ForwardingClass":"voice","LossPriority":"high","DSCPValues":null}`},
		{"dscp classifier unset", CoSDSCPClassifierEntry{ForwardingClass: "be"}, `{"ForwardingClass":"be","LossPriority":"","DSCPValues":null}`},
		{"inet-prec entry", CoSINetPrecedenceClassifierEntry{ForwardingClass: "voice", LossPriority: LossPriorityMediumLow}, `{"ForwardingClass":"voice","LossPriority":"medium-low","Precedences":null}`},
		{"ieee classifier entry", CoSIEEE8021ClassifierEntry{ForwardingClass: "voice", LossPriority: LossPriorityMediumHigh}, `{"ForwardingClass":"voice","LossPriority":"medium-high","CodePoints":null}`},
		{"scheduler strict-high", CoSScheduler{Name: "s", Priority: SchedulerPriorityStrictHigh}, ""},
		{"scheduler unset", CoSScheduler{Name: "s"}, ""},
		{"tunnel gre", TunnelConfig{Name: "gr-0-0-0", Mode: TunnelModeGRE}, ""},
		{"tunnel unset", TunnelConfig{Name: "gr-0-0-0"}, ""},
	}
	for _, tc := range cases {
		if tc.want == "" {
			continue
		}
		got, err := json.Marshal(tc.v)
		if err != nil {
			t.Fatalf("%s: marshal: %v", tc.name, err)
		}
		if string(got) != tc.want {
			t.Errorf("%s: marshal = %s, want pre-change bytes %s", tc.name, got, tc.want)
		}
	}
	// Field-token checks for the structs whose full marshal carries
	// unrelated fields: the typed token must be the pre-change token.
	termJSON, err := json.Marshal(FirewallFilterTerm{Name: "t1", LossPriority: LossPriorityHigh})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(termJSON), `"LossPriority":"high"`) {
		t.Errorf("filter term marshal missing pre-change LossPriority token: %s", termJSON)
	}
	schedJSON, err := json.Marshal(CoSScheduler{Name: "s", Priority: SchedulerPriorityStrictHigh})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(schedJSON), `"Priority":"strict-high"`) {
		t.Errorf("scheduler marshal missing pre-change Priority token: %s", schedJSON)
	}
	unsetSched, _ := json.Marshal(CoSScheduler{Name: "s"})
	if !strings.Contains(string(unsetSched), `"Priority":""`) {
		t.Errorf("scheduler unset must marshal empty token, got %s", unsetSched)
	}
	tunJSON, err := json.Marshal(TunnelConfig{Name: "gr-0-0-0", Mode: TunnelModeGRE})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(tunJSON), `"Mode":"gre"`) {
		t.Errorf("tunnel marshal missing pre-change Mode token: %s", tunJSON)
	}
	unsetTun, _ := json.Marshal(TunnelConfig{Name: "gr-0-0-0"})
	if !strings.Contains(string(unsetTun), `"Mode":""`) {
		t.Errorf("tunnel unset must marshal empty token (GRE default preserved), got %s", unsetTun)
	}
	// Round-trip of a pre-change payload into the typed fields.
	var term FirewallFilterTerm
	if err := json.Unmarshal([]byte(`{"Name":"t1","LossPriority":"medium-high"}`), &term); err != nil {
		t.Fatal(err)
	}
	if term.LossPriority != LossPriorityMediumHigh {
		t.Errorf("pre-change payload decoded LossPriority=%q, want medium-high", term.LossPriority)
	}
	var tun TunnelConfig
	if err := json.Unmarshal([]byte(`{"Name":"wg0","Mode":"wireguard"}`), &tun); err != nil {
		t.Fatal(err)
	}
	if tun.Mode != TunnelModeWireGuard {
		t.Errorf("pre-change payload decoded Mode=%q, want wireguard", tun.Mode)
	}

	// Type-level pins: every named field is the typed type.
	for _, f := range []struct {
		typ  reflect.Type
		name string
		want reflect.Type
	}{
		{reflect.TypeOf(CoSDSCPClassifierEntry{}), "LossPriority", reflect.TypeOf(LossPriority(""))},
		{reflect.TypeOf(CoSINetPrecedenceClassifierEntry{}), "LossPriority", reflect.TypeOf(LossPriority(""))},
		{reflect.TypeOf(CoSIEEE8021ClassifierEntry{}), "LossPriority", reflect.TypeOf(LossPriority(""))},
		{reflect.TypeOf(CoSDSCPRewriteRuleEntry{}), "LossPriority", reflect.TypeOf(LossPriority(""))},
		{reflect.TypeOf(CoSIEEE8021RewriteRuleEntry{}), "LossPriority", reflect.TypeOf(LossPriority(""))},
		{reflect.TypeOf(CoSInertRewriteRuleEntry{}), "LossPriority", reflect.TypeOf(LossPriority(""))},
		{reflect.TypeOf(FirewallFilterTerm{}), "LossPriority", reflect.TypeOf(LossPriority(""))},
		{reflect.TypeOf(CoSScheduler{}), "Priority", reflect.TypeOf(SchedulerPriority(""))},
		{reflect.TypeOf(TunnelConfig{}), "Mode", reflect.TypeOf(TunnelMode(""))},
	} {
		fld, _ := f.typ.FieldByName(f.name)
		if fld.Type != f.want {
			t.Errorf("%s.%s type = %s, want %s", f.typ.Name(), f.name, fld.Type, f.want)
		}
	}
	// The TunnelConfig struct split was rejected: the applied-record
	// fields stay on the one struct.
	for _, name := range []string{"Key", "TTL", "MTU", "RIListMember", "WgPeers"} {
		if _, ok := reflect.TypeOf(TunnelConfig{}).FieldByName(name); !ok {
			t.Errorf("TunnelConfig.%s missing — struct split was rejected for #16141", name)
		}
	}
}

func TestCoSLossAndSchedulerPriorityValid16141(t *testing.T) {
	for _, p := range []LossPriority{LossPriorityUnset, LossPriorityLow, LossPriorityMediumLow, LossPriorityMediumHigh, LossPriorityHigh} {
		if !p.Valid() {
			t.Errorf("LossPriority(%q).Valid() = false, want true", p)
		}
	}
	for _, p := range []LossPriority{"medum-low", "LOW", "strict-high", "banana"} {
		if p.Valid() {
			t.Errorf("LossPriority(%q).Valid() = true, want false", p)
		}
	}
	for _, p := range []SchedulerPriority{SchedulerPriorityUnset, SchedulerPriorityLow, SchedulerPriorityMediumLow, SchedulerPriorityMediumHigh, SchedulerPriorityHigh, SchedulerPriorityStrictHigh} {
		if !p.Valid() {
			t.Errorf("SchedulerPriority(%q).Valid() = false, want true", p)
		}
		// The exported boundary helper must agree with Valid().
		if !CoSSchedulerPriorityValid(p) {
			t.Errorf("CoSSchedulerPriorityValid(%q) = false, want true", p)
		}
	}
	for _, p := range []SchedulerPriority{"ultra-high", "LOW", "banana"} {
		if p.Valid() {
			t.Errorf("SchedulerPriority(%q).Valid() = true, want false", p)
		}
		if CoSSchedulerPriorityValid(p) {
			t.Errorf("CoSSchedulerPriorityValid(%q) = true, want false", p)
		}
	}
	// Const tokens are exactly the pre-change wire tokens.
	if LossPriorityUnset != "" || LossPriorityLow != "low" || LossPriorityMediumLow != "medium-low" || LossPriorityMediumHigh != "medium-high" || LossPriorityHigh != "high" {
		t.Error("LossPriority const tokens drifted from wire tokens")
	}
	if SchedulerPriorityUnset != "" || SchedulerPriorityStrictHigh != "strict-high" {
		t.Error("SchedulerPriority const tokens drifted from wire tokens")
	}
	if TunnelModeUnset != "" || TunnelModeGRE != "gre" || TunnelModeIPIP != "ipip" || TunnelModeIP6GRE != "ip6gre" || TunnelModeWireGuard != "wireguard" {
		t.Error("TunnelMode const tokens drifted from wire tokens")
	}
	// TunnelModeNames is derived from the consts and stays the
	// schema-accepted subset (ipip deliberately absent, #4785/#6924).
	if got := strings.Join(TunnelModeNames, ","); got != "gre,ip6gre,wireguard" {
		t.Errorf("TunnelModeNames = %q, want gre,ip6gre,wireguard", got)
	}
}

func TestCoSTypedCompilerWritesConstants16141(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service forwarding-classes queue 5 voice",
		"set class-of-service classifiers dscp wan forwarding-class voice loss-priority high code-points ef",
		"set class-of-service schedulers be-sched priority strict-high",
		"set class-of-service schedulers be-sched transmit-rate 10m",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	entry := cfg.ClassOfService.DSCPClassifiers["wan"].Entries[0]
	if entry.LossPriority != LossPriorityHigh {
		t.Fatalf("compiled LossPriority=%q, want LossPriorityHigh", entry.LossPriority)
	}
	if sched := cfg.ClassOfService.Schedulers["be-sched"]; sched == nil || sched.Priority != SchedulerPriorityStrictHigh {
		t.Fatalf("compiled scheduler Priority=%+v, want strict-high", sched)
	}

	// Tunnel mode compiles to the typed const; the ip- default stays ipip.
	tunTree := flatTreeFromSets(t,
		"set interfaces gr-0/0/0 tunnel mode ip6gre",
		"set interfaces gr-0/0/0 tunnel source 192.0.2.1",
		"set interfaces gr-0/0/0 tunnel destination 192.0.2.2",
		"set interfaces ip-0/0/0 tunnel source 192.0.2.1",
		"set interfaces ip-0/0/0 tunnel destination 192.0.2.2",
	)
	// The ip-* default is ipip, which strict commit rejects (#4785);
	// the lenient path keeps it typed as TunnelModeIPIP.
	tunCfg, err := CompileConfigLenient(tunTree)
	if err != nil {
		t.Fatalf("compile tunnels: %v", err)
	}
	if got := tunCfg.Interfaces.Interfaces["gr-0/0/0"].Tunnel.Mode; got != TunnelModeIP6GRE {
		t.Fatalf("gr tunnel Mode=%q, want TunnelModeIP6GRE", got)
	}
	if got := tunCfg.Interfaces.Interfaces["ip-0/0/0"].Tunnel.Mode; got != TunnelModeIPIP {
		t.Fatalf("ip tunnel Mode=%q, want TunnelModeIPIP default", got)
	}
}
