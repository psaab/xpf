package config

import (
	"os"
	"strings"
	"testing"
)

// #15649 RED/GREEN: shared SSOT renderers. On pre-fix code these symbols do
// not exist (build RED); assertions below fail on the old divergent literals
// (ICMP 30s, bare 0s, #5804 GRE, IPFIX-only "No flow monitoring").

func TestRenderFlowTimeoutsParity15649(t *testing.T) {
	cfg := &Config{}
	cfg.Security.Flow.GREPerformanceAcceleration = true
	var sb strings.Builder
	RenderFlowTimeouts(&sb, cfg)
	out := sb.String()
	for _, want := range []string{"ICMP session timeout:", "60s (default)", "UDP session timeout:", "TCP established timeout:", "1800s (default)", "#7188", "RFC 2890"} {
		if !strings.Contains(out, want) {
			t.Errorf("unset flow timeouts missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "30s (default)") && strings.Contains(out, "ICMP") {
		// specifically ICMP must not be 30s
		for _, l := range strings.Split(out, "\n") {
			if strings.Contains(l, "ICMP") && strings.Contains(l, "30s") {
				t.Errorf("ICMP still 30s: %q", l)
			}
		}
	}
	if strings.Contains(out, "0s\n") {
		t.Errorf("bare 0s for unset timeout:\n%s", out)
	}
	if strings.Contains(out, "#5804") || strings.Contains(out, "remain 5-tuple") {
		t.Errorf("stale #5804 GRE text:\n%s", out)
	}
	cfg2 := &Config{}
	cfg2.Security.Flow.ICMPSessionTimeout = 45
	cfg2.Security.Flow.TCPSession = &TCPSessionConfig{EstablishedTimeout: 600}
	var sb2 strings.Builder
	RenderFlowTimeouts(&sb2, cfg2)
	if !strings.Contains(sb2.String(), "45s") || !strings.Contains(sb2.String(), "600s") {
		t.Errorf("configured values lost:\n%s", sb2.String())
	}
}

func TestDataplaneTimeoutConstantsMatchRust15649(t *testing.T) {
	b, err := os.ReadFile("../../userspace-dp/src/session/mod.rs")
	if err != nil {
		t.Skipf("rust source unavailable: %v", err)
	}
	s := string(b)
	if !strings.Contains(s, "DEFAULT_UDP_SESSION_TIMEOUT_NS: u64 = 60_") {
		t.Fatalf("rust UDP default drifted")
	}
	if !strings.Contains(s, "DEFAULT_ICMP_SESSION_TIMEOUT_NS: u64 = 60_") {
		t.Fatalf("rust ICMP default drifted")
	}
	if DataplaneUDPSessionTimeoutSecs != 60 || DataplaneICMPSessionTimeoutSecs != 60 {
		t.Fatalf("go defaults drifted")
	}
}

func TestExpandedApplicationNames15649(t *testing.T) {
	cfg := &Config{}
	cfg.Applications.Applications = map[string]*Application{
		"custom-term-t1": {Name: "custom-term-t1", Protocol: "tcp", DestinationPort: "443", ALG: "ssl"},
		"custom-term-t2": {Name: "custom-term-t2", Protocol: "udp", DestinationPort: "443"},
		"plain":          {Name: "plain", Protocol: "tcp", DestinationPort: "22"},
	}
	cfg.Applications.ApplicationSets = map[string]*ApplicationSet{
		"custom": {Name: "custom", Applications: []string{"custom-term-t1", "custom-term-t2"}},
		"outer":  {Name: "outer", Applications: []string{"custom", "junos-ssh"}},
	}
	names, ok := ExpandedApplicationNames(cfg, "outer")
	if !ok || strings.Join(names, ",") != "custom-term-t1,custom-term-t2,junos-ssh" {
		t.Fatalf("outer expansion = %v,%v", names, ok)
	}
	app, ok := ResolvedApplication(cfg, "junos-ssh")
	if !ok || app.DestinationPort != "22" {
		t.Fatalf("predefined resolve = %+v,%v", app, ok)
	}
	if got := ApplicationSetExpandedMembers(cfg, cfg.Applications.ApplicationSets["outer"]); got != "custom-term-t1, custom-term-t2, junos-ssh" {
		t.Fatalf("members = %q", got)
	}
}

func TestPolicyDetailStats15649(t *testing.T) {
	pol := &Policy{Name: "p", Count: true}
	var sb strings.Builder
	disabled, err := PolicyDetailStats(&sb, "  ", "  ", pol, false, false, func(uint32) (PolicyCounter, error) {
		return PolicyCounter{Packets: 7, Bytes: 700}, nil
	}, 0)
	if disabled || err != nil {
		t.Fatalf("disabled=%v err=%v", disabled, err)
	}
	if !strings.Contains(sb.String(), "count") || !strings.Contains(sb.String(), "7 packets, 700 bytes") {
		t.Fatalf("stats missing:\n%s", sb.String())
	}
	var sb2 strings.Builder
	disabled, _ = PolicyDetailStats(&sb2, "  ", "  ", &Policy{Name: "q"}, false, false, nil, 0)
	if !disabled {
		t.Fatalf("expected statsDisabled when off and no count")
	}
}

func TestRenderFlowMonitoringIPFIXOnly15649(t *testing.T) {
	cfg := &Config{}
	cfg.Services.FlowMonitoring = &FlowMonitoringConfig{VersionIPFIX: &NetFlowIPFIXConfig{Templates: map[string]*NetFlowIPFIXTemplate{
		"ipfix1": {Name: "ipfix1", FlowActiveTimeout: 60},
	}}}
	cfg.ForwardingOptions.Sampling = &SamplingConfig{Instances: map[string]*SamplingInstance{
		"s1": {Name: "s1", FamilyInet: &SamplingFamily{InlineJflow: true, InlineJflowSourceAddress: "10.0.0.1", FlowServers: []*FlowServer{{Address: "192.0.2.1", Port: 4739, VersionIPFIXTemplate: "ipfix1"}}}},
	}}
	var sb strings.Builder
	RenderFlowMonitoring(&sb, cfg, func(fs *FlowServer) string {
		if r := FlowServerExcludedReason(fs); r != "" {
			return "  [NOT INSTALLED: " + r + "]"
		}
		return ""
	})
	out := sb.String()
	if strings.Contains(out, "No flow monitoring configured") {
		t.Fatalf("IPFIX-only rendered as unconfigured:\n%s", out)
	}
	for _, want := range []string{"IPFIX", "ipfix1", "IPFIX template: ipfix1", "Inline jflow source: 10.0.0.1"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	// Unresolvable collector (no port) must be NOT INSTALLED.
	cfg2 := &Config{}
	cfg2.ForwardingOptions.Sampling = &SamplingConfig{Instances: map[string]*SamplingInstance{
		"s1": {Name: "s1", FamilyInet: &SamplingFamily{FlowServers: []*FlowServer{{Address: "192.0.2.9"}}}},
	}}
	var sb3 strings.Builder
	RenderFlowMonitoring(&sb3, cfg2, func(fs *FlowServer) string {
		if r := FlowServerExcludedReason(fs); r != "" {
			return "  [NOT INSTALLED: " + r + "]"
		}
		return ""
	})
	if !strings.Contains(sb3.String(), "NOT INSTALLED") {
		t.Errorf("bad collector not annotated:\n%s", sb3.String())
	}
}

func TestScreenChecksAlarmWithoutDrop15649(t *testing.T) {
	p := &ScreenProfile{AlarmWithoutDrop: true}
	p.TCP.Land = true
	checks := ScreenChecks(p)
	found := false
	for _, c := range checks {
		if c == ScreenCheckAlarmWithoutDrop {
			found = true
		}
	}
	if !found {
		t.Fatalf("alarm-without-drop missing from ScreenChecks: %v", checks)
	}
	if got := ScreenChecks(&ScreenProfile{}); len(got) != 0 {
		t.Fatalf("drop profile must not emit alarm token: %v", got)
	}
}
