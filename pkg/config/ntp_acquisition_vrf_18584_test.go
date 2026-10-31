package config

import (
	"strings"
	"testing"
)

// #18584: which routing instance chrony's NTP client sockets are bound to.
// chrony has ONE acquisition device, so the decision is all-or-nothing.
func TestNTPAcquisitionInstance18584(t *testing.T) {
	for _, tc := range []struct {
		name    string
		lines   []string
		wantRI  string
		wantOK  bool
		wantWhy string
	}{
		{"no servers", nil, "", true, ""},
		{"default instance", []string{"set system ntp server 192.0.2.1"}, "", true, ""},
		{"management VRF", []string{
			"set system ntp server 192.0.2.1 routing-instance mgmt",
			"set system ntp server 192.0.2.2 routing-instance mgmt",
		}, "mgmt", true, ""},
		{"configured virtual-router", []string{
			"set routing-instances blue instance-type virtual-router",
			"set system ntp server 192.0.2.1 routing-instance blue",
		}, "blue", true, ""},
		{"mixed instances", []string{
			"set system ntp server 192.0.2.1 routing-instance mgmt",
			"set system ntp server 192.0.2.2",
		}, "", false, "different routing-instances"},
		{"unknown instance", []string{"set system ntp server 192.0.2.1 routing-instance nosuch"}, "", false, "not configured"},
		{"forwarding instance has no VRF", []string{
			"set routing-instances fbf instance-type forwarding",
			"set system ntp server 192.0.2.1 routing-instance fbf",
		}, "", false, "forwarding"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compileSetLinesT(t, append([]string{"set system host-name fw0"}, tc.lines...))
			ri, ok, why := NTPAcquisitionInstance(&cfg.System, cfg.RoutingInstances)
			if ri != tc.wantRI || ok != tc.wantOK || !strings.Contains(why, tc.wantWhy) {
				t.Fatalf("NTPAcquisitionInstance = (%q, %v, %q), want (%q, %v, *%s*)",
					ri, ok, why, tc.wantRI, tc.wantOK, tc.wantWhy)
			}
			warned := strings.Contains(strings.Join(cfg.Warnings, "\n"), "system ntp server routing-instance: accepted but NOT enforced")
			if warned == tc.wantOK {
				t.Fatalf("NOT-enforced advisory present=%v, want %v (it must fire exactly when the instance is not honoured); warnings=%q",
					warned, !tc.wantOK, cfg.Warnings)
			}
		})
	}
}

func hasClusterNTPInstanceAdvisory18584(cfg *Config) bool {
	for _, w := range cfg.Warnings {
		if w == clusterNTPDefaultInstanceAdvisory {
			return true
		}
	}
	return false
}

// #18584: a cluster whose NTP servers are reached through the default instance
// warns at commit — the secondary has no default-instance route off the box.
// The same cluster with `routing-instance mgmt` does not, a standalone node does
// not, and the tolerant (boot / peer-sync) paths stay silent like #8357's.
func TestClusterNTPDefaultInstanceAdvisory18584(t *testing.T) {
	withNTP := func(extra ...string) []string {
		return append(append([]string{}, clusterCmds8357...), extra...)
	}
	if cfg := compile8357(t, withNTP("set system ntp server 192.0.2.1"), CompileConfig); !hasClusterNTPInstanceAdvisory18584(cfg) {
		t.Fatalf("a cluster with default-instance NTP must warn; warnings=%q", cfg.Warnings)
	}
	if cfg := compile8357(t, withNTP("set system ntp server 192.0.2.1 routing-instance mgmt"), CompileConfig); hasClusterNTPInstanceAdvisory18584(cfg) {
		t.Fatalf("a cluster with NTP in the management VRF must not warn; warnings=%q", cfg.Warnings)
	}
	if cfg := compile8357(t, clusterCmds8357, CompileConfig); hasClusterNTPInstanceAdvisory18584(cfg) || !hasNTPAdvisory8357(cfg) {
		t.Fatalf("no NTP at all is #8357's advisory, not this one; warnings=%q", cfg.Warnings)
	}
	if cfg := compile8357(t, []string{"set system host-name fw0", "set system ntp server 192.0.2.1"}, CompileConfig); hasClusterNTPInstanceAdvisory18584(cfg) {
		t.Fatalf("a standalone node must not carry the cluster advisory; warnings=%q", cfg.Warnings)
	}
	if cfg := compile8357(t, withNTP("set system ntp server 192.0.2.1"), CompileConfigLenient); hasClusterNTPInstanceAdvisory18584(cfg) {
		t.Fatalf("the tolerant path must stay silent; warnings=%q", cfg.Warnings)
	}
}
