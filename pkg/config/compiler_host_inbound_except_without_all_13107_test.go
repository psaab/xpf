// #13107 (deep-review D1-02): a host-inbound-traffic `except` exclusion had
// no check that it subtracts from a positive `all` in the SAME stanza. A
// stanza authoring only `system-services telnet except` (assuming `all` was
// implied), or `all except` / `any-service except`, compiled silently to a
// non-nil EMPTY deny-all HostInboundTraffic, locking out all zone/interface
// host-inbound traffic with zero errors or warnings. The exclusions filter
// (hostInboundFilterExcept) subtracts the excluded token from the positive
// list; with no `all` token present there is nothing to subtract from, and
// when the exclusion names `all` itself it removes the whole positive list.
// Strict commits must reject all three shapes; tolerant loads keep the
// compiled stanza but warn (#1960 no-brick). An exclusion carried by one
// #12317-unioned interface contributor against another contributor's `all`
// stays valid (its positive base arrives through the union), so only the
// standalone stanza shapes are gated here.
package config

import (
	"strings"
	"testing"
)

// strictRejectCases13107 are stanza shapes that must not compile on the
// strict path: each carries a known `except` exclusion whose stanza has no
// positive `all` base to subtract from (including the self-canceling
// `all except` / `any-service except`). Names cover the zone stanza and a
// per-interface stanza on both admission planes.
var strictRejectCases13107 = []struct {
	name       string
	directives []string
	wantText   string
}{
	{
		name:       "zone services standalone except",
		directives: []string{"set security zones security-zone trust host-inbound-traffic system-services telnet except"},
		wantText:   "telnet",
	},
	{
		name:       "zone services all except",
		directives: []string{"set security zones security-zone trust host-inbound-traffic system-services all except"},
		wantText:   "all",
	},
	{
		name:       "zone services any-service except",
		directives: []string{"set security zones security-zone trust host-inbound-traffic system-services any-service except"},
		wantText:   "any-service",
	},
	{
		name: "zone services any-service except with positive sibling",
		directives: []string{
			"set security zones security-zone trust host-inbound-traffic system-services any-service except",
			"set security zones security-zone trust host-inbound-traffic system-services ping",
		},
		wantText: "any-service",
	},
	{
		name: "zone services named except without all and positive sibling",
		directives: []string{
			"set security zones security-zone trust host-inbound-traffic system-services telnet except",
			"set security zones security-zone trust host-inbound-traffic system-services ping",
		},
		wantText: "telnet",
	},
	{
		name:       "zone protocols all except",
		directives: []string{"set security zones security-zone trust host-inbound-traffic protocols all except"},
		wantText:   "protocols",
	},
	{
		name:       "zone protocols standalone except",
		directives: []string{"set security zones security-zone trust host-inbound-traffic protocols ospf except"},
		wantText:   "ospf",
	},
	{
		name:       "interface services standalone except",
		directives: []string{crossScopeUnit12317 + "system-services telnet except"},
		wantText:   "telnet",
	},
	{
		name:       "interface services all except",
		directives: []string{crossScopeUnit12317 + "system-services all except"},
		wantText:   "all",
	},
	{
		name:       "interface protocols all except",
		directives: []string{crossScopeUnit12317 + "protocols bgp except"},
		wantText:   "bgp",
	},
}

func TestHostInboundExceptWithoutAllStrictRejects13107(t *testing.T) {
	for _, tc := range strictRejectCases13107 {
		t.Run(tc.name, func(t *testing.T) {
			tree := flat10292(t, append([]string{
				"set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24",
				"set security zones security-zone trust interfaces ge-0/0/0.0",
			}, tc.directives...)...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("strict compile accepted %q with no error; want a fail-closed rejection naming %q (D1-02)", tc.name, tc.wantText)
			}
			if !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("strict compile error for %q = %v, want it to name %q", tc.name, err, tc.wantText)
			}
			if !strings.Contains(err.Error(), "except") {
				t.Fatalf("strict compile error for %q = %v, want it to mention the except exclusion", tc.name, err)
			}
		})
	}
}

// TestHostInboundExceptWithoutAllLenientWarns13107: tolerant load must not
// brick on an already-persisted stanza (the #12054/#12313 shape), but it
// must surface a warning naming the offending exclusion rather than
// silently installing the empty deny-all.
func TestHostInboundExceptWithoutAllLenientWarns13107(t *testing.T) {
	for _, tc := range strictRejectCases13107 {
		t.Run(tc.name, func(t *testing.T) {
			tree := flat10292(t, append([]string{
				"set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24",
				"set security zones security-zone trust interfaces ge-0/0/0.0",
			}, tc.directives...)...)
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile failed for %q: %v", tc.name, err)
			}
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, tc.wantText) && strings.Contains(warning, "except") {
					return
				}
			}
			t.Fatalf("lenient compile of %q produced no warning naming %q + except: %v", tc.name, tc.wantText, cfg.Warnings)
		})
	}
}

// TestHostInboundExceptWithAllStillCompiles13107 is the positive control:
// `all` minus a named exclusion is valid Junos and must keep compiling in
// both modes, with the exclusion applied.
func TestHostInboundExceptWithAllStillCompiles13107(t *testing.T) {
	for _, lenient := range []bool{false, true} {
		cfg := compileCrossScopeExcept12317(t, lenient,
			"set security zones security-zone trust host-inbound-traffic system-services all",
			"set security zones security-zone trust host-inbound-traffic system-services telnet except",
			"set security zones security-zone trust host-inbound-traffic protocols all",
			"set security zones security-zone trust host-inbound-traffic protocols ospf except",
		)
		hib := cfg.Security.Zones["trust"].HostInboundTraffic
		if hib == nil {
			t.Fatalf("lenient=%t: zone stanza lost", lenient)
		}
		for _, svc := range hib.SystemServices {
			if svc == "telnet" {
				t.Fatalf("lenient=%t: telnet survived its own except exclusion: %v", lenient, hib.SystemServices)
			}
		}
		for _, proto := range hib.Protocols {
			if proto == "ospf" {
				t.Fatalf("lenient=%t: ospf survived its own except exclusion: %v", lenient, hib.Protocols)
			}
		}
		if len(hib.SystemServices) == 0 || len(hib.Protocols) == 0 {
			t.Fatalf("lenient=%t: all-except-<named> collapsed to empty (services=%v protocols=%v)", lenient, hib.SystemServices, hib.Protocols)
		}
	}
}

// TestHostInboundCrossScopeExceptStillCompiles13107: an exclusion in one
// #12317-unioned interface contributor subtracting from another
// contributor's `all` has its positive base through the union; the
// stanza-local gate must not reject it in either mode.
func TestHostInboundCrossScopeExceptStillCompiles13107(t *testing.T) {
	for _, lenient := range []bool{false, true} {
		cfg := compileCrossScopeExcept12317(t, lenient,
			crossScopeUnit12317+"system-services all",
			crossScopePhysical12317+"system-services ssh except",
		)
		effective := ResolveInterfaceHostInbound(cfg)[crossScopeExceptUnit12317]
		if effective == nil {
			t.Fatalf("lenient=%t: no effective override", lenient)
		}
		assertExceptSSHPorts12317(t, effective.SystemServices, false, true, true)
	}
}

// TestHostInboundPhysicalExceptValidatesEveryUnit13107 catches a physical
// override that is made valid on unit 0 by that unit's `all`, but still leaves
// unit 1 with an empty deny-all when it inherits only the physical exclusion.
func TestHostInboundPhysicalExceptValidatesEveryUnit13107(t *testing.T) {
	directives := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24",
		"set interfaces ge-0/0/0 unit 1 family inet address 192.0.2.2/24",
		"set security zones security-zone trust interfaces ge-0/0/0",
		crossScopePhysical12317 + "system-services ssh except",
		crossScopeUnit12317 + "system-services all",
	}
	if _, err := CompileConfig(flat10292(t, directives...)); err == nil || !strings.Contains(err.Error(), ".1") {
		t.Fatalf("strict compile error = %v, want unit 1's empty effective admission rejected", err)
	}
}
