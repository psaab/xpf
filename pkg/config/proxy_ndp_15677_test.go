package config

import (
	"reflect"
	"strings"
	"testing"
)

// #15677: Junos `security nat proxy-ndp` was rejected by SchemaValidate and
// silently dropped by compile, despite docs/feature-gaps.md claiming Done
// (the Done referred to IPv6 under `proxy-arp`). Also `expandAddressRange`
// hard-failed IPv6 `address <low> to <high>` ranges.

func TestProxyNDP15677StanzaCompiles(t *testing.T) {
	for _, tc := range []struct {
		name string
		tree *ConfigTree
		want []string
	}{
		{"hier single v6", hierTree6659(t, `
security { nat { proxy-ndp { interface ge-0/0/0.0 { address 2001:db8::1; } } } }`),
			[]string{"2001:db8::1/128"}},
		{"hier v6 range", hierTree6659(t, `
security { nat { proxy-ndp { interface ge-0/0/0.0 { address 2001:db8::1 to 2001:db8::3; } } } }`),
			[]string{"2001:db8::1/128", "2001:db8::2/128", "2001:db8::3/128"}},
		{"hier v6 range under proxy-arp", hierTree6659(t, `
security { nat { proxy-arp { interface ge-0/0/0.0 { address 2001:db8::1 to 2001:db8::3; } } } }`),
			[]string{"2001:db8::1/128", "2001:db8::2/128", "2001:db8::3/128"}},
		{"flat v6 range", setTree6659(t,
			"set security nat proxy-ndp interface ge-0/0/0.0 address 2001:db8::1 to 2001:db8::3"),
			[]string{"2001:db8::1/128", "2001:db8::2/128", "2001:db8::3/128"}},
		{"flat v6 single", setTree6659(t,
			"set security nat proxy-ndp interface ge-0/0/0.0 address 2001:db8::5"),
			[]string{"2001:db8::5/128"}},
		{"both stanzas merge", hierTree6659(t, `
security { nat { proxy-arp { interface ge-0/0/0.0 { address 192.0.2.1; } } proxy-ndp { interface ge-0/0/1.0 { address 2001:db8::1; } } } }`),
			nil}, // checked separately below
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := SchemaValidate(tc.tree, nil); err != nil {
				t.Fatalf("SchemaValidate rejected proxy-ndp: %v", err)
			}
			cfg, err := CompileConfig(tc.tree)
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			if len(cfg.Security.NAT.ProxyARP) == 0 {
				t.Fatal("ProxyARP empty — proxy-ndp silently dropped")
			}
			if tc.want != nil {
				if got := cfg.Security.NAT.ProxyARP[0].Addresses; !reflect.DeepEqual(got, tc.want) {
					t.Fatalf("Addresses = %q, want %q", got, tc.want)
				}
			} else {
				if len(cfg.Security.NAT.ProxyARP) != 2 {
					t.Fatalf("want 2 merged entries, got %d: %+v", len(cfg.Security.NAT.ProxyARP), cfg.Security.NAT.ProxyARP)
				}
			}
			// Lenient must also compile.
			if _, err := CompileConfigLenient(tc.tree); err != nil {
				t.Fatalf("CompileConfigLenient: %v", err)
			}
		})
	}
}

func TestExpandAddressRangeIPv6_15677(t *testing.T) {
	got, err := expandAddressRange("2001:db8::1", "2001:db8::3")
	if err != nil {
		t.Fatalf("v6 range: %v", err)
	}
	if want := []string{"2001:db8::1/128", "2001:db8::2/128", "2001:db8::3/128"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
	// /128 suffixed endpoints
	got, err = expandAddressRange("2001:db8::ff/128", "2001:db8::101/128")
	if err != nil || len(got) != 3 {
		t.Fatalf("suffixed v6 range: got %q err %v", got, err)
	}
	// Mixed family must fail
	if _, err := expandAddressRange("10.0.0.1", "2001:db8::1"); err == nil {
		t.Fatal("mixed family must error")
	}
	if _, err := expandAddressRange("2001:db8::1", "10.0.0.1"); err == nil {
		t.Fatal("mixed family (reversed) must error")
	}
	// Reversed v6
	if _, err := expandAddressRange("2001:db8::3", "2001:db8::1"); err == nil {
		t.Fatal("reversed v6 range must error")
	}
	// Oversize v6 (>256)
	if _, err := expandAddressRange("2001:db8::", "2001:db8::100"); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("oversize v6 must be too-large, got %v", err)
	}
	// Exactly 256 v6
	got, err = expandAddressRange("2001:db8::0", "2001:db8::ff")
	if err != nil || len(got) != 256 {
		t.Fatalf("256 v6: len=%d err=%v", len(got), err)
	}
	// Pool caller: v6 pool range expands (appendPoolAddresses path via expandAddressRange already covered)
	// IPv4 unchanged
	got, err = expandAddressRange("10.0.0.1", "10.0.0.3")
	if err != nil || !reflect.DeepEqual(got, []string{"10.0.0.1/32", "10.0.0.2/32", "10.0.0.3/32"}) {
		t.Fatalf("v4 regression: %q %v", got, err)
	}
}

func TestProxyNDP15677BadAddressStrictRejectsLenientWarns(t *testing.T) {
	tree := hierTree6659(t, `
security { nat { proxy-ndp { interface ge-0/0/0.0 { address bogus; } } } }`)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("strict must reject bogus proxy-ndp address")
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient must load: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "proxy-ARP") || strings.Contains(w, "proxy-NDP") || strings.Contains(w, "bogus") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient must warn about bogus proxy-ndp address, warnings=%q", cfg.Warnings)
	}
}
