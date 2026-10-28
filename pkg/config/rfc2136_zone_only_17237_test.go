package config

import (
	"reflect"
	"testing"
)

// #17237 RED probe: a v6 dynamic-dns block holding only forward-zone or
// reverse-zone must be kept (not discarded as empty), so v6 does not
// silently inherit the v4 policy via EffectiveDynamicDNS.

func TestQ40DHCPDynamicDNSZoneOnlyBlockDropped17237(t *testing.T) {
	cases := []struct {
		name string
		leaf string
		val  string
	}{
		{"forward-zone only", "forward-zone", "v6.example."},
		{"reverse-zone only", "reverse-zone", "8.b.d.0.1.0.0.2.ip6.arpa."},
		{"update-server only (control)", "update-server", "2001:db8::53"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(buildTree(t, []string{
				"set system services dhcp-local-server dynamic-dns enable",
				"set system services dhcp-local-server dynamic-dns update-server 192.0.2.53",
				"set system services dhcp-local-server dynamic-dns forward-zone v4.example.",
				"set system services dhcpv6-local-server dynamic-dns " + tc.leaf + " " + tc.val,
			}))
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			v6 := cfg.System.DHCPServer.DynamicDNSv6
			if v6 == nil {
				t.Fatalf("DynamicDNSv6 nil=true for %s %q: zone-only v6 block discarded, v6 would inherit v4", tc.leaf, tc.val)
			}
			got := map[string]string{"forward-zone": v6.ForwardZone, "reverse-zone": v6.ReverseZone, "update-server": v6.UpdateServer}[tc.leaf]
			if got != tc.val {
				t.Fatalf("v6 %s = %q, want %q (full v6=%+v)", tc.leaf, got, tc.val, v6)
			}
			// v4 untouched
			if cfg.System.DHCPServer.DynamicDNS == nil || cfg.System.DHCPServer.DynamicDNS.ForwardZone != "v4.example." {
				t.Fatalf("v4 policy disturbed: %+v", cfg.System.DHCPServer.DynamicDNS)
			}
		})
	}
	// Provider control: zone-only provider is kept in catalog (already worked).
	cfg, err := CompileConfig(buildTree(t, []string{
		"set system services dynamic-dns provider p1 forward-zone v6.example.",
	}))
	if err != nil {
		t.Fatalf("CompileConfig provider: %v", err)
	}
	if cfg.System.Services.DynamicDNS == nil || cfg.System.Services.DynamicDNS.Providers["p1"] == nil {
		t.Fatalf("zone-only provider dropped from catalog")
	}
}

func TestRFC2136EndpointIsZeroCoversEveryField17237(t *testing.T) {
	typ := reflect.TypeOf(RFC2136Endpoint{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		var e RFC2136Endpoint
		v := reflect.ValueOf(&e).Elem().Field(i)
		switch v.Kind() {
		case reflect.String:
			v.SetString("x")
		case reflect.Bool:
			v.SetBool(true)
		default:
			// Secret etc: set via NewSecret if type matches
			if v.Type() == reflect.TypeOf(Secret{}) {
				v.Set(reflect.ValueOf(NewSecret("x")))
			} else {
				t.Fatalf("unhandled field kind %s for %s", v.Kind(), f.Name)
			}
		}
		if e.IsZero() {
			t.Fatalf("IsZero()=true with only %s set; IsZero does not read %s", f.Name, f.Name)
		}
	}
	if !(RFC2136Endpoint{}).IsZero() {
		t.Fatal("zero endpoint must be IsZero")
	}
}
