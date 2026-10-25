package config

import (
	"net"
	"reflect"
	"testing"
)

// #16544 — wildcard-address must use Junos polarity (mask 1 = compared).
// The pre-fix Cisco polarity inverted every mask: the host wildcard
// 255.255.255.255 became 0.0.0.0/0 and every genuine Junos mask was
// refused as non-contiguous.

func TestWildcardPolarityAcceptance16544(t *testing.T) {
	// Acceptance from the issue, via the strict compiler + UsableValues
	// (the exact values the userspace resolver consumes).
	for _, tc := range []struct{ spec, want string }{
		{"10.1.2.3/255.255.255.0", "10.1.2.0/24"},
		{"10.1.2.3/255.255.255.255", "10.1.2.3/32"},
		{"2001:db8::1/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "2001:db8::1/128"},
	} {
		cfg, err := CompileConfig(soleFormTree(t, `address wc { wildcard-address `+tc.spec+`; }`))
		if err != nil {
			t.Fatalf("%s: strict commit refused Junos wildcard: %v", tc.spec, err)
		}
		if got := cfg.Security.AddressBook.Addresses["wc"].UsableValues(); !reflect.DeepEqual(got, []string{tc.want}) {
			t.Fatalf("%s: UsableValues=%v want [%s]", tc.spec, got, tc.want)
		}
	}
	// 10.1.2.3/0.0.0.255 must never yield 10.1.2.0/24 (or /0 as the
	// inverted host): under Junos polarity it is non-contiguous → refuse.
	got, err := expandWildcardAddress("10.1.2.3/0.0.0.255")
	if err == nil || got == "10.1.2.0/24" || got == "0.0.0.0/0" {
		t.Fatalf("Cisco-polarity mask: got=%q err=%v, want refusal", got, err)
	}
	if _, err := CompileConfig(soleFormTree(t, `address wc { wildcard-address 10.1.2.3/0.0.0.255; }`)); err == nil {
		t.Fatal("Cisco-polarity mask must be refused at strict commit")
	}
	// Membership sanity for the /24: Junos member 10.1.2.77 in, 99.9.9.3 out.
	_, ipnet, err := net.ParseCIDR("10.1.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if !ipnet.Contains(net.ParseIP("10.1.2.77")) || ipnet.Contains(net.ParseIP("99.9.9.3")) {
		t.Fatal("10.1.2.0/24 membership inverted")
	}
	// Family mismatch and malformed masks refused, never widened.
	for _, spec := range []string{"10.1.2.3/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "2001:db8::1/255.255.255.0", "10.1.2.3/notamask", "10.1.2.3"} {
		if got, err := expandWildcardAddress(spec); err == nil {
			t.Errorf("expandWildcardAddress(%q)=%q want error", spec, got)
		}
	}
}
