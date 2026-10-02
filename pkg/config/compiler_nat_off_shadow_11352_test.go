package config

// #11352: unsupported DNAT off-shadow shapes must remain operator-visible.

import (
	"strings"
	"testing"
)

func assertDNATOffShadow11352Warning(t *testing.T, lines []string, offRule string) {
	t.Helper()
	cfg, err := CompileConfig(buildTree(t, lines))
	if err != nil {
		t.Fatalf("CompileConfig rejected the residual shadow shape: %v", err)
	}
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "#11352") && strings.Contains(warning, offRule) {
			return
		}
	}
	t.Fatalf("expected an operator-visible #11352 warning naming %q, got %v", offRule, cfg.Warnings)
}

func TestDNATOffShadowAddressBookWarns11352(t *testing.T) {
	assertDNATOffShadow11352Warning(t, []string{
		"set security address-book global address svc-vip 192.0.2.10/32",
		"set security nat destination pool p1 address 192.168.1.10",
		"set security nat destination rule-set rs1 from zone untrust",
		"set security nat destination rule-set rs1 rule r-off match destination-address-name svc-vip",
		"set security nat destination rule-set rs1 rule r-off then destination-nat off",
		"set security nat destination rule-set rs1 rule r-translate match destination-address 192.0.2.10/32",
		"set security nat destination rule-set rs1 rule r-translate match destination-port 80",
		"set security nat destination rule-set rs1 rule r-translate then destination-nat pool p1",
	}, "r-off")
}

func TestDNATOffShadowApplicationWarns11352(t *testing.T) {
	assertDNATOffShadow11352Warning(t, []string{
		"set security nat destination pool p1 address 192.168.1.10",
		"set security nat destination rule-set rs1 from zone untrust",
		"set security nat destination rule-set rs1 rule r-off match destination-address 192.0.2.10/32",
		"set security nat destination rule-set rs1 rule r-off then destination-nat off",
		"set security nat destination rule-set rs1 rule r-translate match destination-address 192.0.2.10/32",
		"set security nat destination rule-set rs1 rule r-translate match application junos-http",
		"set security nat destination rule-set rs1 rule r-translate then destination-nat pool p1",
	}, "r-off")
}

func TestDNATOffShadowCrossRuleSetWarns11352(t *testing.T) {
	assertDNATOffShadow11352Warning(t, []string{
		"set security nat destination pool p1 address 192.168.1.10",
		"set security nat destination rule-set rs1 from zone untrust",
		"set security nat destination rule-set rs1 rule r-off match destination-address 192.0.2.10/32",
		"set security nat destination rule-set rs1 rule r-off then destination-nat off",
		"set security nat destination rule-set rs2 from zone untrust",
		"set security nat destination rule-set rs2 rule r-translate match destination-address 192.0.2.10/32",
		"set security nat destination rule-set rs2 rule r-translate match destination-port 80",
		"set security nat destination rule-set rs2 rule r-translate then destination-nat pool p1",
	}, "r-off")
}

func TestDNATOffShadowFeedExtendedAddressBookWarns11671(t *testing.T) {
	lines := append(feedServerBinding("svc-vip"),
		"set security address-book global address svc-vip 192.0.2.10/32",
		"set security address-book global address-set static-service-vips address svc-vip",
		"set security nat destination pool p1 address 192.168.1.10",
		"set security nat destination rule-set rs1 from zone untrust",
		"set security nat destination rule-set rs1 rule r-off match destination-address-name static-service-vips",
		"set security nat destination rule-set rs1 rule r-off then destination-nat off",
		"set security nat destination rule-set rs1 rule r-translate match destination-address 192.0.2.20/32",
		"set security nat destination rule-set rs1 rule r-translate then destination-nat pool p1",
	)
	assertDNATOffShadow11352Warning(t, lines, "r-off")
}

func TestDNATOffShadowApplicationAnyWarns11671(t *testing.T) {
	assertDNATOffShadow11352Warning(t, []string{
		"set security nat destination pool p1 address 192.168.1.10",
		"set security nat destination rule-set rs1 from zone untrust",
		"set security nat destination rule-set rs1 rule r-off match destination-address 192.0.2.10/32",
		"set security nat destination rule-set rs1 rule r-off match application any",
		"set security nat destination rule-set rs1 rule r-off then destination-nat off",
		"set security nat destination rule-set rs1 rule r-translate match destination-address 192.0.2.10/32",
		"set security nat destination rule-set rs1 rule r-translate match application any",
		"set security nat destination rule-set rs1 rule r-translate then destination-nat pool p1",
	}, "r-off")
}
