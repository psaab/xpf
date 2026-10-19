package configstore

import (
	"strings"
	"testing"
)

// #15029 through the real operator check pipeline: a subnet-less DHCP pool
// (the flipped #14601 control) must be rejected naming the pool/subnet, and
// the valid control in the same shape must pass.
func TestCheckTextRefusesSubnetLessDHCPPool15029(t *testing.T) {
	noSubnet := "system { services { dhcp-local-server { group g1 { interface ge-0/0/0.0; " +
		"pool p1 { dns-server 10.0.61.53; } } } } }"
	if _, err := CheckText(noSubnet, 0); err == nil {
		t.Fatal("CheckText accepted a subnet-less DHCP pool (renders \"subnet\": \"\"; Kea refuses the whole file)")
	} else if !strings.Contains(err.Error(), "subnet") || !strings.Contains(err.Error(), "p1") {
		t.Fatalf("CheckText refusal must name the pool and subnet, got: %v", err)
	}
	valid := "system { services { dhcp-local-server { group g1 { interface ge-0/0/0.0; " +
		"pool p1 { subnet 10.0.61.0/24; dns-server 10.0.61.53; } } } } }"
	if _, err := CheckText(valid, 0); err != nil {
		t.Fatalf("control: a valid DHCP pool was refused: %v", err)
	}
}
