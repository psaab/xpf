package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func compileLenientDNATPool10289(t *testing.T, addressCommand string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, command := range []string{
		addressCommand,
		"set security nat destination rule-set RS from zone untrust",
		"set security nat destination rule-set RS rule R1 match destination-address 203.0.113.10/32",
		"set security nat destination rule-set RS rule R1 then destination-nat pool p1",
	} {
		path, err := config.ParseSetCommand(command)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", command, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", command, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	return cfg
}

// #10289: compile the actual `address A to B` set command through the tolerant
// path, then ensure the snapshot builder honors the retained marker and
// publishes no rule rather than installing endpoint B. The single-host
// positive control proves this is not an over-broad pool exclusion.
func TestDNATPoolAddressRangeFailsClosedInSnapshot10289(t *testing.T) {
	rangeCfg := compileLenientDNATPool10289(t,
		"set security nat destination pool p1 address 10.1.0.1 to 10.1.0.9")
	rangePool := rangeCfg.Security.NAT.Destination.Pools["p1"]
	if rangePool.AddressInvalidSpec == "" || rangePool.Address == "10.1.0.9" {
		t.Fatalf("range parser state = (%q, %q), want retained non-collapsed marker",
			rangePool.Address, rangePool.AddressInvalidSpec)
	}
	if snaps := buildDestinationNATSnapshots(rangeCfg, nil); len(snaps) != 0 {
		t.Fatalf("unsupported DNAT range published snapshots: %+v", snaps)
	}

	singleCfg := compileLenientDNATPool10289(t,
		"set security nat destination pool p1 address 10.1.0.1")
	singlePool := singleCfg.Security.NAT.Destination.Pools["p1"]
	if singlePool.AddressInvalidSpec != "" {
		t.Fatalf("single-address pool retained invalid marker %q", singlePool.AddressInvalidSpec)
	}
	snaps := buildDestinationNATSnapshots(singleCfg, nil)
	if len(snaps) != 1 || snaps[0].PoolAddress != "10.1.0.1" {
		t.Fatalf("single-address snapshots = %+v, want one host entry", snaps)
	}
}
