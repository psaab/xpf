package api

import "testing"

// TestNATPoolMetricsOmitAddressOnlyPortUsage9995 is a FAIL-ON-REVERT guard
// for the Prometheus port-statistics surface. Address-only pools have neither
// a port-capacity budget nor a translation-state usage sample to publish.
func TestNATPoolMetricsOmitAddressOnlyPortUsage9995(t *testing.T) {
	setLines := []string{
		"set security nat source pool p1 address 203.0.113.10/32",
		"set security nat source pool p1 port no-translation",
		"set security nat source pool p2 address 203.0.113.11/32",
		"set security nat source rule-set rs from zone trust",
		"set security nat source rule-set rs to zone untrust",
		"set security nat source rule-set rs rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set rs rule r1 then source-nat pool p1",
		"set security nat source rule-set rs rule r2 match source-address 172.16.0.0/12",
		"set security nat source rule-set rs rule r2 then source-nat pool p2",
	}
	poolIDs := map[string]uint8{"p1": 0, "p2": 1}
	got, _ := natPoolGauges(t, setLines, poolIDs)

	// The Prometheus API has no string N/A value, so an address-only pool
	// publishes neither its irrelevant port capacity nor usage series.
	if _, ok := got["p1"]; ok {
		t.Fatalf("address-only pool published xpf_nat_pool_total_ports = %v; PortLow/PortHigh are irrelevant",
			got["p1"])
	}
	if got["p2"] != 64512 {
		t.Fatalf("normal PAT control total ports = %v, want 64512", got["p2"])
	}

	seen := natPoolUsedPortsSamples(t, setLines, poolIDs)
	if seen["p1"] {
		t.Fatal("address-only pool published xpf_nat_pool_used_ports")
	}
	if !seen["p2"] {
		t.Fatal("normal PAT control omitted xpf_nat_pool_used_ports")
	}
}
