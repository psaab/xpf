package config

import "testing"

// #13214 (D3-08): compileFirewall dropped chained leaves under three-color
// policer rate containers and only read the first policer if-exceeding block.
// Persisted/peer-synced trees use CompileConfigLenient, where dropped rate
// leaves made otherwise loadable configs fail completeness validation.

func TestThreeColorPolicerFlatRun13214(t *testing.T) {
	tree := buildTree(t, []string{
		"set firewall three-color-policer tcp1 single-rate committed-information-rate 1m committed-burst-size 15k excess-burst-size 30k",
		"set firewall three-color-policer tcp1 then discard",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient flat single-rate run: %v", err)
	}
	tcp := cfg.Firewall.ThreeColorPolicers["tcp1"]
	if tcp == nil {
		t.Fatal("tcp1 missing")
	}
	// 1m bits = 125000 bytes/sec; 15k=15000; 30k=30000
	if tcp.CIR != 125000 || tcp.CBS != 15000 || tcp.PBS != 30000 {
		t.Fatalf("single-rate flat run: CIR=%d CBS=%d PBS=%d want 125000/15000/30000", tcp.CIR, tcp.CBS, tcp.PBS)
	}
}

func TestThreeColorPolicerTwoRateFlatRun13214(t *testing.T) {
	tree := buildTree(t, []string{
		"set firewall three-color-policer tcp2 two-rate committed-information-rate 1m committed-burst-size 15k peak-information-rate 2m peak-burst-size 30k",
		"set firewall three-color-policer tcp2 then discard",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient flat two-rate run: %v", err)
	}
	tcp := cfg.Firewall.ThreeColorPolicers["tcp2"]
	if tcp == nil {
		t.Fatal("tcp2 missing")
	}
	if tcp.CIR != 125000 || tcp.CBS != 15000 || tcp.PIR != 250000 || tcp.PBS != 30000 {
		t.Fatalf("two-rate flat run: CIR=%d CBS=%d PIR=%d PBS=%d want 125000/15000/250000/30000", tcp.CIR, tcp.CBS, tcp.PIR, tcp.PBS)
	}
}

func TestPolicerSiblingContainersAST13214(t *testing.T) {
	leaf := func(name, val string) *Node { return &Node{Keys: []string{name, val}} }
	fwNode := &Node{Keys: []string{"firewall"}, Children: []*Node{
		{Keys: []string{"policer", "p1"}, Children: []*Node{
			{Keys: []string{"if-exceeding"}, Children: []*Node{leaf("bandwidth-limit", "1m")}},
			{Keys: []string{"if-exceeding"}, Children: []*Node{leaf("burst-size-limit", "15k")}},
			{Keys: []string{"then"}, Children: []*Node{{Keys: []string{"discard"}}}},
		}},
		{Keys: []string{"three-color-policer", "tcp1"}, Children: []*Node{
			{Keys: []string{"single-rate"}, Children: []*Node{leaf("committed-information-rate", "1m")}},
			{Keys: []string{"single-rate"}, Children: []*Node{leaf("committed-burst-size", "15k"), leaf("excess-burst-size", "30k")}},
			{Keys: []string{"then"}, Children: []*Node{{Keys: []string{"discard"}}}},
		}},
	}}
	fw := &FirewallConfig{}
	if err := compileFirewall(fwNode, fw); err != nil {
		t.Fatalf("compileFirewall: %v", err)
	}
	pol := fw.Policers["p1"]
	if pol == nil || pol.BandwidthLimit != 125000 || pol.BurstSizeLimit != 15000 {
		t.Fatalf("sibling if-exceeding dropped: %+v", pol)
	}
	tcp := fw.ThreeColorPolicers["tcp1"]
	if tcp == nil || tcp.CIR != 125000 || tcp.CBS != 15000 || tcp.PBS != 30000 {
		t.Fatalf("sibling single-rate dropped: %+v", tcp)
	}
}
