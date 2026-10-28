package configstore

import "testing"

// #17172: braced packed DPD (`dead-peer-detection { interval 20 threshold 3; }`)
// passed production CheckText under `security ike gateway` but was
// false-rejected under `security ipsec gateway` ("unknown modifier
// threshold") because only the ike schema copy set packedStatements on
// dead-peer-detection. Both parents now use gatewaySchemaNode, so the
// strict gate must give identical results.
func TestGatewayBracedPackedDPDCheckText17172(t *testing.T) {
	for _, parent := range []string{"ike", "ipsec"} {
		t.Run(parent, func(t *testing.T) {
			text := "security { " + parent + " { gateway g1 { dead-peer-detection { interval 20 threshold 3; } } } }"
			cfg, err := CheckText(text, -1)
			if err != nil {
				t.Fatalf("CheckText rejected braced packed DPD under %s: %v", parent, err)
			}
			gw := cfg.Security.IPsec.Gateways["g1"]
			if gw == nil {
				t.Fatal("gateway g1 not compiled")
			}
			if !gw.DPDEnable || gw.DPDInterval != 20 || gw.DPDThreshold != 3 {
				t.Fatalf("DPD = enable=%v interval=%d threshold=%d, want true/20/3", gw.DPDEnable, gw.DPDInterval, gw.DPDThreshold)
			}
		})
	}
}
