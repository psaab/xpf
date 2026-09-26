package config

import (
	"strings"
	"testing"
)

func TestIPsecProposalLifetimeUpperBound10882(t *testing.T) {
	const (
		maxLifetime = "86400"
		overLimit   = "315360000"
	)
	const ikeBody = "   authentication-method pre-shared-keys;\n   dh-group group14;\n" +
		"   authentication-algorithm sha-256;\n   encryption-algorithm aes-256-cbc;\n"
	const espBody = "   protocol esp;\n   authentication-algorithm hmac-sha-256-128;\n" +
		"   encryption-algorithm aes-256-cbc;\n"
	phases := []struct {
		name, stanza, body string
		lifetime           func(*Config) (int, bool)
	}{
		{"ike", "ike", ikeBody, func(c *Config) (int, bool) {
			p, ok := c.Security.IPsec.IKEProposals["p1"]
			if !ok || p == nil {
				return 0, false
			}
			return p.LifetimeSeconds, true
		}},
		{"ipsec", "ipsec", espBody, func(c *Config) (int, bool) {
			p, ok := c.Security.IPsec.Proposals["p1"]
			if !ok || p == nil {
				return 0, false
			}
			return p.LifetimeSeconds, true
		}},
	}

	for _, phase := range phases {
		t.Run(phase.name, func(t *testing.T) {
			valid := ipsecLifetimeTree9008(t, phase.stanza, phase.body, maxLifetime)
			if err := SchemaValidate(valid, nil); err != nil {
				t.Fatalf("Junos maximum lifetime %s must pass schema validation: %v", maxLifetime, err)
			}
			if _, err := CompileConfig(valid); err != nil {
				t.Fatalf("Junos maximum lifetime %s must compile: %v", maxLifetime, err)
			}

			tooLong := ipsecLifetimeTree9008(t, phase.stanza, phase.body, overLimit)
			if err := SchemaValidate(tooLong, nil); err == nil || !strings.Contains(err.Error(), overLimit) {
				t.Fatalf("schema must reject and name over-limit lifetime %s, got %v", overLimit, err)
			}
			if _, err := CompileConfig(tooLong); err == nil || !strings.Contains(err.Error(), "lifetime-seconds") {
				t.Fatalf("strict compile must reject over-limit lifetime %s, got %v", overLimit, err)
			}

			cfg, err := CompileConfigLenient(tooLong)
			if err != nil {
				t.Fatalf("tolerant load must retain compatibility for over-limit lifetime: %v", err)
			}
			got, ok := phase.lifetime(cfg)
			if !ok {
				t.Fatal("tolerant compile dropped the proposal")
			}
			if got != 86400 {
				t.Fatalf("tolerant lifetime = %d, want clamped Junos maximum 86400", got)
			}
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "lifetime") && strings.Contains(warning, overLimit) {
					return
				}
			}
			t.Fatalf("tolerant compile must advise about over-limit lifetime %s, warnings: %v", overLimit, cfg.Warnings)
		})
	}
}

func TestIPsecDPDLenientClampsBounds10882(t *testing.T) {
	for _, scope := range []string{"ike", "ipsec"} {
		t.Run(scope, func(t *testing.T) {
			prefix := "set security " + scope + " gateway gw1 dead-peer-detection "
			tree := flatTreeFromSets(t,
				"set security "+scope+" gateway gw1 address 198.51.100.1",
				prefix+"interval 999999999",
				prefix+"threshold 999999999",
			)
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("tolerant compile: %v", err)
			}
			gw := cfg.Security.IPsec.Gateways["gw1"]
			if gw == nil {
				t.Fatal("gateway was not compiled")
			}
			if gw.DPDInterval != 3600 {
				t.Errorf("DPD interval = %d, want clamped maximum 3600", gw.DPDInterval)
			}
			if gw.DPDThreshold != 100 {
				t.Errorf("DPD threshold = %d, want clamped maximum 100", gw.DPDThreshold)
			}
		})
	}
}

func TestIPsecDPDLenientClampsPackedValues10882(t *testing.T) {
	tree := hierTree(t, `security {
    ike {
        gateway gw1 {
            address 198.51.100.1;
            dead-peer-detection interval 999999999 threshold 999999999;
        }
    }
}`)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	gw := cfg.Security.IPsec.Gateways["gw1"]
	if gw == nil {
		t.Fatal("gateway was not compiled")
	}
	if gw.DPDInterval != 3600 || gw.DPDThreshold != 100 {
		t.Fatalf("packed DPD values = (%d, %d), want clamped (3600, 100)",
			gw.DPDInterval, gw.DPDThreshold)
	}
}
