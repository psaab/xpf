package ipsec

import (
	"strings"
	"testing"
)

func TestRenderSkipsUnsupportedIPsecAlgorithms_10880(t *testing.T) {
	for _, slot := range []string{"ike", "esp"} {
		for _, value := range []string{"null", "aes-512-cbc"} {
			t.Run(slot+"/"+value, func(t *testing.T) {
				cfg := proposalRenderConfig9906(slot, value)
				text, rendered, err := (&Manager{}).renderConfig(cfg)
				if err != nil {
					t.Fatalf("render returned error instead of tolerant skip: %v", err)
				}
				if rendered["tun"] {
					t.Fatalf("proposal with unsupported %q was reported rendered", value)
				}
				if strings.Contains(text, "null") || strings.Contains(text, "aes512") {
					t.Fatalf("unsupported encryption reached swanctl output:\n%s", text)
				}
			})
		}
	}
}

func TestRenderSkipsNonAEADIKEWithoutIntegrity_10880(t *testing.T) {
	cfg := proposalRenderConfig9906("ike", "aes-256-cbc")
	cfg.IKEProposals["ike"].AuthAlg = ""
	text, rendered, err := (&Manager{}).renderConfig(cfg)
	if err != nil {
		t.Fatalf("render returned error instead of tolerant skip: %v", err)
	}
	if rendered["tun"] {
		t.Fatal("integrity-less non-AEAD IKE connection was reported rendered")
	}
	doc := parseSwanctlDoc(t, text)
	doc.hasNoSettingAnywhere(t, "proposals")
	doc.hasNoSettingAnywhere(t, "esp_proposals")
}

func TestRenderCanonicalizesUppercaseGCM_10880(t *testing.T) {
	for _, slot := range []string{"ike", "esp"} {
		t.Run(slot, func(t *testing.T) {
			cfg := proposalRenderConfig9906(slot, "AES-256-GCM")
			text, rendered, err := (&Manager{}).renderConfig(cfg)
			if err != nil {
				t.Fatalf("render uppercase GCM: %v", err)
			}
			if !rendered["tun"] {
				t.Fatalf("uppercase GCM proposal was not rendered:\n%s", text)
			}
			if strings.Contains(text, "AES-256-GCM") || !strings.Contains(text, "aes256gcm16") {
				t.Fatalf("uppercase GCM was not canonicalized in swanctl output:\n%s", text)
			}
		})
	}
}

func TestRenderSkipsUnsupportedIPsecIntegrity_10880(t *testing.T) {
	for _, slot := range []string{"ike", "esp"} {
		t.Run(slot, func(t *testing.T) {
			cfg := proposalRenderConfig9906(slot, "aes-256-cbc")
			if slot == "ike" {
				cfg.IKEProposals["ike"].AuthAlg = "sha-777"
			} else {
				cfg.Proposals["esp"].AuthAlg = "sha-777"
			}
			text, rendered, err := (&Manager{}).renderConfig(cfg)
			if err != nil {
				t.Fatalf("render returned error instead of tolerant skip: %v", err)
			}
			if rendered["tun"] || strings.Contains(text, "sha777") {
				t.Fatalf("unsupported integrity proposal reached swanctl output (rendered=%v):\n%s", rendered["tun"], text)
			}
		})
	}
}
