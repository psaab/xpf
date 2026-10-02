package ipsec

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #11690: resolveESPSettings silently first-won on divergent multi-proposal
// lifetimes while the IKE side (#10879) rejects the same shape. The child
// rekey_time is child-SA-level in swanctl, so the renderer must reject
// divergent survivor lifetimes instead of emitting the first.
func TestResolveESPSettingsRejectsDivergentLifetimes_11690(t *testing.T) {
	for _, tc := range []struct {
		name       string
		first      string
		second     string
		firstLife  int
		secondLife int
	}{
		{
			name:       "divergent lifetime first",
			first:      "esp-short",
			second:     "esp-long",
			firstLife:  3600,
			secondLife: 28800,
		},
		{
			name:       "divergent lifetime reversed",
			first:      "esp-long",
			second:     "esp-short",
			firstLife:  28800,
			secondLife: 3600,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.IPsecConfig{
				Proposals: map[string]*config.IPsecProposal{
					tc.first: {
						Name:            tc.first,
						Protocol:        "esp",
						EncryptionAlg:   "aes-256-cbc",
						AuthAlg:         "hmac-sha-256-128",
						DHGroup:         14,
						LifetimeSeconds: tc.firstLife,
					},
					tc.second: {
						Name:            tc.second,
						Protocol:        "esp",
						EncryptionAlg:   "aes-128-cbc",
						AuthAlg:         "hmac-sha-256-128",
						DHGroup:         14,
						LifetimeSeconds: tc.secondLife,
					},
				},
				Policies: map[string]*config.IPsecPolicyDef{
					"ipsec-pol": {Name: "ipsec-pol", Proposals: []string{tc.first, tc.second}},
				},
			}
			_, _, err := resolveESPSettings(cfg, &config.IPsecVPN{IPsecPolicy: "ipsec-pol"})
			if !errors.Is(err, errProposalUnresolved) {
				t.Fatalf("resolveESPSettings error = %v, want errProposalUnresolved", err)
			}
			for _, want := range []string{tc.first, tc.second, "lifetime-seconds"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not name %q", err, want)
				}
			}
		})
	}
}

// #11690 filtering-first cell: a bad FIRST proposal is filtered, so the
// effective lifetime silently shifts to the next survivor — and divergent
// survivors must still be rejected rather than first-win among themselves.
func TestResolveESPSettingsFilteringFirstDivergence_11690(t *testing.T) {
	proposal := func(name string, life int) *config.IPsecProposal {
		return &config.IPsecProposal{
			Name:            name,
			Protocol:        "esp",
			EncryptionAlg:   "aes-256-cbc",
			AuthAlg:         "hmac-sha-256-128",
			DHGroup:         14,
			LifetimeSeconds: life,
		}
	}
	cfg := &config.IPsecConfig{
		Proposals: map[string]*config.IPsecProposal{
			"esp-bad": {
				Name:               "esp-bad",
				Protocol:           "esp",
				EncryptionAlg:      "aes-256-cbc",
				AuthAlg:            "hmac-sha-256-128",
				DHGroupInvalidSpec: "nonsense",
				LifetimeSeconds:    9999,
			},
			"esp-short": proposal("esp-short", 3600),
			"esp-long":  proposal("esp-long", 28800),
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"ipsec-pol": {Name: "ipsec-pol", Proposals: []string{"esp-bad", "esp-short", "esp-long"}},
		},
	}
	_, _, err := resolveESPSettings(cfg, &config.IPsecVPN{IPsecPolicy: "ipsec-pol"})
	if !errors.Is(err, errProposalUnresolved) {
		t.Fatalf("resolveESPSettings error = %v, want errProposalUnresolved", err)
	}
	// The diagnostic must name the DIVERGENT SURVIVORS, not the filtered entry.
	for _, want := range []string{"esp-short", "esp-long", "lifetime-seconds"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "esp-bad") {
		t.Errorf("error %q names the filtered proposal instead of the divergent survivors", err)
	}
}

// #11690 single-emit control: agreeing survivors still render, with the one
// shared lifetime — the agreement gate only rejects DIVERGENCE.
func TestResolveESPSettingsAgreeingSurvivorsRender_11690(t *testing.T) {
	cfg := &config.IPsecConfig{
		Proposals: map[string]*config.IPsecProposal{
			"esp-bad": {
				Name:               "esp-bad",
				Protocol:           "esp",
				EncryptionAlg:      "aes-256-cbc",
				AuthAlg:            "hmac-sha-256-128",
				DHGroupInvalidSpec: "nonsense",
				LifetimeSeconds:    9999,
			},
			"esp-a": {
				Name:            "esp-a",
				Protocol:        "esp",
				EncryptionAlg:   "aes-256-cbc",
				AuthAlg:         "hmac-sha-256-128",
				DHGroup:         14,
				LifetimeSeconds: 3600,
			},
			"esp-b": {
				Name:            "esp-b",
				Protocol:        "esp",
				EncryptionAlg:   "aes-128-cbc",
				AuthAlg:         "hmac-sha-256-128",
				DHGroup:         14,
				LifetimeSeconds: 3600,
			},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"ipsec-pol": {Name: "ipsec-pol", Proposals: []string{"esp-bad", "esp-a", "esp-b"}},
		},
	}
	got, lifetime, err := resolveESPSettings(cfg, &config.IPsecVPN{IPsecPolicy: "ipsec-pol"})
	if err != nil {
		t.Fatalf("agreeing survivors must render, got error %v", err)
	}
	if lifetime != 3600 {
		t.Errorf("lifetime = %d, want 3600 (the shared survivor lifetime)", lifetime)
	}
	if !strings.Contains(got, ",") {
		t.Errorf("proposals = %q, want both survivors comma-joined", got)
	}
}
