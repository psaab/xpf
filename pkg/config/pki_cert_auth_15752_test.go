package config

import (
	"strings"
	"testing"
)

// #15752 (G18-01/02/03): PKI / cert-auth chain.
//
//   - security pki is captured with an accepted-only advisory (no dangling
//     cert reference sold as implemented PKI lifecycle).
//   - ike policy local-certificate + ecdsa-signatures-256/384 compile.
//   - pubkey VPN without a local certificate is strict-rejected (render
//     belt in pkg/ipsec); psk VPN renders no certs (pkg/ipsec).
//   - gateway local/remote-identity distinguished-name (bare, container,
//     wildcard, direct DN) and key-id compile without dropping/stealing
//     tokens, in flat, packed and hierarchical spellings.

func pkiBaseCmds15752(authMethod string) []string {
	return []string{
		"set security ike proposal p1 authentication-method " + authMethod,
		"set security ike proposal p1 encryption-algorithm aes-256-cbc",
		"set security ike proposal p1 authentication-algorithm sha-256",
		"set security ike proposal p1 dh-group group14",
		"set security ike policy pol1 proposals p1",
		"set security ike gateway gw1 address 203.0.113.1",
		"set security ike gateway gw1 ike-policy pol1",
		"set security ipsec proposal ep1 protocol esp",
		"set security ipsec proposal ep1 encryption-algorithm aes-256-cbc",
		"set security ipsec proposal ep1 authentication-algorithm hmac-sha-256-128",
		"set security ipsec proposal ep1 dh-group group14",
		"set security ipsec policy epol1 proposals ep1",
		"set security ipsec vpn v1 gateway gw1",
		"set security ipsec vpn v1 ipsec-policy epol1",
		"set security ipsec vpn v1 bind-interface st0.0",
	}
}

func TestPKIStanzaCapturedWithAdvisory15752(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set security pki ca-profile entrust ca-identity example-ca",
		"set security pki ca-profile entrust enrollment url http://ca.example.com:8080/scep",
		"set security pki ca-profile entrust revocation-check crl",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("security pki must commit (captured, advisory): %v", err)
	}
	if cfg.Security.PKI == nil || cfg.Security.PKI.CAProfiles["entrust"] == nil {
		t.Fatalf("ca-profile entrust not captured: %+v", cfg.Security.PKI)
	}
	p := cfg.Security.PKI.CAProfiles["entrust"]
	if p.CAIDentity != "example-ca" || p.EnrollmentURL != "http://ca.example.com:8080/scep" || p.RevocationCheck != "crl" {
		t.Fatalf("ca-profile = %+v, want identity/url/crl", p)
	}
	found := false
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "security pki") && strings.Contains(w, "accepted-only") {
			found = true
		}
	}
	if !found {
		t.Fatalf("ValidateConfig must warn security pki accepted-only, got %v", ValidateConfig(cfg))
	}
	// Hierarchical spelling captures the same profile.
	hier, perrs := NewParser(`security { pki { ca-profile entrust { ca-identity example-ca; enrollment { url http://ca.example.com:8080/scep; } revocation-check { crl; } } } }`).Parse()
	if len(perrs) > 0 {
		t.Fatalf("hier parse: %v", perrs)
	}
	cfg2, err := CompileConfig(hier)
	if err != nil {
		t.Fatalf("hier security pki must commit: %v", err)
	}
	if cfg2.Security.PKI == nil || cfg2.Security.PKI.CAProfiles["entrust"] == nil ||
		cfg2.Security.PKI.CAProfiles["entrust"].CAIDentity != "example-ca" {
		t.Fatalf("hier ca-profile not captured: %+v", cfg2.Security.PKI)
	}
}

func TestIKEPolicyLocalCertificateAndECDSA15752(t *testing.T) {
	for _, auth := range []string{"ecdsa-signatures-256", "ecdsa-signatures-384", "ecdsa-signatures", "rsa-signatures"} {
		t.Run(auth, func(t *testing.T) {
			cmds := pkiBaseCmds15752(auth)
			cmds = append(cmds, "set security ike policy pol1 local-certificate Hub")
			cfg, err := CompileConfig(buildTreeFromSet(t, cmds))
			if err != nil {
				t.Fatalf("%s with policy local-certificate must commit: %v", auth, err)
			}
			pol := cfg.Security.IPsec.IKEPolicies["pol1"]
			if pol == nil || pol.LocalCertificate != "Hub" {
				t.Fatalf("pol1.LocalCertificate = %+v, want Hub", pol)
			}
			gw := cfg.Security.IPsec.Gateways["gw1"]
			if got := EffectiveLocalCertificate(&cfg.Security.IPsec, cfg.Security.IPsec.VPNs["v1"], gw); got != "Hub" {
				t.Fatalf("effective cert = %q, want Hub (policy fallback)", got)
			}
		})
	}
	// Gateway cert wins over policy cert.
	cmds := pkiBaseCmds15752("rsa-signatures")
	cmds = append(cmds,
		"set security ike policy pol1 local-certificate Hub",
		"set security ike gateway gw1 local-certificate GwCert",
	)
	cfg, err := CompileConfig(buildTreeFromSet(t, cmds))
	if err != nil {
		t.Fatalf("gateway+policy cert must commit: %v", err)
	}
	gw := cfg.Security.IPsec.Gateways["gw1"]
	if got := EffectiveLocalCertificate(&cfg.Security.IPsec, cfg.Security.IPsec.VPNs["v1"], gw); got != "GwCert" {
		t.Fatalf("effective cert = %q, want GwCert (gateway wins)", got)
	}
}

func TestPubkeyWithoutCertificateRejected15752(t *testing.T) {
	for _, auth := range []string{"rsa-signatures", "ecdsa-signatures", "ecdsa-signatures-256", "ecdsa-signatures-384"} {
		t.Run(auth+" strict rejects", func(t *testing.T) {
			_, err := CompileConfig(buildTreeFromSet(t, pkiBaseCmds15752(auth)))
			if err == nil || !strings.Contains(err.Error(), "local-certificate") {
				t.Fatalf("pubkey VPN without local-certificate must strict-reject naming local-certificate, got %v", err)
			}
		})
		t.Run(auth+" lenient warns and keeps VPN", func(t *testing.T) {
			cfg, err := CompileConfigLenient(buildTreeFromSet(t, pkiBaseCmds15752(auth)))
			if err != nil {
				t.Fatalf("lenient must not reject: %v", err)
			}
			found := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "local-certificate") {
					found = true
				}
			}
			if !found {
				t.Fatalf("lenient must warn naming local-certificate, warnings=%v", cfg.Warnings)
			}
			if cfg.Security.IPsec.VPNs["v1"] == nil {
				t.Fatal("lenient must keep VPN (render belt skips it)")
			}
		})
	}
	// Control: PSK with a key and no cert commits; pubkey with gateway
	// cert commits.
	{
		cmds := append(pkiBaseCmds15752("pre-shared-keys"), "set security ike policy pol1 pre-shared-key ascii-text secret")
		if _, err := CompileConfig(buildTreeFromSet(t, cmds)); err != nil {
			t.Fatalf("psk VPN with key and no cert must commit: %v", err)
		}
	}
	{
		cmds := append(pkiBaseCmds15752("rsa-signatures"), "set security ike gateway gw1 local-certificate GwCert")
		if _, err := CompileConfig(buildTreeFromSet(t, cmds)); err != nil {
			t.Fatalf("pubkey VPN with gateway cert must commit: %v", err)
		}
	}
}

func TestGatewayIdentityDNAndKeyID15752(t *testing.T) {
	type want struct{ lt, lv, lm, rt, rv, rm, ext string }
	cases := []struct {
		name string
		cmds []string
		want want
	}{
		{"bare local DN flat", []string{"set security ike gateway gw1 local-identity distinguished-name"}, want{lt: "distinguished-name"}},
		{"bare local DN does not steal packed sibling", []string{"set security ike gateway gw1 local-identity distinguished-name external-interface ge-0/0/0"}, want{lt: "distinguished-name", ext: "ge-0/0/0"}},
		{"direct remote DN", []string{"set security ike gateway gw1 remote-identity distinguished-name CN=peer"}, want{rt: "distinguished-name", rv: "CN=peer"}},
		{"container remote DN", []string{"set security ike gateway gw1 remote-identity distinguished-name container CN=peer"}, want{rt: "distinguished-name", rv: "CN=peer", rm: "container"}},
		{"wildcard remote DN", []string{"set security ike gateway gw1 remote-identity distinguished-name wildcard CN=peer"}, want{rt: "distinguished-name", rv: "CN=peer", rm: "wildcard"}},
		{"container local DN", []string{"set security ike gateway gw1 local-identity distinguished-name container CN=me"}, want{lt: "distinguished-name", lv: "CN=me", lm: "container"}},
		{"key-id local", []string{"set security ike gateway gw1 local-identity key-id mykey"}, want{lt: "key-id", lv: "mykey"}},
		{"key-id remote", []string{"set security ike gateway gw1 remote-identity key-id peerkey"}, want{rt: "key-id", rv: "peerkey"}},
		{"hostname control", []string{"set security ike gateway gw1 local-identity hostname foo.example.com"}, want{lt: "hostname", lv: "foo.example.com"}},
		{"ipsec gateway container DN", []string{"set security ipsec gateway gw1 remote-identity distinguished-name container CN=peer"}, want{rt: "distinguished-name", rv: "CN=peer", rm: "container"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(buildTreeFromSet(t, tc.cmds))
			if err != nil {
				t.Fatalf("must commit: %v", err)
			}
			gw := cfg.Security.IPsec.Gateways["gw1"]
			if gw == nil {
				t.Fatal("gw1 missing")
			}
			got := want{lt: gw.LocalIDType, lv: gw.LocalIDValue, lm: gw.LocalDNModifier, rt: gw.RemoteIDType, rv: gw.RemoteIDValue, rm: gw.RemoteDNModifier, ext: gw.ExternalIface}
			if got != tc.want {
				t.Fatalf("gateway identity = %+v, want %+v", got, tc.want)
			}
		})
	}
	// Unknown identity type strict-rejects (no silent verbatim render).
	_, err := CompileConfig(buildTreeFromSet(t, []string{"set security ike gateway gw1 local-identity bogus foo"}))
	if err == nil || !strings.Contains(err.Error(), "bogus") {
		t.Fatalf("unknown identity type must strict-reject naming bogus, got %v", err)
	}
	cfg, err := CompileConfigLenient(buildTreeFromSet(t, []string{"set security ike gateway gw1 local-identity bogus foo"}))
	if err != nil {
		t.Fatalf("lenient must not reject unknown identity type: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "bogus") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient must warn naming bogus, warnings=%v", cfg.Warnings)
	}
	// Hierarchical spellings: bare DN block and container DN block.
	hierCases := []struct {
		name string
		src  string
		want want
	}{
		{"hier bare local DN", `security { ike { gateway gw1 { local-identity { distinguished-name; } } } }`, want{lt: "distinguished-name"}},
		{"hier container remote DN", `security { ike { gateway gw1 { remote-identity { distinguished-name { container CN=peer; } } } } }`, want{rt: "distinguished-name", rv: "CN=peer", rm: "container"}},
		{"hier bare DN with sibling", `security { ike { gateway gw1 { local-identity distinguished-name; external-interface ge-0/0/0; } } }`, want{lt: "distinguished-name", ext: "ge-0/0/0"}},
		{"hier packed DN does not steal", `security { ike { gateway gw1 local-identity distinguished-name external-interface ge-0/0/0; } }`, want{lt: "distinguished-name", ext: "ge-0/0/0"}},
	}
	for _, tc := range hierCases {
		t.Run(tc.name, func(t *testing.T) {
			tree, perrs := NewParser(tc.src).Parse()
			if len(perrs) > 0 {
				t.Fatalf("parse: %v", perrs)
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("must commit: %v", err)
			}
			gw := cfg.Security.IPsec.Gateways["gw1"]
			if gw == nil {
				t.Fatal("gw1 missing")
			}
			got := want{lt: gw.LocalIDType, lv: gw.LocalIDValue, lm: gw.LocalDNModifier, rt: gw.RemoteIDType, rv: gw.RemoteIDValue, rm: gw.RemoteDNModifier, ext: gw.ExternalIface}
			if got != tc.want {
				t.Fatalf("gateway identity = %+v, want %+v", got, tc.want)
			}
		})
	}
}
