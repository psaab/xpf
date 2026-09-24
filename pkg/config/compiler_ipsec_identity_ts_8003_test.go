package config

import (
	"strings"
	"testing"
)

// Tests for #8003: `security ipsec vpn <v> local-identity / remote-identity`
// are rendered as the swanctl local_ts / remote_ts when the VPN declares no
// traffic-selector (pkg/ipsec effectiveTrafficSelectors), but the #4098 walk
// only ever descended into `traffic-selector` children, so nothing examined
// them at commit.
//
// Measured on strongSwan 6.0.5, a non-selector value here does not degrade the
// child SA — it discards the ENTIRE connection:
//
//	loading connection 'm_fqdnts' failed: invalid value for: local_ts,
//	config discarded
//
// so the VPN silently never establishes. The trap is that IPsecVPN.LocalID is
// declared "local traffic selector (CIDR)" while the only statement that fills
// it is spelled `local-identity`, which in Junos is an IDENTITY and is normally
// an FQDN or a DN — so the operator writing the Junos-shaped value is exactly
// the one who gets a dead tunnel.

func buildTree8003(t *testing.T, cmds []string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// TestIdentityFQDNRejectedStrict is the primary guard. An FQDN is the value a
// Junos-literate operator would write, it clears the general control-char and
// whitespace gates, and only the #8003 gate rejects it.
func TestIdentityFQDNRejectedStrict(t *testing.T) {
	for _, leaf := range []string{"local-identity", "remote-identity"} {
		t.Run(leaf, func(t *testing.T) {
			tree := buildTree8003(t, []string{
				`set security ipsec vpn v1 ` + leaf + ` vpn.example.com`,
				`set security ipsec vpn v1 bind-interface st0`,
			})
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted %s of an FQDN; strongSwan discards the whole connection for it (#8003)", leaf)
			}
			if !strings.Contains(err.Error(), "#8003") || !strings.Contains(err.Error(), leaf) {
				t.Fatalf("reject error %q should name %s and #8003", err.Error(), leaf)
			}
		})
	}
}

// TestIdentityDistinguishedNameRejectedStrict covers the other normal Junos
// identity shape. A DN contains '=' and ',' and is not a selector either.
func TestIdentityDistinguishedNameRejectedStrict(t *testing.T) {
	tree := buildTree8003(t, []string{
		`set security ipsec vpn v1 local-identity "CN=gw1.example.com"`,
		`set security ipsec vpn v1 bind-interface st0`,
	})
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("CompileConfig accepted a distinguished-name local-identity (#8003)")
	}
}

// TestIdentityLenientWarns: an already-persisted or peer-synced config must
// still BOOT (#1960 fail-closed-on-load class) and warn, rather than failing
// the load. The render belt keeps the value inert on that path.
func TestIdentityLenientWarns(t *testing.T) {
	tree := buildTree8003(t, []string{
		`set security ipsec vpn v1 local-identity vpn.example.com`,
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must not fail on a persisted config (#1960): %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#8003") && strings.Contains(w, "local-identity") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient compile did not warn about the identity selector; warnings=%v", cfg.Warnings)
	}
}

// TestIdentitySelectorShapesAccepted is the over-reject negative control, and
// it carries real weight: `local-identity` IS the way a proxy-ID is expressed
// in this grammar (the field is literally declared "local traffic selector
// (CIDR)"), so a gate that rejected every identity would break every VPN
// configured the intended way. Each shape the renderer can legally emit must
// still commit clean and warn on neither path.
func TestIdentitySelectorShapesAccepted(t *testing.T) {
	for _, val := range []string{
		"10.0.0.0/24",
		"2001:db8::/48",
		"192.0.2.1",
		"2001:db8::1",
		"10.0.0.1-10.0.0.9",
	} {
		t.Run(val, func(t *testing.T) {
			tree := buildTree8003(t, []string{
				`set security ipsec vpn v1 local-identity ` + val,
				`set security ipsec vpn v1 remote-identity ` + val,
				`set security ipsec vpn v1 bind-interface st0`,
			})
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig rejected a valid selector-shaped identity %q: %v", val, err)
			}
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "#8003") {
					t.Fatalf("clean identity %q produced an #8003 warning: %q", val, w)
				}
			}
		})
	}
}
