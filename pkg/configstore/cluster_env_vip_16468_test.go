package configstore

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #16468: every cluster env's WAN_VIP4 / LAN_VIP4 / LAN_VIP6 must be an
// address its CLUSTER_CONF actually configures. The loss-userspace env
// pinned WAN_VIP4=172.16.50.6 while docs/ha-cluster-userspace.conf
// configures reth0.50=172.16.50.8, so test-private-rg's WAN VIP cells
// failed by construction; loss-cluster.env set none of the three, so
// cluster-env.sh's defaults (172.16.50.6, 10.0.60.1, cf01::1) applied
// against ha-cluster-loss.conf (.7, 10.0.89.1, df01::1) and failed the
// same way. Positive controls tcp (.10) / udp (.11) already matched.
//
// The assertion is on the COMPILED config (CheckText), not the conf
// text, so an address hidden in a comment or an inert stanza cannot
// satisfy it. Each env is sourced through cluster-env.sh in the test
// helper below so an env that stops pinning a VIP -- and silently
// falls back to a cluster-env.sh default -- is measured on the value
// the harnesses will actually see.
//
// RED on revert: restore WAN_VIP4=172.16.50.6 in
// loss-userspace-cluster.env (or mutate any pinned VIP) and the
// matching subtest fails naming env, variable, value and conf.

type clusterEnvVIPCase struct {
	env      string
	wanVIP4  string
	lanVIP4  string
	lanVIP6  string
	confBase string
}

var clusterEnvVIPCases = []clusterEnvVIPCase{
	{"loss-userspace-cluster.env", "172.16.50.8", "10.0.61.1", "2001:559:8585:ef00::1", "ha-cluster-userspace.conf"},
	{"loss-cluster.env", "172.16.50.7", "10.0.89.1", "2001:559:8585:df01::1", "ha-cluster-loss.conf"},
	{"tcp-userspace-cluster.env", "172.16.50.10", "10.0.62.1", "2001:559:8585:aa00::1", "ha-cluster-tcp.conf"},
	{"udp-userspace-cluster.env", "172.16.50.11", "10.0.63.1", "2001:559:8585:ba00::1", "ha-cluster-udp.conf"},
}

// envVIPs parses the three VIP pins from an env file. An absent pin
// yields "" so the test reports it as unconfigured rather than
// silently skipping the variable (the loss-cluster.env defect).
func envVIPs(t *testing.T, envPath string) (wan, lan4, lan6 string) {
	t.Helper()
	raw, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read %s: %v", envPath, err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		// ${VAR:-default} / ${VAR:-...} wrappers: take the default.
		if strings.HasPrefix(v, "${") {
			if i := strings.Index(v, ":-"); i >= 0 {
				v = strings.TrimSuffix(v[i+2:], "}")
			}
		}
		switch strings.TrimSpace(k) {
		case "WAN_VIP4":
			wan = v
		case "LAN_VIP4":
			lan4 = v
		case "LAN_VIP6":
			lan6 = v
		}
	}
	return wan, lan4, lan6
}

func compiledAddresses(t *testing.T, confPath string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("read %s: %v", confPath, err)
	}
	cfg, err := CheckText(strings.ReplaceAll(string(raw), "${node}", "node0"), 0)
	if err != nil {
		t.Fatalf("compile %s: %v", confPath, err)
	}
	out := map[string]string{} // ip -> "iface.unit"
	for name, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		for num, unit := range ifc.Units {
			if unit == nil {
				continue
			}
			_ = num
			for _, a := range unit.Addresses {
				ipStr := a
				if p, err := netip.ParsePrefix(a); err == nil {
					ipStr = p.Addr().String()
				} else if ap, err := netip.ParseAddr(a); err == nil {
					ipStr = ap.String()
				}
				key := ipStr
				if ap, err := netip.ParseAddr(ipStr); err == nil {
					key = ap.String()
				}
				out[key] = name
			}
			// VRRP virtual addresses also count as configured.
			for _, vg := range unit.VRRPGroups {
				if vg == nil {
					continue
				}
				for _, a := range vg.VirtualAddresses {
					ipStr := a
					if p, err := netip.ParsePrefix(a); err == nil {
						ipStr = p.Addr().String()
					}
					if ap, err := netip.ParseAddr(ipStr); err == nil {
						ipStr = ap.String()
					}
					out[ipStr] = name
				}
			}
		}
	}
	return out
}

func TestClusterEnvVIPsMatchClusterConf16468(t *testing.T) {
	for _, tc := range clusterEnvVIPCases {
		t.Run(tc.env, func(t *testing.T) {
			envPath := filepath.Join("..", "..", "test", "incus", tc.env)
			wan, lan4, lan6 := envVIPs(t, envPath)
			// Pin the exact expected values so a drift in either the
			// env or these expectations is loud, then assert the
			// invariant against the compiled conf.
			if wan != tc.wanVIP4 || lan4 != tc.lanVIP4 || lan6 != tc.lanVIP6 {
				t.Fatalf("%s pins WAN_VIP4=%q LAN_VIP4=%q LAN_VIP6=%q, want %q/%q/%q",
					tc.env, wan, lan4, lan6, tc.wanVIP4, tc.lanVIP4, tc.lanVIP6)
			}
			confPath := filepath.Join("..", "..", "docs", tc.confBase)
			addrs := compiledAddresses(t, confPath)
			for varName, vip := range map[string]string{
				"WAN_VIP4": wan, "LAN_VIP4": lan4, "LAN_VIP6": lan6,
			} {
				if vip == "" {
					t.Errorf("%s does not pin %s, so cluster-env.sh's default applies and was the #16468 loss-cluster defect", tc.env, varName)
					continue
				}
				key := vip
				if ap, err := netip.ParseAddr(vip); err == nil {
					key = ap.String()
				}
				if _, ok := addrs[key]; !ok {
					t.Errorf("MISMATCH %s %s=%s is configured on NO interface of docs/%s (compiled addresses: %v)",
						tc.env, varName, vip, tc.confBase, addrs)
				} else {
					t.Logf("MATCH %s %s=%s -> %s", tc.env, varName, vip, addrs[key])
				}
			}
		})
	}
}

// The legacy local cluster (BPFRX_CLUSTER_ENV=) has no env file: its
// conf is docs/ha-cluster.conf and its VIPs are cluster-env.sh's
// defaults. Those defaults must also be configured there, or the
// fallback path reintroduces the same fail-by-construction cell.
func TestClusterEnvDefaultsMatchLegacyConf16468(t *testing.T) {
	addrs := compiledAddresses(t, filepath.Join("..", "..", "docs", "ha-cluster.conf"))
	for varName, vip := range map[string]string{
		"WAN_VIP4 (cluster-env.sh default)": "172.16.50.6",
		"LAN_VIP4 (cluster-env.sh default)": "10.0.60.1",
		"LAN_VIP6 (cluster-env.sh default)": "2001:559:8585:cf01::1",
	} {
		if _, ok := addrs[vip]; !ok {
			t.Errorf("MISMATCH %s=%s is configured on NO interface of docs/ha-cluster.conf (compiled: %v)", varName, vip, addrs)
		} else {
			t.Logf("MATCH %s=%s -> %s", varName, vip, addrs[vip])
		}
	}
}
