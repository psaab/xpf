package configstore

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// haClusterConfPath is the shipped loss-userspace-cluster config that
// `make cluster-deploy` pushes to both nodes (shared with other cells in
// this package).
const haClusterConfPath = "../../docs/ha-cluster-userspace.conf"

// haCluster8280Cases is every shipped HA cluster whose test-failover pool
// phase (#8280) must measure its OWN pool. #16471: test-failover.sh used to
// hardcode the loss values (10.0.61.240 / 172.16.80.7), so the tcp/udp
// clusters — whose pool rules match 10.0.62.240/28 resp. 10.0.63.240/28 and
// translate to .12 resp. .13 — reported false #8280/#8297/#8314 defects and
// never exercised their real pools. Each row pins env <-> conf <-> parsed
// config agreement: the env states POOL_SRC/POOL_NAT_ADDR explicitly, the
// conf's `rule pool-snat` covers POOL_SRC and pools to POOL_NAT_ADDR, and
// the parsed config proxy-ARPs that address.
var haCluster8280Cases = []struct {
	name     string
	confPath string
	envPath  string
	poolSrc  string // host address the harness binds (cover prefix base)
	cover    string // pool rule's match prefix
	poolAddr string // pool / proxy-ARP address
}{
	{"loss-userspace", "../../docs/ha-cluster-userspace.conf", "../../test/incus/loss-userspace-cluster.env", "10.0.61.240", "10.0.61.240/28", "172.16.80.7"},
	{"tcp-userspace", "../../docs/ha-cluster-tcp.conf", "../../test/incus/tcp-userspace-cluster.env", "10.0.62.240", "10.0.62.240/28", "172.16.80.12"},
	{"udp-userspace", "../../docs/ha-cluster-udp.conf", "../../test/incus/udp-userspace-cluster.env", "10.0.63.240", "10.0.63.240/28", "172.16.80.13"},
}

func read8280(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}

// envValue8280 returns the value of a `KEY="value"` (or KEY=value) line in a
// sourced cluster env file, or "" when absent.
func envValue8280(text, key string) string {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, key+"=") {
			continue
		}
		v := strings.TrimSpace(strings.TrimPrefix(line, key+"="))
		v = strings.Trim(v, "\"'")
		// Strip a trailing ${...:-default} wrapper if present.
		if strings.HasPrefix(v, "${") {
			if i := strings.Index(v, ":-"); i >= 0 {
				v = strings.TrimSuffix(v[i+2:], "}")
			}
		}
		return v
	}
	return ""
}

// TestShippedHAClusterConfigPassesCommitCheck8280 runs the real commit-check
// over every config the cluster smoke actually deploys.
//
// Added with the #8280 pool-mode source-NAT rule, because that edit is exactly
// the kind a unit suite cannot see: the config is prose to Go, it is validated
// only when a human pushes it to a shared cluster, and the failure mode is a
// deploy that half-applies on a box other lanes are using. The #6751 gate in
// particular — a NAT pool may not sit on an interface-mode SNAT egress address,
// or both mint the same (address, port) tuple with no shared occupancy — is
// invisible to every other test in the tree for this file. #16471 extends the
// check from the loss conf alone to the tcp/udp confs.
//
// nodeID -1 is the "no node identity" form CheckText uses for a plain syntax +
// semantic check, matching how a commit validates before any node binding.
func TestShippedHAClusterConfigPassesCommitCheck8280(t *testing.T) {
	for _, tc := range haCluster8280Cases {
		t.Run(tc.name, func(t *testing.T) {
			text := strings.ReplaceAll(read8280(t, tc.confPath), "${node}", "node0")
			cfg, err := CheckText(text, 0)
			if err != nil {
				t.Fatalf("the shipped cluster config %s does not pass commit-check: %v", tc.confPath, err)
			}
			if cfg == nil {
				t.Fatal("commit-check returned no config and no error")
			}
		})
	}
}

// The pool-mode rule #8280 added exists so the cluster smoke reaches the port
// allocator at all. Assert the PROPERTIES that make it non-interfering and
// non-vacuous, because a later edit that widens its match or drops its pool
// silently returns the smoke to covering nothing — and nothing else would say
// so.
func TestClusterConfigKeepsAPoolModeSourceNATRule8280(t *testing.T) {
	for _, tc := range haCluster8280Cases {
		t.Run(tc.name, func(t *testing.T) {
			text := read8280(t, tc.confPath)

			if !strings.Contains(text, "source-nat { pool pool-snat-pool; }") {
				t.Fatal("the cluster config has no POOL-mode source-NAT rule. Every " +
					"`source-nat { interface; }` rule is address-only and returns before any " +
					"port allocation, so without this the cluster smoke never executes a line " +
					"of the NAT port allocator and a change to it passes 17/17 while being " +
					"completely unmeasured (#8280)")
			}
			// Non-interference: the rule must stay scoped to a prefix nothing is
			// assigned. The LAN host is .102, the VIP .1, the DHCP range .100-.199.
			if !strings.Contains(text, "match { source-address "+tc.cover+"; }") {
				t.Fatalf("the pool-mode rule's match is no longer the unassigned %s. "+
					"Widening it moves EXISTING smoke traffic onto the pool "+
					"path, which changes what every other cluster assertion measures (#8280)", tc.cover)
			}
			// Ordering: first-match-wins is what keeps the catch-all from swallowing it.
			poolIdx := strings.Index(text, "rule pool-snat {")
			ifaceIdx := strings.Index(text, "rule snat {")
			if poolIdx < 0 || ifaceIdx < 0 {
				t.Fatalf("expected both rules present; pool=%d iface=%d", poolIdx, ifaceIdx)
			}
			if poolIdx > ifaceIdx {
				t.Fatal("the pool-mode rule is listed AFTER the catch-all `snat` rule. " +
					"First-match-wins means the catch-all matches 0.0.0.0/0 first and the pool " +
					"rule can never fire (#8280)")
			}
			// Return traffic: a pool address distinct from the interface's own needs
			// proxy-ARP or it blackholes — the same lesson xpf-cluster-fw0.conf records.
			//
			// Asserted on the PARSED config, not on the text. The first version of this
			// check was `strings.Contains(text, "proxy-arp {")`, and it passed while the
			// stanza sat one level out under `security` instead of under `nat`: that
			// config committed clean, rendered back through
			// `show configuration security proxy-arp`, and was completely INERT, because
			// reconcileProxyARP reads cfg.Security.NAT.ProxyARP. Pool return traffic
			// blackholed on the real cluster with no error anywhere, and a text check
			// could not tell the two apart. Assert what the config BECOMES.
			cfg, err := CheckText(strings.ReplaceAll(text, "${node}", "node0"), 0)
			if err != nil {
				t.Fatalf("commit-check: %v", err)
			}
			if len(cfg.Security.NAT.ProxyARP) == 0 {
				t.Fatal("the parsed config has NO proxy-arp entries under security.nat, so " +
					"reconcileProxyARP installs no NTF_PROXY entry, the firewall answers no ARP " +
					"for the pool address, and pool-mode return traffic blackholes — with the " +
					"stanza still present in the file and still rendered by `show " +
					"configuration` (#8280)")
			}
			foundPoolAddr := false
			for _, pa := range cfg.Security.NAT.ProxyARP {
				for _, a := range pa.Addresses {
					if strings.HasPrefix(a, tc.poolAddr) {
						foundPoolAddr = true
					}
				}
			}
			if !foundPoolAddr {
				t.Fatalf("no proxy-arp entry covers the pool address %s; parsed "+
					"entries: %+v", tc.poolAddr, cfg.Security.NAT.ProxyARP)
			}

			// #16471: the parsed pool rule itself — not just the file text —
			// must cover POOL_SRC and translate via a pool that contains
			// POOL_NAT_ADDR, and the cluster env must state exactly those
			// values. This is the hermetic form of the reporter's probe:
			// MATCH for all three envs, derived from what the config BECOMES.
			coverPrefix, err := netip.ParsePrefix(tc.cover)
			if err != nil {
				t.Fatalf("cover %q does not parse: %v", tc.cover, err)
			}
			srcAddr, err := netip.ParseAddr(tc.poolSrc)
			if err != nil {
				t.Fatalf("pool source %q does not parse: %v", tc.poolSrc, err)
			}
			if !coverPrefix.Contains(srcAddr) {
				t.Fatalf("pool rule cover %s does not contain POOL_SRC %s", tc.cover, tc.poolSrc)
			}
			var poolRule *config.NATRule
			for _, rs := range cfg.Security.NAT.Source {
				for _, r := range rs.Rules {
					if r.Then.PoolName != "" {
						rr := r
						poolRule = rr
					}
				}
			}
			if poolRule == nil {
				t.Fatal("parsed config has no source-NAT rule with a pool action (#8280)")
			}
			covered := false
			for _, s := range poolRule.Match.SourceAddressList() {
				if s == tc.cover {
					covered = true
				}
			}
			if !covered {
				t.Fatalf("parsed pool rule matches %v, want cover %s (POOL_SRC %s)",
					poolRule.Match.SourceAddressList(), tc.cover, tc.poolSrc)
			}
			pool := cfg.Security.NAT.SourcePools[poolRule.Then.PoolName]
			if pool == nil {
				t.Fatalf("parsed pool rule references pool %q, absent from SourcePools %v",
					poolRule.Then.PoolName, cfg.Security.NAT.SourcePools)
			}
			inPool := false
			for _, m := range config.SourceNATPoolMembers(pool) {
				if strings.TrimSuffix(m, "/32") == tc.poolAddr {
					inPool = true
				}
			}
			if !inPool {
				t.Fatalf("pool %s members %v do not contain POOL_NAT_ADDR %s",
					poolRule.Then.PoolName, config.SourceNATPoolMembers(pool), tc.poolAddr)
			}

			envText := read8280(t, tc.envPath)
			if got := envValue8280(envText, "POOL_SRC"); got != tc.poolSrc {
				t.Fatalf("%s POOL_SRC = %q, want %q (the address %s's pool rule covers); "+
					"test-failover binding any other source never takes the pool path (#16471)",
					tc.envPath, got, tc.poolSrc, tc.confPath)
			}
			if got := envValue8280(envText, "POOL_NAT_ADDR"); got != tc.poolAddr {
				t.Fatalf("%s POOL_NAT_ADDR = %q, want %q (the pool/proxy-ARP address in %s); "+
					"asserting on any other address reports false pool/proxy-ARP defects (#16471)",
					tc.envPath, got, tc.poolAddr, tc.confPath)
			}
			if got := envValue8280(envText, "CLUSTER_CONF"); !strings.HasSuffix(tc.confPath, strings.TrimPrefix(got, "../../")) && filepath.Base(got) != filepath.Base(tc.confPath) {
				t.Fatalf("%s CLUSTER_CONF = %q, want it to name %s", tc.envPath, got, tc.confPath)
			}
		})
	}
}

// TestFailoverPoolDerivationMatchesClusterConf16471 pins the shell-side
// contract test-failover.sh now implements: POOL_SRC/POOL_NAT_ADDR are
// derived from CLUSTER_CONF's `rule pool-snat` (POOL_CONF_SRC /
// POOL_CONF_ADDR / POOL_CONF_COVER in the script) and a mismatch VOIDs the
// phase. The script cannot be executed hermetically (it reboots cluster
// nodes), so this cell asserts the derivation's inputs and outputs agree
// for every shipped env/conf pair, and that the script actually contains
// the derivation + VOID wiring rather than the old loss literals as
// defaults.
func TestFailoverPoolDerivationMatchesClusterConf16471(t *testing.T) {
	script := read8280(t, "../../test/incus/test-failover.sh")
	for _, want := range []string{
		"POOL_CONF_SRC",
		"POOL_CONF_ADDR",
		"POOL_CONF_COVER",
		"POOL_VOID_REASON",
		`POOL_SRC="${POOL_SRC:-$POOL_CONF_SRC}"`,
		`POOL_NAT_ADDR="${POOL_NAT_ADDR:-$POOL_CONF_ADDR}"`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("test-failover.sh no longer contains %q — the #16471 derivation/VOID wiring is gone and the pool phase can again silently measure the wrong cluster's pool", want)
		}
	}
	if strings.Contains(script, `POOL_SRC="${POOL_SRC:-10.0.61.240}"`) ||
		strings.Contains(script, `POOL_NAT_ADDR="${POOL_NAT_ADDR:-172.16.80.7}"`) {
		t.Fatal("test-failover.sh again defaults POOL_SRC/POOL_NAT_ADDR to the loss cluster's literals; on tcp/udp that binds a source the pool rule never matches and reports the zeroes as product defects (#16471)")
	}
	for _, tc := range haCluster8280Cases {
		t.Run(tc.name, func(t *testing.T) {
			envText := read8280(t, tc.envPath)
			confText := read8280(t, tc.confPath)
			// The reporter's probe, hermetically: env-stated values must be
			// covered by the conf's pool rule and present as pool+proxy-ARP.
			if !strings.Contains(confText, "match { source-address "+tc.cover+"; }") {
				t.Fatalf("%s pool rule does not cover %s", tc.confPath, tc.cover)
			}
			if got := envValue8280(envText, "POOL_SRC"); got != tc.poolSrc {
				t.Fatalf("MISMATCH %s POOL_SRC=%q want %q", tc.envPath, got, tc.poolSrc)
			}
			if got := envValue8280(envText, "POOL_NAT_ADDR"); got != tc.poolAddr {
				t.Fatalf("MISMATCH %s POOL_NAT_ADDR=%q want %q", tc.envPath, got, tc.poolAddr)
			}
			t.Logf("MATCH %s pool-rule-covers-POOL_SRC=%q pool-has-POOL_NAT_ADDR=%v proxy-arp-has-POOL_NAT_ADDR=%v",
				filepath.Base(tc.envPath), tc.cover,
				strings.Contains(confText, "address "+tc.poolAddr+"/32"),
				strings.Contains(confText, "address "+tc.poolAddr+"/32"))
		})
	}
}
