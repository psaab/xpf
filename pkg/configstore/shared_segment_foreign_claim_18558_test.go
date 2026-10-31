package configstore

import (
	"sort"
	"strings"
	"testing"
)

// #18558: an address that NO xpf config claims twice can still be a
// duplicate on the shared lab segment. The #16473 census compares the
// shipped configs with each other, so it cannot see a claimant that has no
// config at all. That is how tcp's 172.16.50.10 and udp's 172.16.50.11
// passed every hermetic check while a non-xpf lab device held each of them:
// the upstream gateway's ARP entry flipped between the device and the RG
// owner, and 20-80% of the clusters' IPv4 replies were delivered to the
// device, while IPv6 on the same path stayed clean.
//
// foreignClaimed18558 is a MEASUREMENT, not a registry: every address in the
// shared networks that a host outside every xpf stack answered ARP for. It
// was taken with RFC 5227 probes (sender 0.0.0.0) from tcp fw1's
// ge-7-0-2.50 / ge-7-0-2.80, three rounds over each /24, at
// 2026-10-31 00:18 UTC, plus the one ARP sender (.15) seen in an earlier
// capture. Excluded: the gateway (.1, .254) and every xpf RETH MAC
// (02:bf:72:<cluster-id>:..), which the #16473 census already accounts for.
// The live counterpart is test-failover's ha_wan_claim_check, which probes
// the running cluster's WAN address in the same window as a failing
// external IPv4 cell. This list goes stale as the lab changes. Re-measure it
// before relying on an address it does not name being free.
//
// RED on revert: restore 172.16.50.10 in docs/ha-cluster-tcp.conf (or .11
// in docs/ha-cluster-udp.conf) and the tcp (udp) subtest fails, naming the
// foreign MAC.
var foreignClaimed18558 = map[string]string{
	"172.16.50.2":   "9a:a7:c5:30:66:1f",
	"172.16.50.4":   "10:66:6a:ee:06:be",
	"172.16.50.9":   "2a:dd:35:a2:96:97",
	"172.16.50.10":  "18:e8:29:2c:13:7a",
	"172.16.50.11":  "d8:b3:70:8c:f8:44",
	"172.16.50.12":  "ac:8b:a9:df:fd:f3",
	"172.16.50.13":  "24:5a:4c:14:f9:e7",
	"172.16.50.14":  "f4:e2:c6:ea:d7:80",
	"172.16.50.15":  "9c:05:d6:e1:f2:0f",
	"172.16.50.18":  "94:2a:6f:fe:3d:b1",
	"172.16.50.19":  "74:ac:b9:a8:6f:54",
	"172.16.50.20":  "84:78:48:fc:05:0c",
	"172.16.50.21":  "74:ac:b9:a8:6f:f0",
	"172.16.50.22":  "8c:ed:e1:72:0a:dd",
	"172.16.50.23":  "ac:8b:a9:df:fd:b1",
	"172.16.50.24":  "74:ac:b9:a8:70:9b",
	"172.16.50.28":  "a8:9c:6c:80:34:a8",
	"172.16.50.29":  "d0:21:f9:7c:be:86",
	"172.16.50.30":  "f4:92:bf:a2:3d:1b",
	"172.16.50.31":  "f4:92:bf:a2:3d:00",
	"172.16.50.32":  "60:22:32:99:6a:bf",
	"172.16.50.33":  "f4:92:bf:a2:3d:24",
	"172.16.50.34":  "94:2a:6f:fe:40:0a",
	"172.16.50.35":  "d8:b3:70:fc:af:8b",
	"172.16.50.36":  "94:2a:6f:4e:da:89",
	"172.16.50.51":  "24:5a:4c:2f:eb:73",
	"172.16.50.65":  "9c:05:d6:0c:6b:ca",
	"172.16.50.68":  "9c:05:d6:0c:76:6e",
	"172.16.50.80":  "84:78:48:a2:8b:a4",
	"172.16.50.81":  "84:78:48:a2:8f:2c",
	"172.16.50.82":  "84:78:48:a2:e2:f0",
	"172.16.50.104": "a8:9c:6c:a2:ee:98",
	"172.16.50.108": "84:78:48:12:37:0c",
	"172.16.50.109": "a8:9c:6c:a2:ee:9c",
	"172.16.50.110": "94:2a:6f:5c:41:f8",
	"172.16.50.111": "8c:ed:e1:ea:bb:80",
	"172.16.50.116": "a8:9c:6c:a2:da:84",
	"172.16.50.119": "8c:ed:e1:ea:c4:11",
	"172.16.50.134": "a8:9c:6c:a2:ec:bc",
	"172.16.50.145": "94:2a:6f:42:dd:c3",
	"172.16.50.149": "94:2a:6f:42:db:17",
	"172.16.50.150": "a8:9c:6c:a2:f0:08",
	"172.16.50.153": "a8:9c:6c:a2:ed:70",
	"172.16.50.154": "90:41:b2:50:f1:d0",
	"172.16.50.157": "94:2a:6f:42:d7:2b",
	"172.16.50.158": "9c:05:d6:0c:76:d4",
	"172.16.50.165": "90:41:b2:50:fe:58",
	"172.16.50.167": "10:66:6a:88:85:08",
	"172.16.50.185": "94:2a:6f:5c:42:2c",
	"172.16.50.186": "a8:9c:6c:a2:ed:ec",
	"172.16.50.201": "10:66:6a:88:85:08",
	"172.16.50.246": "3e:6c:44:17:a5:ef",
	"172.16.50.253": "a4:ae:11:1e:3d:af",
	"172.16.80.2":   "7e:1d:ac:9f:c4:03",
	"172.16.80.32":  "8a:2c:50:1b:fe:00",
	"172.16.80.64":  "6e:b8:72:bb:a6:ae",
	"172.16.80.65":  "72:27:81:8a:05:e1",
	"172.16.80.66":  "5e:1a:31:da:e7:51",
	"172.16.80.67":  "ce:32:12:c4:65:f4",
	"172.16.80.68":  "d2:5e:38:79:db:b1",
	"172.16.80.69":  "16:ac:a6:e9:94:1a",
	"172.16.80.70":  "ce:60:35:57:ef:bd",
	"172.16.80.71":  "1a:36:d2:a6:f6:69",
	"172.16.80.100": "32:24:8d:a3:ac:4d",
	"172.16.80.101": "3e:c9:0d:bc:54:7e",
	"172.16.80.102": "32:14:fc:bd:34:9e",
	"172.16.80.104": "7a:2e:25:2a:9d:38",
	"172.16.80.105": "92:bd:6e:30:a5:3b",
	"172.16.80.106": "a6:ab:3a:9d:95:bb",
	"172.16.80.107": "fa:6e:58:fb:df:3b",
	"172.16.80.109": "1a:06:86:58:2a:30",
	"172.16.80.110": "c6:a2:f8:d9:f2:77",
	"172.16.80.111": "56:87:2c:4d:54:ab",
	"172.16.80.117": "3a:17:d9:38:7b:90",
	"172.16.80.124": "4a:2d:45:af:c5:cc",
	"172.16.80.130": "10:66:6a:b5:87:a4",
	"172.16.80.167": "52:54:00:cd:b8:b4",
	"172.16.80.174": "10:66:6a:8b:91:a4",
	"172.16.80.196": "50:7c:6f:22:8e:c0",
	"172.16.80.197": "50:7c:6f:22:8d:e0",
	"172.16.80.200": "10:66:6a:8b:91:a4 f6:f0:06:10:77:d5",
	"172.16.80.201": "10:66:6a:8b:91:a4",
	"172.16.80.210": "10:66:6a:5c:f2:b8",
	"172.16.80.211": "10:66:6a:b5:87:a4",
	"172.16.80.243": "22:79:6f:c2:ca:9e",
	"172.16.80.244": "b2:a5:34:07:39:cc",
	"172.16.80.245": "52:ba:5f:46:09:02",
	"172.16.80.253": "a4:ae:11:1e:3d:af",
}

// knownForeignCollisions18558 are shipped claims on a foreign-held address
// that this change does not move: the standalone VM and the legacy local
// cluster are not among the three gate clusters and cannot be re-validated
// live here. EXPIRY: #18574 re-addresses them. Delete each entry when its
// claim moves. An entry whose claim is already gone fails the test, so
// the list cannot outlive its reason.
var knownForeignCollisions18558 = map[string]string{
	"172.16.50.9":  "legacy local (ha-cluster.conf)",
	"172.16.50.12": "legacy local (ha-cluster.conf)",
	"172.16.50.14": "standalone (xpf-test.conf)",
	"172.16.50.15": "standalone (xpf-test.conf)",
}

func TestSharedSegmentForeignClaims18558(t *testing.T) {
	// Every stack's claims are collected BEFORE any subtest runs, and the
	// exemption audit below reads that collection. Running a single subtest
	// (`-run TestSharedSegmentForeignClaims18558/tcp`) therefore cannot make
	// an exemption look unused.
	type stackClaims struct {
		name   string
		rel    string
		claims map[string][]claim16473
	}
	var all []stackClaims
	used := map[string]bool{}
	for _, st := range labStacks16473 {
		for _, rel := range st.files {
			claims := claimsForFile16473(t, rel)
			all = append(all, stackClaims{st.name, rel, claims})
			for addr := range claims {
				if knownForeignCollisions18558[addr] == st.name {
					used[addr] = true
				}
			}
		}
	}
	byStack := map[string][]stackClaims{}
	for _, sc := range all {
		byStack[sc.name] = append(byStack[sc.name], sc)
	}
	for _, st := range labStacks16473 {
		st := st
		t.Run(st.name, func(t *testing.T) {
			for _, sc := range byStack[st.name] {
				addrs := make([]string, 0, len(sc.claims))
				for a := range sc.claims {
					addrs = append(addrs, a)
				}
				sort.Strings(addrs)
				for _, addr := range addrs {
					macs, foreign := foreignClaimed18558[addr]
					if !foreign {
						continue
					}
					if knownForeignCollisions18558[addr] == st.name {
						t.Logf("KNOWN %s (%s) is held by non-xpf %s; tracked by #18574", addr, sc.rel, macs)
						continue
					}
					kinds := make([]string, 0, len(sc.claims[addr]))
					for _, c := range sc.claims[addr] {
						kinds = append(kinds, c.kind)
					}
					t.Errorf("FOREIGN-HELD %s: %s claims it (%s) but non-xpf host %s answered ARP for it "+
						"on the shared segment (2026-10-31 sweep); the gateway's ARP entry will flip "+
						"between them. Move the claim to an address a same-day ARP probe shows unanswered, "+
						"and register it in docs/incus-tcp-udp-plan.md section 3.3 (#18558)",
						addr, sc.rel, strings.Join(kinds, ", "), macs)
				}
			}
		})
	}
	for addr, stack := range knownForeignCollisions18558 {
		if _, ok := foreignClaimed18558[addr]; !ok {
			t.Errorf("knownForeignCollisions18558[%s] (%s) is not in the measured foreign list", addr, stack)
		}
		if !used[addr] {
			t.Errorf("knownForeignCollisions18558[%s]: %s no longer claims it; delete the exemption (#18574)", addr, stack)
		}
	}
}
