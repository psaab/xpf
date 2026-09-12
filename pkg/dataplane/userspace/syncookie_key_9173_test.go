package userspace

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// synCookieT0_9173 sits 512 s into its rotation period, so a second either way
// stays inside it.
var synCookieT0_9173 = time.Unix(1_800_000_000, 0)

func synCookieCfg9173(cluster *config.ClusterConfig, rootPassword, hostName string) *config.Config {
	cfg := &config.Config{}
	cfg.System.HostName = hostName
	cfg.Security.Flow.SynFloodProtectionMode = "syn-cookie"
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", ScreenProfile: "flood"},
	}
	cfg.Security.Screen = map[string]*config.ScreenProfile{
		"flood": {
			Name: "flood",
			TCP:  config.TCPScreen{SynFlood: &config.SynFloodConfig{AttackThreshold: 100}},
		},
	}
	cfg.Chassis.Cluster = cluster
	if rootPassword != "" {
		cfg.System.RootAuthentication = &config.RootAuthConfig{EncryptedPassword: config.Secret(rootPassword)}
	}
	return cfg
}

func keyedCluster9173(key, additional string) *config.ClusterConfig {
	return &config.ClusterConfig{
		ClusterID:             3,
		ControlLinkAuthKey:    config.Secret(key),
		ControlLinkAuthKeyAlt: config.Secret(additional),
	}
}

// restartDaemon9173 stands in for a daemon restart: a fresh per-start secret,
// with the previous one restored when the test ends.
func restartDaemon9173(t *testing.T) {
	t.Helper()
	saved := synCookieProcessSecret
	synCookieProcessSecret = sync.OnceValue(newSynCookieProcessSecret)
	t.Cleanup(func() { synCookieProcessSecret = saved })
}

func TestSYNCookieKeyIsIndependentOfTheRootPassword9173(t *testing.T) {
	cluster := keyedCluster9173("psk-A", "")
	key, ring := buildSYNCookieKeys(synCookieCfg9173(cluster, "$6$one$hash", "fw"), synCookieT0_9173)
	if len(key) != 32 || ring == nil {
		t.Fatalf("premise: SYN-cookie protection must be active, got key %q ring %v", key, ring)
	}
	for _, root := range []string{"$6$two$different", ""} {
		other, otherRing := buildSYNCookieKeys(synCookieCfg9173(cluster, root, "fw"), synCookieT0_9173)
		if other != key || !reflect.DeepEqual(otherRing, ring) {
			t.Fatalf("root password %q changed the SYN-cookie key", root)
		}
	}
	// Control: the secret that SHOULD key the cookie does move it.
	if other, _ := buildSYNCookieKeys(synCookieCfg9173(keyedCluster9173("psk-B", ""), "$6$one$hash", "fw"), synCookieT0_9173); other == key {
		t.Fatal("a different authentication-key derived the same SYN-cookie key")
	}
}

func TestTwoNodesWithTheSameAuthKeyAndEpochDeriveTheSameKey9173(t *testing.T) {
	node0 := synCookieCfg9173(keyedCluster9173("psk-A", "psk-old"), "$6$one$hash", "fw0")
	key0, ring0 := buildSYNCookieKeys(node0, synCookieT0_9173)
	// The peer is a different daemon start: a keyed cluster must not mix in the
	// per-start secret, or the nodes would never agree.
	restartDaemon9173(t)
	node1 := synCookieCfg9173(keyedCluster9173("psk-A", "psk-old"), "$6$one$hash", "fw1")
	key1, ring1 := buildSYNCookieKeys(node1, synCookieT0_9173.Add(time.Second))
	if len(key0) != 32 || key0 != key1 || !reflect.DeepEqual(ring0, ring1) {
		t.Fatalf("nodes with one authentication-key in one period disagree: %q vs %q", key0, key1)
	}
	// Controls: the rotation epoch and the cluster identity each move the key.
	if next, _ := buildSYNCookieKeys(node0, synCookieT0_9173.Add(synCookieKeyPeriodSecs*time.Second)); next == key0 {
		t.Fatal("the next rotation period derived the same key")
	}
	otherCluster := keyedCluster9173("psk-A", "psk-old")
	otherCluster.ClusterID = 4
	if other, _ := buildSYNCookieKeys(synCookieCfg9173(otherCluster, "", "fw0"), synCookieT0_9173); other == key0 {
		t.Fatal("a different cluster-id derived the same key")
	}
	// The screened-zone set is deliberately NOT a control here: it does not move
	// the key (TestNodesWithDifferentScreenedZonesDeriveTheSameKey9740).
}

// TestSYNCookieRingCarriesTheBaseAndTheAdditionalBase9173: the helper derives
// every period's key from the ring, so the ring carries bases -- the primary one
// and, during a #6630 PSK rotation window, an accept-only one -- and does not
// change with the clock.
func TestSYNCookieRingCarriesTheBaseAndTheAdditionalBase9173(t *testing.T) {
	cfg := synCookieCfg9173(keyedCluster9173("psk-new", "psk-old"), "", "fw")
	key, ring := buildSYNCookieKeys(cfg, synCookieT0_9173)
	if ring == nil || ring.PeriodSecs != synCookieKeyPeriodSecs || ring.PeriodSecs%synCookieEpochSecs != 0 {
		t.Fatalf("ring = %+v, want period %d, a whole number of %d s cookie epochs",
			ring, synCookieKeyPeriodSecs, synCookieEpochSecs)
	}
	if len(ring.Bases) != 2 || ring.Bases[0].AcceptOnly || !ring.Bases[1].AcceptOnly ||
		len(ring.Bases[0].Base) != 64 || len(ring.Bases[1].Base) != 64 {
		t.Fatalf("ring bases = %+v, want a primary then an accept-only base, 64 hex each", ring.Bases)
	}
	primary, err := hex.DecodeString(ring.Bases[0].Base)
	if err != nil {
		t.Fatalf("decode the primary base: %v", err)
	}
	if want := deriveSYNCookieEpochKey(primary, synCookieRotationEpoch(synCookieT0_9173)); key != want {
		t.Fatal("syn_cookie_master_key must be the primary base's key for the snapshot's period")
	}
	// The accept-only base is exactly the base a peer still keyed with the old PSK
	// mints from.
	_, peer := buildSYNCookieKeys(synCookieCfg9173(keyedCluster9173("psk-old", ""), "", "fw"), synCookieT0_9173)
	if peer == nil || len(peer.Bases) != 1 || ring.Bases[1].Base != peer.Bases[0].Base {
		t.Fatal("the accept-only base must equal the primary base of a node signing with additional-authentication-key")
	}
	// A later period keeps the same ring: rotating needs no republish.
	if _, later := buildSYNCookieKeys(cfg, synCookieT0_9173.Add(10*synCookieKeyPeriodSecs*time.Second)); !reflect.DeepEqual(later, ring) {
		t.Fatal("the ring changed with the clock, so a helper would need a republish to rotate")
	}
}

func TestStandaloneSYNCookieKeyChangesAcrossADaemonRestart9173(t *testing.T) {
	restartDaemon9173(t)
	cfg := synCookieCfg9173(nil, "$6$one$hash", "fw")
	first, _ := buildSYNCookieKeys(cfg, synCookieT0_9173)
	if again, _ := buildSYNCookieKeys(cfg, synCookieT0_9173); len(first) != 32 || again != first {
		t.Fatalf("within one daemon start the key must be stable: %q then %q", first, again)
	}
	if other, _ := buildSYNCookieKeys(synCookieCfg9173(nil, "$6$two$hash", "fw"), synCookieT0_9173); other != first {
		t.Fatal("the root password moved a standalone node's SYN-cookie key")
	}
	if next, _ := buildSYNCookieKeys(cfg, synCookieT0_9173.Add(synCookieKeyPeriodSecs*time.Second)); next == first {
		t.Fatal("a standalone key must rotate with the epoch")
	}
	restartDaemon9173(t)
	if after, _ := buildSYNCookieKeys(cfg, synCookieT0_9173); after == first {
		t.Fatal("a standalone key must change across a daemon restart")
	}
}

func TestUnkeyedClusterSYNCookieKeyIsPerDaemonStart9173(t *testing.T) {
	restartDaemon9173(t)
	cfg := synCookieCfg9173(keyedCluster9173("", ""), "", "fw")
	before, _ := buildSYNCookieKeys(cfg, synCookieT0_9173)
	restartDaemon9173(t)
	if after, _ := buildSYNCookieKeys(cfg, synCookieT0_9173); len(before) != 32 || after == before {
		t.Fatalf("an unkeyed cluster has no shared secret, so its key must be per daemon start: %q then %q", before, after)
	}
	// An additional key alone signs nothing, so it must not enter the ring.
	_, ring := buildSYNCookieKeys(synCookieCfg9173(keyedCluster9173("", "psk-old"), "", "fw"), synCookieT0_9173)
	for _, b := range ring.Bases {
		if b.AcceptOnly {
			t.Fatal("an additional-authentication-key without an authentication-key must not add an accept-only base")
		}
	}
}

var rustCookieEpochSecsRe9173 = regexp.MustCompile(`pub\(crate\) const EPOCH_SECS: u64 = (\d+);`)

// TestSYNCookieEpochMatchesTheHelper9173: a period must be a whole number of the
// HELPER's cookie epochs, so Go's copy of that constant is pinned to the source.
func TestSYNCookieEpochMatchesTheHelper9173(t *testing.T) {
	src, err := os.ReadFile("../../../userspace-dp/src/screen/syncookie.rs")
	if err != nil {
		t.Fatalf("read the helper's cookie codec: %v", err)
	}
	var code strings.Builder
	for _, line := range strings.Split(string(src), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "//") {
			code.WriteString(line + "\n")
		}
	}
	match := rustCookieEpochSecsRe9173.FindStringSubmatch(code.String())
	if match == nil {
		t.Fatal("SynCookieCodec::EPOCH_SECS not found in userspace-dp/src/screen/syncookie.rs")
	}
	if match[1] != "64" || synCookieEpochSecs != 64 {
		t.Fatalf("helper cookie epoch %s s, Go synCookieEpochSecs %d s: they must agree", match[1], synCookieEpochSecs)
	}
}

// TestSYNCookieEpochKeyMatchesTheHelper9173 pins deriveSYNCookieEpochKey to a
// known-answer vector that userspace-dp's
// syn_cookie_epoch_key_matches_the_control_plane_derivation_9173 asserts too.
// The helper derives every period's key from the ring's bases, so the two
// derivations must never drift apart one language at a time.
func TestSYNCookieEpochKeyMatchesTheHelper9173(t *testing.T) {
	base := make([]byte, 32)
	for i := range base {
		base[i] = byte(i)
	}
	const want = "a028081b51656faa6cd12471864df2c5"
	if got := deriveSYNCookieEpochKey(base, 502_232); got != want {
		t.Fatalf("deriveSYNCookieEpochKey(0x00..0x1f, 502232) = %s; the helper derives %s", got, want)
	}
}

// TestSYNCookieBaseDerivationVector9173 pins deriveSYNCookieBase to a known
// answer. Two cluster nodes on different builds must derive one base, so a change
// to its label, field order or framing has to be deliberate.
func TestSYNCookieBaseDerivationVector9173(t *testing.T) {
	// #9740: the screened zones left the base, which moved this vector. The value
	// was computed independently of this package, and that computation reproduced
	// the previous zone-bearing vector first.
	got := hex.EncodeToString(deriveSYNCookieBase([]byte("xpf-kat-psk"), "cluster-id=3"))
	const want = "490ca8d4374e5e570cd9d8298f06a3e323f135fd75b88615adbc03d2d081156e"
	if got != want {
		t.Fatalf("deriveSYNCookieBase vector = %s, want %s", got, want)
	}
}

// TestSYNCookieKeysEnterTheContentDigestOnlyAsSaltedFingerprints9173: the #9520
// digest reaches state.json and conflict logs, so it must not be an offline
// oracle for a keyed cluster's authentication-key, which the keys derive from.
func TestSYNCookieKeysEnterTheContentDigestOnlyAsSaltedFingerprints9173(t *testing.T) {
	key, ring := buildSYNCookieKeys(synCookieCfg9173(keyedCluster9173("weak", ""), "", "fw"), synCookieT0_9173)
	snap := &ConfigSnapshot{DefaultPolicy: "permit", SYNCookieMasterKey: key, SYNCookieKeyRing: ring}
	digest, ok := snapshotContentHash(snap)
	if !ok || key == "" {
		t.Fatal("premise: a keyed snapshot and a computable digest")
	}
	// The ring's bases are fingerprinted too, not only the key.
	if fp := synCookieRingDigestFingerprint(ring); fp == nil || len(fp.Bases) != len(ring.Bases) ||
		fp.Bases[0].Base == ring.Bases[0].Base {
		t.Fatal("the content digest must carry each ring base only as a salted fingerprint")
	}

	// What an offline attacker computes: the same content with the key they
	// guessed, hashed raw.
	raw := *snap
	raw.Neighbors = filterPublishableNeighbors(snap.Neighbors)
	data, err := json.Marshal(&raw)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if sha256.Sum256(data) == digest {
		t.Fatal("the content digest is a raw hash over the SYN-cookie keys: an offline oracle for the authentication-key")
	}
	// Again with the ring alone, so a fingerprinted key cannot make the digests
	// differ by itself: the bases must not enter the digest raw either.
	ringOnly := &ConfigSnapshot{DefaultPolicy: "permit", SYNCookieKeyRing: ring}
	ringDigest, ok := snapshotContentHash(ringOnly)
	if !ok {
		t.Fatal("premise: a ring-only snapshot hashes")
	}
	rawRing := *ringOnly
	rawRing.Neighbors = filterPublishableNeighbors(ringOnly.Neighbors)
	if data, err := json.Marshal(&rawRing); err != nil || sha256.Sum256(data) == ringDigest {
		t.Fatalf("the content digest hashes the ring's bases raw (marshal err %v): an offline oracle for the authentication-key", err)
	}

	// Exactness is kept: a snapshot differing only in its keys hashes differently.
	otherKey, otherRing := buildSYNCookieKeys(synCookieCfg9173(keyedCluster9173("other", ""), "", "fw"), synCookieT0_9173)
	if other, _ := snapshotContentHash(&ConfigSnapshot{DefaultPolicy: "permit", SYNCookieMasterKey: otherKey,
		SYNCookieKeyRing: otherRing}); other == digest {
		t.Fatal("a snapshot differing only in its SYN-cookie keys must hash differently")
	}

	// A new daemon start draws a new salt, so nothing outside this process can
	// recompute the digest for the same content.
	saved := synCookieDigestSalt
	synCookieDigestSalt = sync.OnceValue(newSynCookieProcessSecret)
	t.Cleanup(func() { synCookieDigestSalt = saved })
	if restarted, _ := snapshotContentHash(snap); restarted == digest {
		t.Fatal("the digest did not depend on the per-start salt, so it can be recomputed offline")
	}
}
