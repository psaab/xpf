package userspace

import (
	"encoding/json"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9161: the hybrid-apply guard compared `json.Marshal` output, in which
// `config.Secret` renders REDACTED — so a WireGuard key rotation compared EQUAL,
// the #5680 refusal did not fire, and the snapshot was marked applied carrying
// the OLD keys. The operator was told the rotation landed while the tunnel ran
// on the previous material.
//
// The guard's own justification asserted the opposite of the code: "the helper
// ALWAYS receives the redacted JSON encoding — it never sees raw secrets".
// `protocol_tunnels.go` declares `WgLocalPrivkeyHex` as a PLAIN string with a
// json tag and `tunnels.go` fills it with `.Reveal()`. WireGuard was also absent
// from that comment's list of secret-bearing subsystems applying on separate
// paths — it does not apply on one.
func wgConfig9161(privkey, psk string) *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"wg0": {
			Tunnel: &config.TunnelConfig{
				Name:              "wg0",
				Mode:              "wireguard",
				WgListenPort:      51820,
				WgLocalPrivkeyHex: config.NewSecret(privkey),
				WgPeers: []config.WgPeerConfig{
					{PublicKeyHex: "aaaa", PresharedKeyHex: config.NewSecret(psk)},
				},
			},
		},
	}
	return cfg
}

// THE DEFECT: a rotation of the local private key must be visible.
func TestSecretOnlyRotationIsADifference9161(t *testing.T) {
	before := wgConfig9161("1111111111111111111111111111111111111111111111111111111111111111", "psk-a")
	after := wgConfig9161("2222222222222222222222222222222222222222222222222222222222222222", "psk-a")

	// PRECONDITION: the redacted marshal really cannot tell these apart. If it
	// could, this cell would pass without exercising the fix at all.
	if !sameRedactedMarshal9161(t, before, after) {
		t.Fatal("fixture: the two configs differ in their REDACTED marshal, so this " +
			"cell is not measuring the secret-blindness it is about")
	}

	if configsContentEqual(before, after) {
		t.Fatal("a WireGuard PRIVATE KEY rotation compared EQUAL. The #5680 refusal " +
			"does not fire, the snapshot is marked applied carrying the OLD key, and " +
			"the operator is told the rotation applied while the tunnel runs on the " +
			"previous material (#9161)")
	}
}

// The per-peer preshared key is the second revealed secret and needs its own row
// — a digest covering only the tunnel-level key would pass the cell above.
func TestPresharedKeyRotationIsADifference9161(t *testing.T) {
	before := wgConfig9161("1111111111111111111111111111111111111111111111111111111111111111", "psk-a")
	after := wgConfig9161("1111111111111111111111111111111111111111111111111111111111111111", "psk-b")
	if configsContentEqual(before, after) {
		t.Fatal("a per-peer PRESHARED KEY rotation compared EQUAL (#9161)")
	}
}

// CONTROL 1 — no change must still compare EQUAL. Without this the assertions
// above are satisfied by a guard that reports every config as different, which
// would refuse every route-only publish and is a worse defect than the one being
// fixed.
func TestIdenticalConfigsStillCompareEqual9161(t *testing.T) {
	a := wgConfig9161("1111111111111111111111111111111111111111111111111111111111111111", "psk-a")
	b := wgConfig9161("1111111111111111111111111111111111111111111111111111111111111111", "psk-a")
	if !configsContentEqual(a, b) {
		t.Fatal("two identical configs compared DIFFERENT — every route-only publish " +
			"would be refused")
	}
}

// CONTROL 2 — the coarsening this guard was designed around must SURVIVE. A
// secret the helper never receives must still compare equal, or the fix has
// restored the over-strict DeepEqual the comment explicitly forbids.
func TestASecretTheHelperNeverSeesStillComparesEqual9161(t *testing.T) {
	a := &config.Config{}
	a.System.SNMP = &config.SNMPConfig{V3Users: map[string]*config.SNMPv3User{
		"u": {Name: "u", AuthProtocol: "sha256", AuthPassword: config.NewSecret("secret-one")},
	}}
	b := &config.Config{}
	b.System.SNMP = &config.SNMPConfig{V3Users: map[string]*config.SNMPv3User{
		"u": {Name: "u", AuthProtocol: "sha256", AuthPassword: config.NewSecret("secret-two")},
	}}

	if !configsContentEqual(a, b) {
		t.Fatal("an SNMPv3 password change — a secret the HELPER NEVER RECEIVES — was " +
			"reported as a difference. That is the over-strict DeepEqual this guard's " +
			"coarsening exists to avoid, and its comment forbids restoring: the " +
			"digest must cover only secrets that demonstrably reach the helper")
	}
}

// Peer ORDER must not change the DIGEST. The snapshot builder sorts peers by
// public key before sending, so two authoring orders produce one snapshot and
// the helper cannot observe the difference.
//
// This drives `helperVisibleSecretDigest9161` DIRECTLY rather than through
// `configsContentEqual`, deliberately. Through the guard the cell would be
// VACUOUS: the marshal comparison runs first and already reports a reorder as a
// difference, so the digest is never consulted and a mutation dropping the sort
// would survive. Driving the extracted function is what makes the sort
// exercisable (the #9123 rule: extract the guard, do not write a comment
// excusing an unreachable one).
func TestPeerOrderDoesNotChangeTheDigest9161(t *testing.T) {
	mk := func(first, second string) *config.Config {
		cfg := &config.Config{}
		cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
			"wg0": {Tunnel: &config.TunnelConfig{
				Name: "wg0", Mode: "wireguard",
				WgPeers: []config.WgPeerConfig{
					{PublicKeyHex: first, PresharedKeyHex: config.NewSecret("k-" + first)},
					{PublicKeyHex: second, PresharedKeyHex: config.NewSecret("k-" + second)},
				},
			}},
		}
		return cfg
	}
	if helperVisibleSecretDigest9161(mk("aaaa", "bbbb")) != helperVisibleSecretDigest9161(mk("bbbb", "aaaa")) {
		t.Error("peer authoring order changed the digest; the snapshot builder sorts " +
			"by pubkey, so the helper cannot observe that order")
	}
	// The order is the ONLY thing held constant here: a real peer-secret change
	// must still move the digest, or the sort has flattened the input.
	if helperVisibleSecretDigest9161(mk("aaaa", "bbbb")) == helperVisibleSecretDigest9161(mk("aaaa", "cccc")) {
		t.Error("a different peer set produced the same digest")
	}
}

func sameRedactedMarshal9161(t *testing.T, a, b *config.Config) bool {
	t.Helper()
	ab, err := jsonMarshalFor9161(a)
	if err != nil {
		t.Fatalf("marshal a: %v", err)
	}
	bb, err := jsonMarshalFor9161(b)
	if err != nil {
		t.Fatalf("marshal b: %v", err)
	}
	return string(ab) == string(bb)
}

func jsonMarshalFor9161(c *config.Config) ([]byte, error) { return json.Marshal(c) }
