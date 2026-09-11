package userspace

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestBuildScreenSnapshotsSynFloodSubThresholds verifies the #3315 SYN-flood
// sub-thresholds (alarm/source/destination) cross the userspace-dp wire. Before
// the fix only attack-threshold was published, so the four sub-thresholds
// committed cleanly yet were operationally inert. This is the FAIL-ON-REVERT
// guard for the WIRE PLUMBING only: dropping the screens.go populate block makes
// the three asserts below go zero and the test RED. It does NOT exercise the
// hot-path enforcement — the per-destination/per-source cap drops and the
// log-only alarm gate (and their RED-on-revert) live in the Rust screen runtime
// tests (`cargo test --bin xpf-userspace-dp screen::`, userspace-dp/src/screen/
// tests.rs). #3527: `timeout` now ALSO crosses the wire (SYNFloodTimeout) — it
// maps to the per-zone half-open session window (tcp_opening_ns); the Rust
// SessionTable opening-override tests guard the enforcement RED-on-revert.
func TestBuildScreenSnapshotsSynFloodSubThresholds(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", ScreenProfile: "flood"},
	}
	cfg.Security.Screen = map[string]*config.ScreenProfile{
		"flood": {
			Name: "flood",
			TCP: config.TCPScreen{SynFlood: &config.SynFloodConfig{
				AttackThreshold:      2000,
				AlarmThreshold:       1000,
				SourceThreshold:      50,
				DestinationThreshold: 100,
				Timeout:              20,
			}},
		},
	}
	snaps := buildScreenSnapshots(cfg)
	if len(snaps) != 1 {
		t.Fatalf("expected 1 screen snapshot, got %d", len(snaps))
	}
	s := snaps[0]
	if s.SYNFloodThreshold != 2000 {
		t.Errorf("SYNFloodThreshold = %d, want 2000", s.SYNFloodThreshold)
	}
	if s.SYNFloodAlarmThreshold != 1000 {
		t.Errorf("SYNFloodAlarmThreshold = %d, want 1000", s.SYNFloodAlarmThreshold)
	}
	if s.SYNFloodSrcThreshold != 50 {
		t.Errorf("SYNFloodSrcThreshold = %d, want 50", s.SYNFloodSrcThreshold)
	}
	if s.SYNFloodDstThreshold != 100 {
		t.Errorf("SYNFloodDstThreshold = %d, want 100", s.SYNFloodDstThreshold)
	}
	// #3527: the half-open `timeout` now crosses the wire too.
	if s.SYNFloodTimeout != 20 {
		t.Errorf("SYNFloodTimeout = %d, want 20", s.SYNFloodTimeout)
	}

	// JSON round-trip: the additive fields serialize and decode unchanged.
	blob, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back ScreenProfileSnapshot
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.SYNFloodAlarmThreshold != 1000 || back.SYNFloodSrcThreshold != 50 ||
		back.SYNFloodDstThreshold != 100 || back.SYNFloodTimeout != 20 {
		t.Errorf("round-trip lost sub-thresholds: %+v", back)
	}

	// Skew tolerance: a JSON blob from an OLD Go control plane (no sub-threshold
	// keys) decodes them to 0 (disabled) rather than failing.
	old := `{"zone":"trust","syn_flood_threshold":2000}`
	var legacy ScreenProfileSnapshot
	if err := json.Unmarshal([]byte(old), &legacy); err != nil {
		t.Fatalf("legacy decode: %v", err)
	}
	if legacy.SYNFloodAlarmThreshold != 0 || legacy.SYNFloodSrcThreshold != 0 ||
		legacy.SYNFloodDstThreshold != 0 || legacy.SYNFloodTimeout != 0 {
		t.Errorf("legacy snapshot must decode sub-thresholds as 0, got %+v", legacy)
	}
}

// fable-review-164 L-10: the profile-wide `alarm-without-drop` audit modifier
// must thread from the typed config across the Go->Rust screen snapshot wire.
// FAIL-ON-REVERT: drop the AlarmWithoutDrop assignment in buildScreenSnapshots
// (or the wire field) and the AlarmWithoutDrop assertion goes RED.
func TestBuildScreenSnapshotsAlarmWithoutDrop(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"untrust": {Name: "untrust", ScreenProfile: "audit"},
	}
	cfg.Security.Screen = map[string]*config.ScreenProfile{
		"audit": {
			Name:             "audit",
			TCP:              config.TCPScreen{Land: true},
			AlarmWithoutDrop: true,
		},
	}
	snaps := buildScreenSnapshots(cfg)
	if len(snaps) != 1 {
		t.Fatalf("expected 1 screen snapshot, got %d", len(snaps))
	}
	if !snaps[0].AlarmWithoutDrop {
		t.Fatalf("AlarmWithoutDrop not carried into the snapshot")
	}

	// JSON round-trip preserves the flag; a legacy blob without the key
	// decodes false (drop-on-trip) rather than failing (#1961 skew tolerance).
	blob, err := json.Marshal(snaps[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back ScreenProfileSnapshot
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !back.AlarmWithoutDrop {
		t.Fatalf("round-trip lost AlarmWithoutDrop: %+v", back)
	}
	var legacy ScreenProfileSnapshot
	if err := json.Unmarshal([]byte(`{"zone":"untrust","land":true}`), &legacy); err != nil {
		t.Fatalf("legacy decode: %v", err)
	}
	if legacy.AlarmWithoutDrop {
		t.Fatalf("legacy snapshot must decode AlarmWithoutDrop as false")
	}
}

// A profile carrying ONLY alarm-without-drop (no enabled check) is a no-op and
// must NOT be published — the modifier is intentionally excluded from the
// emit gate (nothing to alarm on without a check).
func TestBuildScreenSnapshotsAlarmWithoutDropAloneNotPublished(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"untrust": {Name: "untrust", ScreenProfile: "audit"},
	}
	cfg.Security.Screen = map[string]*config.ScreenProfile{
		"audit": {Name: "audit", AlarmWithoutDrop: true},
	}
	if snaps := buildScreenSnapshots(cfg); len(snaps) != 0 {
		t.Fatalf("a check-less alarm-without-drop profile must not publish, got %d", len(snaps))
	}
}

func TestBuildScreenSnapshotsMatchesZoneToProfile(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust", ScreenProfile: "basic"},
		"untrust": {Name: "untrust"},
	}
	cfg.Security.Screen = map[string]*config.ScreenProfile{
		"basic": {
			Name: "basic",
			TCP:  config.TCPScreen{Land: true, SynFin: true},
			ICMP: config.ICMPScreen{FloodThreshold: 50},
		},
	}
	snaps := buildScreenSnapshots(cfg)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1", len(snaps))
	}
	if snaps[0].Zone != "trust" {
		t.Fatalf("Zone = %q, want trust", snaps[0].Zone)
	}
	if !snaps[0].Land || !snaps[0].SynFin {
		t.Fatalf("unexpected screen flags: %+v", snaps[0])
	}
	if snaps[0].ICMPFloodThreshold != 50 {
		t.Fatalf("ICMPFloodThreshold = %d, want 50", snaps[0].ICMPFloodThreshold)
	}
}

// #3962: buildScreenSnapshots must serialize the per-zone screen profiles in a
// deterministic (sorted-by-zone-name) order. Before the fix it ranged the
// cfg.Security.Zones map directly, so the wire byte order varied build-to-build
// even for an UNCHANGED config. That shifted the snapshotContentHash every
// build, defeated the reconcile dedup, and re-applied the whole screen config
// on every reconcile. Building the snapshot many times from the same config
// must yield byte-identical (and equal-hash) Screens output. Goes RED on
// revert because map iteration order randomizes per run.
func TestBuildScreenSnapshotsDeterministicOrder(t *testing.T) {
	cfg := &config.Config{}
	// Many zones, each enabling a screen check, so map-order randomization is
	// overwhelmingly likely to reorder the output across N builds pre-fix.
	cfg.Security.Zones = map[string]*config.ZoneConfig{}
	cfg.Security.Screen = map[string]*config.ScreenProfile{}
	zoneNames := []string{"trust", "untrust", "dmz", "wan", "lan", "guest", "mgmt", "iot", "voice", "video"}
	for i, zn := range zoneNames {
		profile := "prof-" + zn
		cfg.Security.Zones[zn] = &config.ZoneConfig{Name: zn, ScreenProfile: profile}
		cfg.Security.Screen[profile] = &config.ScreenProfile{
			Name: profile,
			TCP:  config.TCPScreen{Land: true, SynFin: i%2 == 0},
			ICMP: config.ICMPScreen{FloodThreshold: i + 1},
		}
	}

	first := buildScreenSnapshots(cfg)
	if len(first) != len(zoneNames) {
		t.Fatalf("len(first) = %d, want %d", len(first), len(zoneNames))
	}
	// Pin the deterministic contract: output is sorted ascending by zone name.
	for i := 1; i < len(first); i++ {
		if first[i-1].Zone >= first[i].Zone {
			t.Fatalf("snapshots not sorted by zone: %q before %q", first[i-1].Zone, first[i].Zone)
		}
	}

	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("marshal first: %v", err)
	}
	firstHash := sha256.Sum256(firstJSON)

	const iterations = 64
	for n := 0; n < iterations; n++ {
		got := buildScreenSnapshots(cfg)
		gotJSON, err := json.Marshal(got)
		if err != nil {
			t.Fatalf("marshal iteration %d: %v", n, err)
		}
		if !bytes.Equal(firstJSON, gotJSON) {
			t.Fatalf("iteration %d: screen snapshot bytes differ (nondeterministic order)\nfirst: %s\ngot:   %s",
				n, firstJSON, gotJSON)
		}
		if sha256.Sum256(gotJSON) != firstHash {
			t.Fatalf("iteration %d: content hash differs from first build", n)
		}
	}

	// The missing-profile-refs sibling feeds ConfigSnapshot.ScreenMissingProfiles
	// and so also feeds the content hash — it must be deterministic too. Point a
	// few zones at undefined profiles.
	for _, zn := range []string{"trust", "wan", "iot"} {
		cfg.Security.Zones[zn].ScreenProfile = "does-not-exist-" + zn
	}
	firstMissing, err := json.Marshal(buildScreenMissingProfileRefs(cfg))
	if err != nil {
		t.Fatalf("marshal first missing: %v", err)
	}
	for n := 0; n < iterations; n++ {
		gotMissing, err := json.Marshal(buildScreenMissingProfileRefs(cfg))
		if err != nil {
			t.Fatalf("marshal missing iteration %d: %v", n, err)
		}
		if !bytes.Equal(firstMissing, gotMissing) {
			t.Fatalf("iteration %d: missing-profile-refs bytes differ (nondeterministic order)\nfirst: %s\ngot:   %s",
				n, firstMissing, gotMissing)
		}
	}
}

func TestBuildScreenSnapshotsMarksSynCookieMode(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Flow.SynFloodProtectionMode = "syn-cookie"
	cfg.System.RootAuthentication = &config.RootAuthConfig{
		EncryptedPassword: "$6$rounds=5000$salt$hash",
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", ScreenProfile: "flood"},
	}
	cfg.Security.Screen = map[string]*config.ScreenProfile{
		"flood": {
			Name: "flood",
			TCP:  config.TCPScreen{SynFlood: &config.SynFloodConfig{AttackThreshold: 100}},
		},
	}

	snaps := buildScreenSnapshots(cfg)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1", len(snaps))
	}
	if !snaps[0].SYNCookie {
		t.Fatalf("SYNCookie = false, want true: %+v", snaps[0])
	}
	snap := mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 1, 0)
	if len(snap.SYNCookieMasterKey) != 32 || snap.SYNCookieKeyRing == nil {
		t.Fatalf("SYNCookieMasterKey len = %d, ring = %v; want a 32-hex key and a ring",
			len(snap.SYNCookieMasterKey), snap.SYNCookieKeyRing)
	}
	// #9173: the key no longer derives from root-authentication, so removing it
	// leaves a cookie key in place instead of failing closed.
	cfg.System.RootAuthentication = nil
	cfg.System.MasterPassword = "juniper-prf1"
	snap = mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 1, 0)
	if len(snap.SYNCookieMasterKey) != 32 {
		t.Fatalf("SYNCookieMasterKey without root secret = %q, want a 32-hex key", snap.SYNCookieMasterKey)
	}
}

func TestBuildScreenSnapshotsIncludesAdvancedFields(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", ScreenProfile: "advanced"},
	}
	cfg.Security.Screen = map[string]*config.ScreenProfile{
		"advanced": {
			Name: "advanced",
			TCP:  config.TCPScreen{PortScanThreshold: 100},
			IP:   config.IPScreen{IPSweepThreshold: 50},
			LimitSession: config.LimitSessionScreen{
				SourceIPBased:      200,
				DestinationIPBased: 300,
			},
		},
	}
	snaps := buildScreenSnapshots(cfg)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1", len(snaps))
	}
	if snaps[0].PortScanThreshold != 100 {
		t.Fatalf("PortScanThreshold = %d, want 100", snaps[0].PortScanThreshold)
	}
	if snaps[0].IPSweepThreshold != 50 {
		t.Fatalf("IPSweepThreshold = %d, want 50", snaps[0].IPSweepThreshold)
	}
	if snaps[0].SessionLimitSrc != 200 {
		t.Fatalf("SessionLimitSrc = %d, want 200", snaps[0].SessionLimitSrc)
	}
	if snaps[0].SessionLimitDst != 300 {
		t.Fatalf("SessionLimitDst = %d, want 300", snaps[0].SessionLimitDst)
	}
}

// #1137 Copilot review regression: a profile with ONLY syn_frag
// enabled (and no other check) must still pass the
// "at least one check enabled" emit gate. Without this, a future
// refactor could drop SynFrag from the gate and silently omit the
// whole profile from the userspace snapshot.
func TestBuildScreenSnapshotsIncludesSynFragOnlyProfile(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan", ScreenProfile: "syn-frag-only"},
	}
	cfg.Security.Screen = map[string]*config.ScreenProfile{
		"syn-frag-only": {
			Name: "syn-frag-only",
			TCP:  config.TCPScreen{SynFrag: true},
		},
	}
	snaps := buildScreenSnapshots(cfg)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1 — syn_frag-only profile must pass the emit gate", len(snaps))
	}
	if !snaps[0].SynFrag {
		t.Fatalf("SynFrag = false, want true")
	}
	// Sanity: nothing else should be on
	if snaps[0].SynFin || snaps[0].NoFlag || snaps[0].FinNoAck ||
		snaps[0].WinNuke || snaps[0].PingDeath || snaps[0].Teardrop ||
		snaps[0].SourceRoute || snaps[0].Land {
		t.Fatalf("unexpected other-checks set: %+v", snaps[0])
	}
}

// #3316: an icmp-fragment-only screen profile must publish ICMPFragment in the
// snapshot AND pass the emit gate. The Rust dataplane (screen/stateless.rs
// check_icmp_fragment) consumes the `icmp_fragment` field and drops fragmented
// ICMP/ICMPv6 — but buildScreenSnapshots never set the field nor counted it in
// the enabled-profile predicate, so the protection was unreachable from config.
// RED if the screens.go publish (or the predicate inclusion) is reverted.
func TestBuildScreenSnapshotsIncludesICMPFragmentOnlyProfile(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan", ScreenProfile: "icmp-frag-only"},
	}
	cfg.Security.Screen = map[string]*config.ScreenProfile{
		"icmp-frag-only": {
			Name: "icmp-frag-only",
			ICMP: config.ICMPScreen{Fragment: true},
		},
	}
	snaps := buildScreenSnapshots(cfg)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1 — icmp-fragment-only profile must pass the emit gate", len(snaps))
	}
	if !snaps[0].ICMPFragment {
		t.Fatalf("ICMPFragment = false, want true — snapshot must publish the icmp-fragment screen")
	}
	// Sanity: nothing else should be on.
	if snaps[0].SynFin || snaps[0].NoFlag || snaps[0].FinNoAck ||
		snaps[0].WinNuke || snaps[0].PingDeath || snaps[0].Teardrop ||
		snaps[0].SynFrag || snaps[0].SourceRoute || snaps[0].Land {
		t.Fatalf("unexpected other-checks set: %+v", snaps[0])
	}
}

// #3082: a zone that REFERENCES an undefined screen profile must be recorded
// in the references-missing set so the dataplane can emit a runtime WARN
// (instead of silently passing all screen checks). A zone with no screen
// configured, and a zone whose reference resolves, must NOT be recorded.
func TestBuildScreenMissingProfileRefs(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust", ScreenProfile: "ghost"}, // references missing
		"untrust": {Name: "untrust", ScreenProfile: "real"},
		"dmz":     {Name: "dmz"}, // no screen configured
	}
	cfg.Security.Screen = map[string]*config.ScreenProfile{
		"real": {Name: "real", TCP: config.TCPScreen{Land: true}},
	}
	refs := buildScreenMissingProfileRefs(cfg)
	if len(refs) != 1 {
		t.Fatalf("len(refs) = %d, want 1 (only the dangling reference); refs=%+v", len(refs), refs)
	}
	if refs[0].Zone != "trust" || refs[0].Profile != "ghost" {
		t.Fatalf("refs[0] = %+v, want {Zone:trust Profile:ghost}", refs[0])
	}
}

// #3082: a zone with a valid screen reference and a zone with no screen at all
// must produce NO missing-profile refs even when other zones reference missing
// profiles is not the case here (pure-negative guard).
func TestBuildScreenMissingProfileRefsNoneWhenResolved(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", ScreenProfile: "real"},
		"dmz":   {Name: "dmz"}, // no screen
	}
	cfg.Security.Screen = map[string]*config.ScreenProfile{
		"real": {Name: "real", TCP: config.TCPScreen{Land: true}},
	}
	if refs := buildScreenMissingProfileRefs(cfg); len(refs) != 0 {
		t.Fatalf("len(refs) = %d, want 0; refs=%+v", len(refs), refs)
	}
}
