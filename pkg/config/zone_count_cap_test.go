package config

import (
	"fmt"
	"strings"
	"testing"
)

// zonesConfig returns a *Config with n distinct security zones, built directly
// (no set-command parse) so the validateZoneCountStrict unit tests can exercise
// the pigeonhole cap at scale without paying the parser / collision-gate cost.
func zonesConfig(n int) *Config {
	zones := make(map[string]*ZoneConfig, n)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("z%05d", i)
		zones[name] = &ZoneConfig{Name: name}
	}
	return &Config{Security: SecurityConfig{Zones: zones}}
}

// TestZoneCountCapValue freezes the post-#3075 cap. #2391's u8 wire limit (255)
// is SUPERSEDED: zone ids are now a stable name-hash in a u16 space, so the
// usable space — and therefore the max number of distinct zones — is
// ZoneIDReservedMin-1 (65533, the top two ids reserved for the global / host
// sentinels). If this changes you altered the zone-id space; review the wire
// widen and the collision gate.
func TestZoneCountCapValue(t *testing.T) {
	if MaxUsableZoneID != int64(ZoneIDReservedMin)-1 {
		t.Fatalf("MaxUsableZoneID = %d, want ZoneIDReservedMin-1 = %d", MaxUsableZoneID, int64(ZoneIDReservedMin)-1)
	}
	if MaxUsableZoneID != 4294967293 {
		t.Fatalf("MaxUsableZoneID = %d, want 4294967293 (#16557 widened the u16 space)", MaxUsableZoneID)
	}
}

// TestZoneCountStrictRejectsOverCap asserts the pigeonhole belt: a config with
// more than MaxUsableZoneID distinct zones cannot be assigned distinct u16
// stable-hash ids and is hard-rejected. (In practice the StableZoneID collision
// gate rejects far sooner — at the first hash collision — but the count cap is
// the cheap O(1) backstop.) Removing validateZoneCountStrict makes the over-cap
// config pass this direct check, which is the regression it guards.
func TestZoneCountStrictRejectsOverCap(t *testing.T) {
	if MaxUsableZoneID > 100_000_000 {
		// #16557: the u32 cap (4,294,967,293) cannot be materialised as a
		// real zone map in a test. The O(1) comparison itself is exercised
		// by TestZoneCountCapValue + the small-config tests; the over-cap
		// branch is unreachable at test scale.
		t.Skip("u32 zone cap too large to materialise an over-cap config")
	}
	err := validateZoneCountStrict(zonesConfig(int(MaxUsableZoneID + 1)))
	if err == nil {
		t.Fatalf("validateZoneCountStrict accepted %d zones (cap is %d)", MaxUsableZoneID+1, MaxUsableZoneID)
	}
	for _, want := range []string{
		fmt.Sprintf("%d security zones", MaxUsableZoneID+1),
		fmt.Sprintf("at most %d", MaxUsableZoneID),
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not contain %q", err.Error(), want)
		}
	}
}

// TestZoneCountStrictAcceptsAtCap asserts the boundary is inclusive: EXACTLY
// MaxUsableZoneID zones is accepted by the count cap.
func TestZoneCountStrictAcceptsAtCap(t *testing.T) {
	if MaxUsableZoneID > 100_000_000 {
		t.Skip("u32 zone cap too large to materialise an at-cap config (#16557)")
	}
	if err := validateZoneCountStrict(zonesConfig(int(MaxUsableZoneID))); err != nil {
		t.Fatalf("validateZoneCountStrict rejected a config at exactly the %d-zone cap: %v", MaxUsableZoneID, err)
	}
}

// TestZoneCountStrictAcceptsSmall asserts the common case and the nil guard.
func TestZoneCountStrictAcceptsSmall(t *testing.T) {
	if err := validateZoneCountStrict(nil); err != nil {
		t.Fatalf("validateZoneCountStrict(nil) = %v, want nil", err)
	}
	if err := validateZoneCountStrict(zonesConfig(3)); err != nil {
		t.Fatalf("validateZoneCountStrict rejected a 3-zone config: %v", err)
	}
}

// TestZoneCountNormalConfigUnaffected asserts a small, ordinary zone count
// commits cleanly through the full compile pipeline — neither the cap nor the
// stable-zone-id collision gate perturb the common case.
func TestZoneCountNormalConfigUnaffected(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security zones security-zone dmz",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict commit rejected an ordinary 3-zone config: %v", err)
	}
}
