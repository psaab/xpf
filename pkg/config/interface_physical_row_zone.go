package config

// PhysicalRowZoneKey returns the bare base name under which a zone member
// is attributed to a physical-interface row in the detail / extensive
// `show interfaces` views (#14364, #16562). Those views render ONE zone
// line per physical interface, queried by the bare interface name, so a
// member resolves only when it names the base itself or its unit 0
// ("ge-0/0/1.0" / "eth0.0" govern the physical interface's default unit).
// A non-zero unit member ("ge-0/0/9.50") is NOT attributed to the
// physical row — that zone belongs to the logical unit (rendered per-unit
// by the VLAN view) and claiming it here would misattribute a VLAN unit.
// Malformed suffixes (rejected at commit by the strict #5933 gate) never
// resolve. Splitting routes through the declared-name-aware
// SplitInterfaceUnitRef (#9821) and CanonicalLogicalUnit (#5878), so
// spellings like ".00" fold to unit 0 exactly as the binders do.
//
// This is the single implementation shared by the local CLI presenters
// (pkg/cli) and the gRPC text presenters (pkg/grpcapi) so the twins
// cannot drift (#4984/#5325 parity, #16562).
func PhysicalRowZoneKey(cfg *Config, member string) (string, bool) {
	s := cfg.SplitInterfaceUnitRef(member)
	if !s.HasUnit {
		return s.Base, true
	}
	u, _, err := CanonicalLogicalUnit(s.UnitTok)
	if err != nil || u != 0 {
		return "", false
	}
	return s.Base, true
}
