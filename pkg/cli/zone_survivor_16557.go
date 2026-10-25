package cli

import "github.com/psaab/xpf/pkg/config"

// survivorZoneNames16 projects the u32 survivor reverse map onto the u16
// session/event id space (#16557). See pkg/grpcapi twin.
func survivorZoneNames16(zoneIDs map[string]uint32, cfg *config.Config) map[uint16]string {
	full := config.SurvivorZoneNames(zoneIDs, cfg)
	out := make(map[uint16]string, len(full))
	for id, name := range full {
		// Session/event records carry the low 16 bits of the u32 id
		// (the frozen u16 record field); key the projection by that
		// truncation so a record resolves to its survivor. Distinct
		// zones truncating to the same u16 alias here - the record
		// itself cannot distinguish them (documented #16557 residual).
		out[uint16(id)] = name
	}
	return out
}
