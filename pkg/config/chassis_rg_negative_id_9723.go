package config

import "fmt"

// dropNegativeRedundancyGroups removes every redundancy group with a negative id
// from a leniently compiled cluster config and returns one warning per dropped
// group (#9723).
//
// Strict commit refuses such a group, but the tolerant load / peer-sync path
// only warns and used to keep it. compileChassis parses the id with
// strconv.Atoi, so `redundancy-group -1` really is -1. The heartbeat saturates a
// group id onto its single wire byte (#8337), which maps every negative id to 0,
// the byte RG0 uses. A node holding RG0 and RG -1 then resolved the peer's RG0
// entry to either group, so RG0's election could run on another group's state
// or on none, on both nodes.
//
// Only NEGATIVE ids are dropped. They are the only out-of-range ids that alias a
// group that can actually run: every valid id is 0..MaxRedundancyGroups-1, and a
// negative id also can never index the dataplane's rg_active array, so the group
// could never activate anyway. An id above 255 saturates onto 255, which no valid
// group uses, and #8337 keeps and advertises it on purpose. Both nodes load the
// same synced config, so both drop the same groups and their views agree.
func dropNegativeRedundancyGroups(cc *ClusterConfig) []string {
	if cc == nil {
		return nil
	}
	var warnings []string
	kept := cc.RedundancyGroups[:0]
	for _, rg := range cc.RedundancyGroups {
		if rg != nil && rg.ID < 0 {
			warnings = append(warnings, fmt.Sprintf(
				"chassis cluster redundancy-group %d dropped on the tolerant path: a negative "+
					"id saturates to heartbeat wire byte 0 and would alias redundancy-group 0, "+
					"and it can never activate; renumber it (#9723)", rg.ID))
			continue
		}
		kept = append(kept, rg)
	}
	cc.RedundancyGroups = kept
	return warnings
}
