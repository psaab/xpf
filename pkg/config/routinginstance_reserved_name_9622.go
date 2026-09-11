package config

import (
	"fmt"
	"sort"
)

// ManagementVRFInstanceName is the name of the VRF the daemon creates for the
// management interfaces (vrf-mgmt, kernel table 999; pkg/daemon
// daemon_apply_interfaces.go). It is THE definition of that name: the daemon
// reads it from here, and the reserved-name gate below refuses an
// operator-defined routing instance of the same name (#9622).
//
// Before #9622 the daemon hardcoded "mgmt" and nothing in pkg/config knew it
// was taken. A `routing-instances mgmt` stanza committed clean, and every
// apply then planned two VRF specs with the same name and different tables,
// deleting and re-creating vrf-mgmt and binding the operator's members and the
// management NICs to one device.
const ManagementVRFInstanceName = "mgmt"

// reservedRoutingInstanceNames is the set of routing-instance names the daemon
// uses for its own VRFs. Names are case-sensitive, as kernel device names and
// Junos instance names are, so "MGMT" and "vrf-mgmt" are not reserved: the VRF
// device name is "vrf-" + the instance name, and "vrf-vrf-mgmt" does not
// collide with "vrf-mgmt".
var reservedRoutingInstanceNames = map[string]string{
	ManagementVRFInstanceName: "the management VRF the daemon creates for the management interfaces (vrf-mgmt, table 999)",
}

// IsReservedRoutingInstanceName reports whether name is a routing-instance name
// the daemon reserves for its own VRF.
func IsReservedRoutingInstanceName(name string) bool {
	_, ok := reservedRoutingInstanceNames[name]
	return ok
}

// validateReservedRoutingInstanceNamesAST refuses a routing instance whose name
// the daemon reserves (#9622), judged on the same three-view name union as the
// #3855 table-id gate so a `groups`-defined or `${node}`-expanded instance is
// caught and both cluster nodes decide identically.
//
// Strict (commit / commit-check) returns an error. Lenient (load / peer-sync of
// an already-persisted config) returns a warning so the node still boots
// (#1960 no-brick), and compileRoutingInstances QUARANTINES the instance so it
// never reaches the daemon.
func validateReservedRoutingInstanceNamesAST(tree *ConfigTree, lenient bool) ([]string, error) {
	names := routingInstanceNameUnionAST(tree)
	var hits []string
	for name := range names {
		if IsReservedRoutingInstanceName(name) {
			hits = append(hits, name)
		}
	}
	if len(hits) == 0 {
		return nil, nil
	}
	sort.Strings(hits)
	var warnings []string
	for _, name := range hits {
		msg := fmt.Sprintf("routing-instance name %q is reserved for %s — an instance of that name "+
			"would merge with it; rename the instance (#9622)", name, reservedRoutingInstanceNames[name])
		if !lenient {
			return nil, fmt.Errorf("routing-instances: %s", msg)
		}
		warnings = append(warnings, msg+"; the instance is QUARANTINED (no VRF created, its members "+
			"are not bound and its routes are not programmed) until it is renamed")
	}
	return warnings, nil
}
