package config

import (
	"fmt"
	"sort"
)

// ManagementVRFInstanceName is the name of the VRF the daemon creates for the
// management interfaces (pkg/daemon daemon_apply_interfaces.go). With
// ManagementVRFDeviceName and ManagementVRFTableID below it is THE definition
// of the management VRF: the daemon's VRF planning and binding, the networkd
// compiler, the HA socket wiring, the management route reconcile and the FIB
// importer read them from here, and the reserved-name gate refuses an
// operator-defined routing instance of the same name (#9622).
//
// Before #9622 the daemon hardcoded "mgmt" and nothing in pkg/config knew it
// was taken. A `routing-instances mgmt` stanza committed clean, and every
// apply then planned two VRF specs with the same name and different tables,
// deleting and re-creating vrf-mgmt and binding the operator's members and the
// management NICs to one device.
//
// This is an xpf reservation, NOT Junos parity. Junos reserves `mgmt_junos`,
// which exists only when `system management-instance` is configured; xpf has
// no such knob and always creates its management VRF under this name. A config
// written for Junos with an ordinary instance named `mgmt` commits there, is
// rejected here, and must be renamed.
const ManagementVRFInstanceName = "mgmt"

// ManagementVRFDeviceName is the management VRF's kernel device. pkg/routing
// names every VRF device "vrf-" + the instance name.
const ManagementVRFDeviceName = "vrf-" + ManagementVRFInstanceName

// ManagementVRFTableID is the kernel routing table behind the management VRF.
const ManagementVRFTableID = 999

// reservedRoutingInstanceNames is the set of routing-instance names the daemon
// uses for its own VRFs. Names are case-sensitive, as kernel device names and
// Junos instance names are, so "MGMT" and "vrf-mgmt" are not reserved: the VRF
// device name is "vrf-" + the instance name, and "vrf-vrf-mgmt" does not
// collide with "vrf-mgmt".
var reservedRoutingInstanceNames = map[string]string{
	ManagementVRFInstanceName: fmt.Sprintf("the management VRF the daemon creates for the management interfaces (%s, table %d)",
		ManagementVRFDeviceName, ManagementVRFTableID),
}

// IsReservedRoutingInstanceName reports whether name is a routing-instance name
// the daemon reserves for its own VRF.
func IsReservedRoutingInstanceName(name string) bool {
	_, ok := reservedRoutingInstanceNames[name]
	return ok
}

// validateReservedRoutingInstanceNamesAST refuses a routing instance whose name
// the daemon reserves (#9622). It judges the same three-view name union as the
// #3855 table-id gate (routingInstanceNameUnionAST), so an instance is caught
// wherever it is declared: any top-level `routing-instances` root, any `groups`
// block an apply-groups statement reaches (#9657), either AST shape including the brace-elided leaf, or the node0/node1
// expansion. Both cluster nodes therefore decide identically.
//
// It runs on the STRICT path only (commit / commit-check). The tolerant load and
// peer-sync paths skip it (lenientReservedRoutingInstanceName), and
// compileRoutingInstances quarantines the instance with ONE warning, on the tree
// the node actually compiles. The node still boots (#1960 no-brick) and the
// daemon never plans the instance.
func validateReservedRoutingInstanceNamesAST(tree *ConfigTree) error {
	var hits []string
	for name := range routingInstanceNameUnionAST(tree) {
		if IsReservedRoutingInstanceName(name) {
			hits = append(hits, name)
		}
	}
	if len(hits) == 0 {
		return nil
	}
	sort.Strings(hits)
	return fmt.Errorf("routing-instances: routing-instance name %q is reserved for %s — an instance of that name "+
		"would merge with it; rename the instance (#9622)", hits[0], reservedRoutingInstanceNames[hits[0]])
}
