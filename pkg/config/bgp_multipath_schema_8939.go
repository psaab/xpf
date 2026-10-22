package config

// #8939 at `protocols bgp multipath`: A PACKED RUN SET ONLY ITS FIRST OPTION.
//
//	set protocols bgp multipath ibgp multiple-as
//	  -> MultipathIBGP=true  MultipathMultipleAS=FALSE
//
// SetPath nests the second option onto the first's Keys rather than making them
// siblings -- `[multipath] > [ibgp multiple-as]` -- and the compile loop read
// `mc.Name()` and dropped the rest of that node's keys with it.
//
// The consequence is a routing one rather than cosmetic: `multiple-as` is what
// lets eBGP multipath span differing AS paths, so losing it silently narrows
// the path set the operator asked for, and FRR renders from these two booleans.
//
// Both options are `args: 0` declared children of `multipath`, so expandFlatRun
// cuts the run at the second keyword -- the same composition #9153 used for the
// filter `then` clause, and arity-aware since #9124.
// bgpMultipathSchema8939 resolves the `protocols bgp multipath` container so
// expandFlatRun knows which tokens are siblings rather than values.
func bgpMultipathSchema8939() *schemaNode {
	return refBGPMultipath.resolve()
}
