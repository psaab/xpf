package config

// #8939 at `routing-options interface-routes rib-group`: A PACKED RUN SET ONLY
// THE FIRST FAMILY.
//
//	set routing-options interface-routes rib-group inet RG inet6 RG
//	  -> InterfaceRoutesRibGroup="RG"  InterfaceRoutesRibGroupV6=""
//
// SetPath nests the second family onto the first rather than making them
// siblings, so the compile loop read `inet` and dropped the v6 rib-group with
// it. The consequence is an inter-VRF route leak the operator configured that
// silently does not happen for one address family — and a half-configured leak
// is harder to notice than an absent one, because v4 works.
//
// Applied at BOTH the global site and its routing-instance twin. Fixing one and
// not the other is how this class keeps coming back.
func interfaceRoutesRibGroupSchema8939() *schemaNode {
	return refInterfaceRoutesRibGroup.resolve()
}
