package config

// dynamicAddressProfileSchema9689 returns the schema node for
// `security dynamic-address address-name <name> profile`, the container whose
// leaves the dynamic-address compiler reads.
//
// #9689 gave `profile` a second leaf (`fail-mode`), which makes a packed one-line
// spelling possible, and SetPath builds it in two shapes, both measured:
//
//	set ... profile feed-name f fail-mode drop
//	  [profile] > [feed-name f] > [fail-mode drop]     (nested)
//	profile { feed-name f fail-mode drop; }
//	  [profile] > [feed-name f fail-mode drop]         (packed)
//
// A reader matching profile.Children by name sees only feed-name in both shapes
// and drops fail-mode on a commit that reports success (the #2419 and #9156
// gates caught it). hoistAndSplitRun8939 undoes both shapes, given this node.
func dynamicAddressProfileSchema9689() *schemaNode {
	sec := resolveSchemaChild(setSchema, "security")
	da := resolveSchemaChild(sec, "dynamic-address")
	an := resolveSchemaChild(da, "address-name")
	if an == nil {
		return nil
	}
	if an.wildcard != nil {
		an = an.wildcard
	}
	return resolveSchemaChild(an, "profile")
}
