package config

// dhcpRelayOverridesSchema8939 resolves the
// `forwarding-options dhcp-relay group <name> overrides` container so
// expandFlatRun knows which tokens on a packed node are siblings.
//
// The same container is reachable under `group <g> interface <if> overrides`
// too, and both readers share this schema — the override keywords are the same
// set at either depth.
func dhcpRelayOverridesSchema8939() *schemaNode {
	return refDHCPrelayOverrides.resolve()
}
