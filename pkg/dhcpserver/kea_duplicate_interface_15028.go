package dhcpserver

// dedupKeaInterfaces returns the Kea interfaces-config list with each
// kernel device named once, keeping the first occurrence in the callers'
// stable order, for both the v4 and v6 generators (#15028).
//
// The generators walk groups in stableGroups order and append every
// group's interfaces verbatim, so a config that reached the renderer
// despite naming one device twice — a reth ref and its member ref, a
// unit-0 ref and its bare parent, or one ref repeated across groups —
// emitted the device twice. Kea refuses a duplicate in the interfaces
// list and then loads nothing, so every pool of the family stops.
//
// Commit refuses the duplicate
// (validateDHCPGroupInterfacesUniqueStrict in pkg/config); this is the
// belt for a config that reached the renderer anyway, through the
// tolerant load or peer-sync path. A "" entry names no device at all and
// is not a duplicate.
func dedupKeaInterfaces(ifaces []string) ([]string, []string) {
	seen := make(map[string]bool, len(ifaces))
	out := make([]string, 0, len(ifaces))
	var dropped []string
	for _, iface := range ifaces {
		if iface == "" {
			out = append(out, iface)
			continue
		}
		if seen[iface] {
			dropped = append(dropped, iface)
			continue
		}
		seen[iface] = true
		out = append(out, iface)
	}
	return out, dropped
}
