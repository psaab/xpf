package flowexport

import "hash/fnv"

// stableExporterID maps an exporter group's config identity
// (protocol, sampling-instance name, referenced template name, address family)
// to a stable, nonzero 32-bit id used as the NetFlow v9 header SourceID
// (RFC 3954 §5.1) and the IPFIX header Observation Domain ID
// (RFC 7011 §3.1). It mirrors config.StableTunnelEndpointID / #1873:
// FNV-1a 64 over "protocol|instance|template" for inet and
// "protocol|instance|template|v6" for inet6, xor-folded to 32 bits,
// mapped into [1, 0xFFFFFFFF].
//
// WHY (#3740, #6811, #12148): #3740 gave each (instance, template) group
// a stable id, but groups then contained both address families. #6811 split
// groups by family to prevent cross-family export; this made one inet group
// and one inet6 group with the same (instance, template, collector) compute
// the same id. NetFlow v9 collectors commonly key streams on (exporter source
// IP, SourceID), so independent v9 sequence streams could be mistaken for
// packet loss or exporter restarts. A family suffix gives each group its own
// observation domain; template IDs 256/257 can remain conventional because
// 256 under ODID-A is a different template from 256 under ODID-B.
//
// HA symmetry (the load-bearing constraint): flow export is NOT gated on
// RG mastership — both cluster nodes run exporters from the same synced
// config. Because the id is a pure function of config-synced fields
// (protocol/instance/template/family) and of NOTHING node-specific, both
// nodes compute the IDENTICAL id for a given group, so a failover never
// presents the collector a new observation domain. This is the same
// HA-symmetry argument #1873 relies on, satisfied by construction.
//
// The protocol tag ("netflow9" vs "ipfix") is folded in so a v9 group
// and an IPFIX group with the same instance/template never share a value
// (belt-and-braces; a flow-server binds one version per #2136, so they
// never actually co-point).
//
// Degenerate-default guard: a hand-built ExportConfig{} (the singular
// Build* helpers and several unit tests) carries no instance AND no
// template. The inet default keeps the historical SourceID/ODID = 1 (some
// collectors treat ODID 0 specially). An inet6 group still gets its family
// suffix so it cannot share an id with a same-identity inet group. Real
// multi-group configs always carry a non-empty InstanceName (sampling
// instances are named).
//
// ID migration (#12148): inet ids are unchanged; only inet6 ids change to
// their family-suffixed hash. Collectors therefore see a new v9 SourceID /
// IPFIX ODID for each inet6 group after upgrade. This separates the v9
// sequence streams; collectors or dashboards keyed by the former inet6 id
// may need their filters updated. Templates are re-announced automatically.
func stableExporterID(protocol, instance, template string, isV6 bool) uint32 {
	if instance == "" && template == "" && !isV6 {
		return 1
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(protocol))
	_, _ = h.Write([]byte{'|'})
	_, _ = h.Write([]byte(instance))
	_, _ = h.Write([]byte{'|'})
	_, _ = h.Write([]byte(template))
	if isV6 {
		_, _ = h.Write([]byte("|v6"))
	}
	s := h.Sum64()
	folded := uint32(s) ^ uint32(s>>32)
	return folded%0xFFFFFFFF + 1
}
