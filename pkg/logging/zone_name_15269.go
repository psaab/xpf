package logging

// ZoneName resolves a zone id to its configured name (or the numeric
// spelling when unmapped) for show/syslog consumers. Exported for
// cross-package regression tests of the zone-name map writers (#15269).
func (er *EventReader) ZoneName(id uint16) string { return er.resolveZoneName(id) }
