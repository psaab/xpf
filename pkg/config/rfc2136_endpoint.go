package config

// RFC2136Endpoint is the shared RFC 2136 endpoint shape (#17237): the ten
// leaves (update-server, forward-zone, reverse-zone, tsig-key, tsig-algorithm,
// tsig-secret, require-tsig, source-address, destination-interface,
// routing-instance) declared once and embedded in both DDNSProvider and
// DHCPDynamicDNSConfig, so the two hand-kept twins cannot diverge again
// (#15225 updated only the provider empty-block check; its DHCP twin then
// discarded a zone-only v6 block and v6 silently inherited the v4 policy).
// Field promotion keeps existing selectors (p.UpdateServer, d.TSIGSecret,
// ...) compiling unchanged.
type RFC2136Endpoint struct {
	// UpdateServer is the RFC 2136 target authoritative DNS, host or host:port.
	UpdateServer string
	// ForwardZone / ReverseZone are explicit RFC 2136 UPDATE zones
	// (#15225 A40-05, comma/space-separated lists). When set they take
	// precedence over SOA discovery; empty means discover via SOA walk.
	ForwardZone string
	ReverseZone string
	// TSIGKeyName / TSIGAlgorithm / TSIGSecret are the TSIG credentials for
	// authenticated RFC 2136 updates. TSIGSecret is the sensitive HMAC key,
	// redacted by the Secret type on every marshal and by the owners' String().
	TSIGKeyName   string
	TSIGAlgorithm string
	TSIGSecret    Secret
	// RequireTSIG (#15992) rejects a strict commit with a non-loopback
	// update-server but no tsig-key. Default (false) keeps unsigned
	// source-IP-ACL BIND publishing working.
	RequireTSIG bool
	// SourceAddress / DestinationInterface / RoutingInstance scope the UPDATE
	// TRANSPORT (#2691 P1b / #2665): Dialer.LocalAddr, SO_BINDTODEVICE to the
	// interface, or SO_BINDTODEVICE to the VRF master device named by the
	// routing-instance. All optional; empty means default routing. As of
	// #2846 the HTTP backends and the checkip probe bind to these too.
	SourceAddress        string
	DestinationInterface string
	RoutingInstance      string
}

// IsZero reports whether no RFC 2136 endpoint leaf is set. It is the single
// empty-block predicate both compile paths use, so a future leaf added to
// RFC2136Endpoint is automatically honoured by every empty check (pinned by
// the reflection test in rfc2136_zone_only_17237_test.go).
func (e RFC2136Endpoint) IsZero() bool {
	return e.UpdateServer == "" && e.ForwardZone == "" && e.ReverseZone == "" &&
		e.TSIGKeyName == "" && e.TSIGAlgorithm == "" && e.TSIGSecret.Reveal() == "" &&
		!e.RequireTSIG && e.SourceAddress == "" && e.DestinationInterface == "" &&
		e.RoutingInstance == ""
}

// MergeFrom fills zero fields of e from src (first-writer-wins, matching
// mergeDHCPDynamicDNS's per-field rule). RequireTSIG latches on.
func (e *RFC2136Endpoint) MergeFrom(src RFC2136Endpoint) {
	if e.UpdateServer == "" {
		e.UpdateServer = src.UpdateServer
	}
	if e.ForwardZone == "" {
		e.ForwardZone = src.ForwardZone
	}
	if e.ReverseZone == "" {
		e.ReverseZone = src.ReverseZone
	}
	if e.TSIGKeyName == "" {
		e.TSIGKeyName = src.TSIGKeyName
	}
	if e.TSIGAlgorithm == "" {
		e.TSIGAlgorithm = src.TSIGAlgorithm
	}
	if e.TSIGSecret.Reveal() == "" {
		e.TSIGSecret = src.TSIGSecret
	}
	e.RequireTSIG = e.RequireTSIG || src.RequireTSIG
	if e.SourceAddress == "" {
		e.SourceAddress = src.SourceAddress
	}
	if e.DestinationInterface == "" {
		e.DestinationInterface = src.DestinationInterface
	}
	if e.RoutingInstance == "" {
		e.RoutingInstance = src.RoutingInstance
	}
}
