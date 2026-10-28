package config

// compiler_rfc2136_endpoint.go: the single compile for the shared RFC 2136
// endpoint leaves (#17237). Both compileDDNSProvider (Surface A catalog) and
// compileDHCPDynamicDNS (Surface B per-family) build their endpoint through
// here, so a new endpoint leaf is added in exactly one place.

// compileRFC2136Endpoint builds an RFC2136Endpoint from the leaf->value props
// map both compile walkers produce (keys are the Junos leaf names).
func compileRFC2136Endpoint(props map[string]string) RFC2136Endpoint {
	return RFC2136Endpoint{
		UpdateServer:         props["update-server"],
		ForwardZone:          props["forward-zone"],
		ReverseZone:          props["reverse-zone"],
		TSIGKeyName:          props["tsig-key"],
		TSIGAlgorithm:        props["tsig-algorithm"],
		TSIGSecret:           NewSecret(props["tsig-secret"]),
		RequireTSIG:          props["require-tsig"] == "true",
		SourceAddress:        props["source-address"],
		DestinationInterface: props["destination-interface"],
		RoutingInstance:      props["routing-instance"],
	}
}
