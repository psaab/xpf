package config

// algProtoSchema16814 declares the Junos statement heads accepted without
// implementation. Bodies are intentionally opaque, as for unmodeled ALG
// classes (#4232); the alg container's validator preserves typo rejection
// at the class boundary. See docs/log/16814.md for sources.
func algProtoSchema16814(proto string) *schemaNode {
	children := map[string]*schemaNode{
		"disable": {desc: "Disable this ALG"},
	}
	var inert []string
	switch proto {
	case "dns":
		inert = []string{"doctoring", "maximum-message-length", "oversize-message-drop", "traceoptions"}
	case "ftp":
		inert = []string{"allow-mismatch-ip-address", "ftps-extension", "line-break-extension", "traceoptions"}
	case "sip":
		inert = []string{"application-screen", "bulk-call-mode", "c-timeout", "distribution-ip", "dscp-rewrite", "enable-call-distribution", "hide-via-headers", "inactive-media-timeout", "maximum-call-duration", "retain-hold-resource", "t1-interval", "t4-interval", "traceoptions"}
	case "tftp", "pptp":
		inert = []string{"traceoptions"}
	}
	for _, keyword := range inert {
		children[keyword] = &schemaNode{desc: "Accepted but inert (not implemented)", closedWorldOpaque: true}
	}
	return &schemaNode{
		desc: proto + " ALG", closedWorldOpaque: true,
		children: children,
	}
}
