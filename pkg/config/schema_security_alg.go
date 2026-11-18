package config

// #19190: the VALUE ARITY of the inert ALG statements whose Junos grammar is
// known. A bodiless flag owns no following token, so a `disable` after it on
// the same line is the CLASS's; a valued statement owns exactly its one value.
// Every other inert statement (a container such as traceoptions, or one whose
// arity is not recorded here) owns the rest of its line and body, as #16814
// designed: `traceoptions flag disable` is a traceoptions body, not a class
// disable. Before #19190 every inert statement was treated as a container, so
// `set security alg ftp allow-mismatch-ip-address disable` committed clean
// and left the ALG ENABLED.
var algInertFlags19190 = map[string]bool{
	"allow-mismatch-ip-address": true, "ftps-extension": true, "line-break-extension": true,
	"oversize-message-drop": true, "enable-call-distribution": true, "hide-via-headers": true,
	"retain-hold-resource": true,
}

var algInertValued19190 = map[string]bool{
	"doctoring": true, "maximum-message-length": true, "c-timeout": true, "inactive-media-timeout": true,
	"maximum-call-duration": true, "t1-interval": true, "t4-interval": true,
}

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
