package config

// dynamicAddressSchema is the `security dynamic-address` subtree of
// schemaSecurity: feed servers, their feeds, and the address names bound to
// them. It lives in its own file because #9689's fail-mode leaf took
// schema_security.go past the 1500 LOC refactoraudit floor; the subtree is
// unchanged apart from that leaf and the profile node's packedStatements.
func dynamicAddressSchema() *schemaNode {
	return &schemaNode{desc: "Dynamic address feeds", children: map[string]*schemaNode{
		"feed-server": {desc: "Feed server name", args: 1, placeholder: "<server-name>", children: map[string]*schemaNode{
			"url":             {desc: "Feed URL (takes precedence over hostname)", args: 1, placeholder: "<url>", children: nil},
			"hostname":        {desc: "Server hostname for building per-feed URLs", args: 1, scalar: true, placeholder: "<hostname>", children: nil},
			"update-interval": {desc: "Feed refresh interval in seconds (default 3600)", args: 1, valueType: ValueInteger, valueDesc: "Seconds (> 0)", valueExamples: []string{"3600", "300"}, validator: ValidateInteger(1, MaxDurationSeconds), placeholder: "<seconds>", children: nil},
			"hold-interval":   {desc: "Drop a feed's last-good snapshot to empty after N seconds of fetch failure; omit to retain last-good forever (default)", args: 1, valueType: ValueInteger, valueDesc: "Seconds (> 0)", valueExamples: []string{"86400"}, validator: ValidateInteger(1, MaxDurationSeconds), placeholder: "<seconds>", children: nil},
			"feed-name": {desc: "Named feed on this server", args: 1, placeholder: "<feed-name>", children: map[string]*schemaNode{
				"path": {desc: "Path on the feed server for this feed", args: 1, placeholder: "<path>", children: nil},
			}},
		}},
		"address-name": {desc: "Dynamic address name bound to feeds", args: 1, placeholder: "<address-name>", children: map[string]*schemaNode{
			// #9689: packedStatements, because `profile` now has two scalar leaves
			// (feed-name, fail-mode). A packed run `profile feed-name f fail-mode drop;`
			// splits by the schema's own counts, and the flat, braced and compact
			// spellings compile identically (TestDynamicAddressFailModeSurvivesOneLineSpellings9689).
			"profile": {desc: "Feed binding profile", packedStatements: true, children: map[string]*schemaNode{
				"feed-name": {desc: "Feed to bind to this address name", args: 1, placeholder: "<feed-name>", children: nil},
				"fail-mode": {desc: "What a feed's hold-interval drop does to this binding: retain (default) keeps enforcing the previous-good policy set, drop publishes an empty set (#9689)", args: 1, valueType: ValueEnumOf, valueDesc: "retain | drop", placeholder: "<mode>", validator: ValidateEnum([]string{"retain", "drop"}), children: nil},
			}},
		}},
	}}
}
