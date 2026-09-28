package config

const (
	// MaxDynamicAddressFeedPrefixes bounds parsed feed contents and guard knobs.
	MaxDynamicAddressFeedPrefixes = 1 << 20
	// DefaultDynamicAddressShrinkGuardMinOldCount is the bootstrap/small-feed exemption floor.
	DefaultDynamicAddressShrinkGuardMinOldCount = 32
	// DefaultDynamicAddressShrinkGuardRetainPct is the default retained-prefix percentage floor.
	DefaultDynamicAddressShrinkGuardRetainPct = 50
	// DefaultDynamicAddressShrinkGuardMinDrop is the default absolute-drop floor.
	DefaultDynamicAddressShrinkGuardMinDrop = 16
)

// dynamicAddressSchema is the `security dynamic-address` subtree of
// schemaSecurity: feed servers, their feeds, and the address names bound to
// them. It lives in its own file because #9689's fail-mode leaf took
// schema_security.go past the 1500 LOC refactoraudit floor. It also holds
// #10337's feed-server packedFlatRun boundary, #11059's runtime shrink-guard
// leaves, and the profile node's packedStatements.
func dynamicAddressSchema() *schemaNode {
	return &schemaNode{desc: "Dynamic address feeds", children: map[string]*schemaNode{
		"feed-server": {desc: "Feed server name", args: 1, placeholder: "<server-name>", packedFlatRun: true, children: map[string]*schemaNode{
			"url":                             {desc: "Feed URL (takes precedence over hostname)", args: 1, placeholder: "<url>", children: nil},
			"hostname":                        {desc: "Server hostname for building per-feed URLs", args: 1, scalar: true, placeholder: "<hostname>", children: nil},
			"update-interval":                 {desc: "Feed refresh interval in seconds (default 3600)", args: 1, valueType: ValueInteger, valueDesc: "Seconds (> 0)", valueExamples: []string{"3600", "300"}, validator: ValidateInteger(1, MaxDurationSeconds), placeholder: "<seconds>", children: nil},
			"hold-interval":                   {desc: "Drop a feed's last-good snapshot to empty after N seconds of fetch failure; omit to retain last-good forever (default)", args: 1, valueType: ValueInteger, valueDesc: "Seconds (> 0)", valueExamples: []string{"86400"}, validator: ValidateInteger(1, MaxDurationSeconds), placeholder: "<seconds>", children: nil},
			"shrink-guard-min-old-count":      {desc: "Minimum prior prefix count before drastic-shrink protection applies (default 32)", args: 1, valueType: ValueInteger, valueDesc: "Prefix count", valueExamples: []string{"32"}, validator: ValidateInteger(1, MaxDynamicAddressFeedPrefixes), placeholder: "<count>", children: nil},
			"shrink-guard-min-retain-percent": {desc: "Minimum candidate retention ratio before a shrink is refused (default 50)", args: 1, valueType: ValueInteger, valueDesc: "Percent (1-100)", valueExamples: []string{"50"}, validator: ValidateInteger(1, 100), placeholder: "<percent>", children: nil},
			"shrink-guard-min-drop":           {desc: "Minimum absolute prefix decrease before a shrink is refused (default 16)", args: 1, valueType: ValueInteger, valueDesc: "Prefix count", valueExamples: []string{"16"}, validator: ValidateInteger(1, MaxDynamicAddressFeedPrefixes-1), placeholder: "<count>", children: nil},
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
