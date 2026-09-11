package config

// schema_routing.go carries the routing/forwarding subtrees of the
// config-mode grammar SSOT (#1891 domain split): `routing-options`,
// `policy-options`, `protocols`, `forwarding-options`,
// `bridge-domains`, and `routing-instances`. The root composition, the
// schemaNode type, and the split rationale live in schema.go.

// samplingFlowServerNode builds the typed `flow-server <address>` leaf for
// a sampling output block (#1979 Layer B, Tier 2). It is a fresh node per
// call so the inet and inet6 families own independent subtrees (mirrors
// syslogFacilitySeverityLeaf). flow-server KEEPS args:1 for the collector
// address; adding a children map deliberately flips its bare-terminal
// `set ... flow-server <addr>` behaviour from single-value REPLACE to
// named-container APPEND (ast_edit.go) — benign: a bare no-port server
// compiles Port==0 and the snapshot builder skips it, and real collectors
// carry `port` (taking the container path already). The `port` value feeds
// the Rust u16 CollectorPort wire field; Layer A skips a server whose port
// is <1 or >65535, so the bound is [1, 65535]. version9-template /
// version9 { template } / version-ipfix-template / version-ipfix
// { template } / source-address are the other children the sampling
// compiler reads (compiler_services.go compileSamplingFamily) — declared
// so completion does not silently drop them. A per-server version9 /
// version-ipfix selector binds THIS collector to exactly one export
// protocol (Junos semantics, #2136).
func samplingFlowServerNode() *schemaNode {
	return &schemaNode{
		desc: "Flow collector address", args: 1, placeholder: "<address>",
		children: map[string]*schemaNode{
			"port": {desc: "Flow collector UDP port", args: 1, placeholder: "<port>",
				valueType: ValueInteger, valueDesc: "Flow collector UDP port (1..65535)",
				valueExamples: []string{"2055", "9995"}, validator: ValidateInteger(1, maxWireU16), children: nil},
			"version9-template": {desc: "NetFlow v9 template name for this collector", args: 1, placeholder: "<template-name>", children: nil},
			"version9": {desc: "NetFlow v9 export options", children: map[string]*schemaNode{
				"template": {desc: "NetFlow v9 template name", args: 1, placeholder: "<template-name>", children: nil},
			}},
			"version-ipfix-template": {desc: "IPFIX template name for this collector", args: 1, placeholder: "<template-name>", children: nil},
			"version-ipfix": {desc: "IPFIX export options", children: map[string]*schemaNode{
				"template": {desc: "IPFIX template name", args: 1, placeholder: "<template-name>", children: nil},
			}},
			"source-address": {desc: "Source address for exported flows", args: 1, placeholder: "<address>", children: nil},
		},
	}
}

// staticRouteNode builds the typed `route <destination>` node for a static
// routes block (#2448). It is a fresh node per call so each static block
// (routing-options, per-rib, and the routing-instances mirrors) owns an
// independent subtree. The destination identity arg is validated as a
// family-agnostic CIDR (ValidateRouteDestination); the next-hop gateway is
// validated as an IP / ip@interface / interface-name (ValidateStaticNextHop)
// via the next-hop CONTAINER's keyValidator — so the optional
// `interface <iface>` child still walks as a value-bearing child in both AST
// shapes (a typed value-leaf would mis-route it through the presence-only
// modifier path). Both leaves were accepted untyped before #2448, so a
// malformed destination or next-hop committed cleanly and then silently
// failed to install in the FRR renderer and the Rust FIB builder. The
// remaining children (qualified-next-hop, discard, reject, next-table,
// preference) are declared so completion does not drop them and so each is
// recognized as a known child rather than an extra identity token.
func staticRouteNode() *schemaNode {
	return &schemaNode{
		desc: "Static route", args: 1, placeholder: "<destination>",
		keyValueType: ValueCIDR, keyValueDesc: "Route destination prefix (CIDR, e.g. 10.0.0.0/24 or ::/0)",
		keyValueExamples: []string{"0.0.0.0/0", "10.0.0.0/24", "::/0"},
		keyValidator:     ValidateRouteDestination,
		children: map[string]*schemaNode{
			// next-hop is a CONTAINER (keyValidator), NOT a typed value-leaf:
			// the gateway is validated via the identity-arg keyValidator
			// (ValidateStaticNextHop) so its optional `interface <iface>`
			// child — which the compiler supports for IPv6 link-local
			// gateways in BOTH the hierarchical
			// `next-hop fe80::50 { interface reth0.50; }` and the flat/inline
			// `next-hop fe80::50 interface reth0.50` shapes
			// (compiler_routing.go) — walks as a normal value-bearing child.
			// Modeling it as a typed value-leaf routed the `interface` child
			// through the presence-only modifier path, so the value token
			// after `interface` was rejected as `unknown modifier` (#2448
			// over-rejection regression).
			// #3872: next-hop is a multi + valueList leaf so a canonical Junos
			// ECMP list `next-hop [ gw1 gw2 ]` collapses onto ONE leaf
			// (Keys=["next-hop", gw1, gw2]) in BOTH the block-parse and
			// flat-set SetPath shapes, matching the #2419 multi-value pattern;
			// the compiler reads Keys[1:] and installs every gateway as an
			// equal-cost next-hop. valueList lets this multi leaf keep its
			// `interface` MODIFIER child: SetPath descends into the container
			// for the single-gateway IPv6 link-local form
			// (`next-hop fe80::1 interface reth0.50`) and absorbs the value
			// list otherwise (ast_edit.go). A qualified-next-hop backup is a
			// SEPARATE leaf (floating, per-NH preference, #3871), kept distinct
			// from this equal-cost list.
			"next-hop": {desc: "Next-hop gateway (IP, ip@interface, or interface name)", args: 1, multi: true, valueList: true, placeholder: "<gateway>",
				keyValueType: ValueIPAddress, keyValueDesc: "next-hop IP address, ip@interface, or interface name",
				keyValueExamples: []string{"192.168.1.1", "2001:db8::1"}, keyValidator: ValidateStaticNextHop,
				children: map[string]*schemaNode{
					"interface": {desc: "Egress interface for this next-hop", args: 1, placeholder: "<interface-name>", children: nil},
				}},
			// #5726: the qualified-next-hop gateway is validated at commit via
			// the CONTAINER keyValidator (ValidateStaticNextHop), mirroring the
			// sibling `next-hop` node. Before this the node carried no
			// keyValidator, so a typo'd floating-backup gateway (1.2.3.999)
			// committed clean and FRR then rendered it verbatim → the backup
			// silently never installed (discovered only during the primary-path
			// failure it exists to survive).
			"qualified-next-hop": {desc: "Qualified next-hop", args: 1, placeholder: "<gateway>",
				keyValueType: ValueIPAddress, keyValueDesc: "next-hop IP address, ip@interface, or interface name",
				keyValueExamples: []string{"192.168.1.1", "2001:db8::1"}, keyValidator: ValidateStaticNextHop,
				children: map[string]*schemaNode{
					"interface": {desc: "Egress interface", args: 1, placeholder: "<interface-name>", children: nil},
					// The qualified-next-hop preference is carried PER next-hop
					// (NextHopEntry.Preference, #3871) so the qualified gateway
					// renders as a FLOATING backup at its own admin distance — it is
					// NO LONGER folded into the single route-level preference (that
					// fold was the #3871 bug: it made every next-hop equal-cost).
					// The typing is still the same i32 wire field gated for the
					// route-level `preference` leaf (#3827): a negative / i32-
					// overflow value is rejected at commit (naming the leaf) instead
					// of only tripping the Rust snapshot backstop
					// (RoutePreferenceOutOfRange) with retained-prior-state.
					"preference": {desc: "Preference", args: 1, placeholder: "<value>",
						valueType: ValueInteger, valueDesc: "Route preference / administrative distance (0..2147483647; lower = more preferred, default 5)",
						valueExamples: []string{"5", "100"}, validator: ValidateInteger(0, maxWireI32), children: nil},
					// metric is carried per next-hop (NextHopEntry.Metric, #3871) but
					// NOT rendered — FRR's static-route CLI has no metric field, so a
					// metric-only qualified-next-hop (no preference) does NOT float;
					// preference is what creates the floating backup.
					"metric": {desc: "Metric", args: 1, placeholder: "<value>", children: nil},
				}},
			"discard":    {desc: "Discard (blackhole) route", children: nil},
			"reject":     {desc: "Reject route (send ICMP unreachable)", children: nil},
			"next-table": {desc: "Resolve in another routing table", args: 1, placeholder: "<table>", children: nil},
			// #3771 (L1): validate the route preference at the Go commit boundary
			// — a non-negative admin distance representable on the i32 wire. This
			// is the primary gate; the Rust helper backstops it
			// (RoutePreferenceOutOfRange) for a corrupt / version-drifted snapshot.
			"preference": {desc: "Route preference (administrative distance)", args: 1, placeholder: "<value>",
				valueType: ValueInteger, valueDesc: "Route preference / administrative distance (0..2147483647; lower = more preferred, default 5)",
				valueExamples: []string{"5", "100"}, validator: ValidateInteger(0, maxWireI32), children: nil},
		},
	}
}

var schemaRoutingOptions = &schemaNode{desc: "Routing options", children: map[string]*schemaNode{
	"static": {desc: "Static routes", children: map[string]*schemaNode{
		"route": staticRouteNode(),
	}},
	"rib": {desc: "Routing information base", args: 1, placeholder: "<rib-name>", children: map[string]*schemaNode{
		"static": {desc: "Static routes", children: map[string]*schemaNode{
			"route": staticRouteNode(),
		}},
	}},
	"autonomous-system": {desc: "Autonomous system number", args: 1, valueType: ValueInteger, placeholder: "<as-number>", validator: ValidateInteger(1, 4294967295), children: nil},
	"forwarding-table": {desc: "Forwarding table", children: map[string]*schemaNode{
		"export": {desc: "Export policy", args: 1, multi: true, placeholder: "<policy>", children: nil},
	}},
	"rib-groups": {desc: "RIB groups", wildcard: &schemaNode{desc: "RIB group name", placeholder: "<group-name>", children: map[string]*schemaNode{
		"import-rib": {desc: "Import RIB", children: nil},
	}}},
	"interface-routes": {desc: "Interface routes", children: map[string]*schemaNode{
		"rib-group": {desc: "RIB group", children: map[string]*schemaNode{
			"inet":  {desc: "IPv4 RIB group", args: 1, placeholder: "<group-name>", children: nil},
			"inet6": {desc: "IPv6 RIB group", args: 1, placeholder: "<group-name>", children: nil},
		}},
	}},
	"generate": {desc: "Generated routes", children: map[string]*schemaNode{
		"route": {desc: "Generated route", args: 1, placeholder: "<destination>", children: map[string]*schemaNode{
			"policy":  {desc: "Policy", args: 1, placeholder: "<policy>", children: nil},
			"discard": {desc: "Discard route", children: nil},
		}},
	}},
}}

var schemaPolicyOptions = &schemaNode{desc: "Policy options", children: map[string]*schemaNode{
	"prefix-list": {desc: "Prefix list", args: 1, placeholder: "<name>", keyValidator: ValidateFRRObjectName, children: nil},
	"community": {desc: "Community", args: 1, placeholder: "<name>", keyValidator: ValidateFRRObjectName, closedWorld: true, children: map[string]*schemaNode{
		"members": {desc: "Community members", args: 1, multi: true, placeholder: "<community>", children: nil},
	}},
	"as-path": {desc: "AS path", args: 2, multi: true, placeholder: "<name>", keyValidatorPos: ValidateASPathNameArg, children: nil},
	"policy-statement": {desc: "Policy statement", args: 1, placeholder: "<name>", keyValidator: ValidateFRRObjectName, children: map[string]*schemaNode{
		"term": {desc: "Term name", args: 1, placeholder: "<term-name>", keyValidator: ValidateFRRObjectName, children: map[string]*schemaNode{
			"from": {desc: "Match condition", children: map[string]*schemaNode{
				// "from protocol" is a multi-value match: Junos accepts
				// "from protocol [ bgp ospf static ]" and, equivalently, a
				// sequence of separate "set ... from protocol <X>" commands.
				// Mark it multi so SetPath keeps every protocol as a sibling
				// leaf instead of replacing the previous one (#2008 H18 /
				// Copilot #2011). A single-value leaf collapses separate set
				// commands down to only the last protocol.
				// #7121: valueExamples is the operator-facing completion list AND what the
				// #2419 compact/block equivalence probe synthesizes from. Without it the
				// probe used a placeholder the new strict gate rejects, so every spelling
				// failed identically and the cell went blind — it would have reported
				// "compiles equivalently" for a leaf it could no longer observe at all.
				// The domain itself is config.FRRRoutingProtocolKeyword; these are two
				// members of it, not a second copy.
				"protocol": {desc: "Protocol (direct, static, ospf, ospf6, bgp, rip, ripng, isis, kernel)", args: 1, multi: true, placeholder: "<protocol>", valueExamples: []string{"bgp", "ospf"}, children: nil},
				// prefix-list / route-filter / community / as-path may all be
				// repeated within one term (Junos OR's repeated same-type `from`
				// matches). Mark them multi so SetPath keeps every flat-set
				// `set ... from <type> <value>` line as a distinct sibling leaf
				// instead of overwriting the previous one (#2630). Without multi,
				// the i>=len(path) single-value-leaf branch in SetPath filters
				// by Keys[0] and replaces every prior entry, so only the LAST
				// flat-set value survived — silently dropping all but the last
				// route-filter/prefix-list/community/as-path. route-filter is
				// args:2 (prefix + match-type); a trailing upto/range/through
				// arg lands as a fourth packed key via the multi value-tail
				// absorber, matching the brace AST the compiler already reads.
				"prefix-list":  {desc: "Prefix list", args: 1, multi: true, placeholder: "<list-name>", children: nil},
				"route-filter": {desc: "Route filter", args: 2, multi: true, placeholder: "<prefix>", keyValidatorPos: ValidateRouteFilterArgPositional, children: nil},
				"community":    {desc: "Community", args: 1, multi: true, placeholder: "<community>", children: nil},
				"as-path":      {desc: "AS path", args: 1, multi: true, placeholder: "<name>", children: nil},
			}},
			"then": {desc: "Action", children: map[string]*schemaNode{
				"accept":       {desc: "Accept route", children: nil},
				"reject":       {desc: "Reject route", children: nil},
				"next-hop":     {desc: "Next hop", args: 1, placeholder: "<address>", children: nil},
				"load-balance": {desc: "Load balance", args: 1, placeholder: "<policy>", children: nil},
				// #4688: type these three `then` leaves. Without a validator a
				// non-numeric value (`then local-preference abc`) committed
				// silently — the compiler's strconv.Atoi failed under an
				// err==nil gate with no else, so HasLocalPreference stayed false
				// and the FRR clause was never emitted (fail-open, no warning).
				// A uint32-overflow value (`then local-preference 42949672960`)
				// parsed as int64 in the compiler, rendered, then FRR (u32)
				// rejected it at frr-reload and aborted the WHOLE reload
				// (fable-167 R-1 class). ValidateInteger(0, maxWireU32) gates
				// local-preference/metric at commit — naming the leaf — so a
				// bad value never reaches FRR. metric-type is the OSPF external
				// route type, valid values 1 or 2.
				"local-preference": {desc: "Local preference", args: 1, placeholder: "<value>",
					valueType: ValueInteger, valueDesc: "Local preference (0..4294967295)",
					valueExamples: []string{"100", "200"}, validator: ValidateInteger(0, maxWireU32), children: nil},
				"metric": {desc: "Metric", args: 1, placeholder: "<value>",
					valueType: ValueInteger, valueDesc: "Metric (0..4294967295)",
					valueExamples: []string{"5", "100"}, validator: ValidateInteger(0, maxWireU32), children: nil},
				"metric-type": {desc: "Metric type", args: 1, placeholder: "<type>",
					valueType: ValueInteger, valueDesc: "OSPF external metric type (1 or 2)",
					valueExamples: []string{"1", "2"}, validator: ValidateInteger(1, 2), children: nil},
				// `then community` supports the Junos community operations
				// (add | delete | set | none) plus the legacy bare
				// `then community <value>` (= replace). multi:true packs the
				// optional operation keyword and the value onto one leaf's
				// Keys (`community add 65000:100`, `community none`,
				// `community 65000:100`); the compiler interprets the first
				// token as the operation when it is add/delete/set/none and
				// otherwise treats it as a bare replace value (#2848).
				"community": {desc: "Community (add | delete | set | none | <value>)", args: 1, multi: true, groupReplace: true, placeholder: "<add|delete|set|none|community>", children: nil},
				// `then as-path-prepend "<asn> <asn> ..."` prepends the listed
				// ASNs to the advertised AS_PATH (FRR `set as-path prepend`).
				// multi:true so a quoted "65001 65001" or bracketed
				// [ 65001 65001 ] list keeps EVERY ASN (order + repetition
				// matter — repeating the ASN is the whole mechanism); a
				// single-value leaf would drop all but the first (#2892).
				"as-path-prepend": {desc: "AS path prepend", args: 1, multi: true, groupReplace: true, placeholder: "<asn>", children: nil},
				// #4919: type `then origin` as an enum. Without a validator a
				// non-control invalid token (e.g. `igpp`) passed the #4498
				// sanitize belt and reached FRR verbatim, failing the route-map
				// grammar at frr-reload and stalling the WHOLE managed section.
				// FRR `set origin` accepts only igp | egp | incomplete.
				"origin": {desc: "Origin", args: 1, valueType: ValueEnumOf, valueDesc: "BGP origin (igp | egp | incomplete)", valueExamples: []string{"igp", "egp", "incomplete"}, validator: ValidateEnum([]string{"igp", "egp", "incomplete"}), placeholder: "<origin>", children: nil},
			}},
		}},
		// #8807-followup: compiler_routing.go:908 ITERATES this node's children
		// ("Default action at the policy level"), so it is a container the
		// schema declared as a bare leaf. Nothing was dropped — the compiler
		// never consulted the schema here — but `policy-statement <p> then
		// <TAB>` offered nothing, so the default action was undiscoverable
		// through `?` help. Declaring the two arms the compiler actually
		// reads makes completion match compilation.
		"then": {desc: "Default action", children: map[string]*schemaNode{
			"accept": {desc: "Accept routes not matched by any term", children: nil},
			"reject": {desc: "Reject routes not matched by any term", children: nil},
		}},
	}},
}}

// Router-advertisement lifetime upper bounds (#3895). The RA sender
// (pkg/ra/sender.go buildRA) builds and sends the whole Router Advertisement
// in a single WriteTo, so an option whose lifetime overflows its on-wire field
// makes the ndp marshal fail and aborts the ENTIRE RA — the segment then
// silently stops receiving RAs and hosts lose their default route / SLAAC when
// the current advertisements expire. #2497 typed these lifetimes as integers
// but left them UNBOUNDED (ValidateIntegerMin(0)); bound them at commit so an
// over-large value is rejected loudly instead of blackholing IPv6 at runtime.
const (
	// RFC 8781 §4: the PREF64 lifetime is a 13-bit value scaled by 8 seconds
	// on the wire, so the maximum representable lifetime is 8191*8 = 65528s.
	// A larger value makes ndp.PREF64.marshal return "scaled lifetime is too
	// large" and aborts the whole RA (the #3895 blackhole).
	raPREF64MaxLifetimeSeconds = 65528
	// RFC 4861 §4.2: the RA header Router Lifetime is a 16-bit seconds field.
	// A larger value silently wraps in ndp's uint16(lifetime) (65536 -> 0 =
	// "not a default router"), so hosts drop their default route.
	//
	// EXPORTED (#8597, muse-004 K72) because this bound is enforced on the
	// STRICT commit path only, and the RA sender has to re-apply it: the
	// tolerant Load / peer-sync ingress downgrades the typed-leaf violation to
	// a warning, and a NEGATIVE value then marshals to 65535 — the maximum,
	// not the minimum. It must re-apply THIS constant rather than a copied
	// 65535, so the gate and the sender cannot disagree about the ceiling.
	RARouterMaxLifetimeSeconds = 65535
	// RFC 4861 §4.6.2: the Prefix Information valid/preferred lifetimes are
	// 32-bit seconds fields (0xffffffff = infinity). A larger value silently
	// truncates in ndp's uint32(lifetime); bound at the 32-bit maximum.
	raPrefixMaxLifetimeSeconds = 4294967295
	// RFC 4861 §4.2: the RA header Reachable Time and Retrans Timer are
	// 32-bit unsigned millisecond fields. The RA sender marshals them via
	// ndp as time.Duration/time.Millisecond -> uint32, so a larger value
	// silently wraps on the wire. Bound both at the 32-bit millisecond
	// maximum; 0 is the RFC "unspecified" sentinel (host uses its own
	// defaults) and is the pre-existing behavior.
	RAReachableRetransMaxMillis = 4294967295
)

var schemaProtocols = &schemaNode{desc: "Protocols configuration", children: map[string]*schemaNode{
	"ospf": {desc: "OSPF configuration", children: map[string]*schemaNode{
		"router-id": {desc: "Router ID", args: 1, placeholder: "<address>", children: nil},
		// #9408: typed. The value is BITS PER SECOND (Junos units) and is
		// converted to FRR's Mbps `auto-cost reference-bandwidth (1-4294967)`
		// by ospfReferenceBandwidthMbps, the SSOT this validator and
		// compileProtocols share. Untyped, the suffix form (`1g`, `100m`) hit
		// a discarded strconv.Atoi error and silently rendered NO auto-cost
		// line, while a bare integer was passed verbatim into a directive
		// whose unit is Mbps. isTypedLeaf() is `valueType != ValueAny`, so the
		// valueType is what makes the validator RUN at all.
		"reference-bandwidth": {desc: "Reference bandwidth", args: 1,
			valueType:     ValueRate,
			valueDesc:     "OSPF auto-cost reference bandwidth in BITS PER SECOND (Junos units; 100 Mbps is 100m or 100000000). Must be a whole number of Mbps in 1000000..4294967000000, the window FRR's auto-cost reference-bandwidth (1-4294967 Mbps) can express",
			valueExamples: []string{"100m", "1g", "10g", "100000000"},
			validator:     ValidateOSPFReferenceBandwidth,
			placeholder:   "<bandwidth>", children: nil},
		"passive": {desc: "Passive mode", children: nil},
		"export":  {desc: "Export policy", args: 1, multi: true, placeholder: "<policy-name>", children: nil},
		"area": {desc: "OSPF area", args: 1, placeholder: "<area-id>", keyValidator: ValidateOSPFArea, children: map[string]*schemaNode{
			"interface": {desc: "Interface", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: map[string]*schemaNode{
				"passive":    {desc: "Passive interface", children: nil},
				"no-passive": {desc: "Non-passive interface", children: nil},
				"interface-type": {desc: "Interface type", args: 1, placeholder: "<type>",
					// #8481: typed. The token is written VERBATIM into the FRR managed
					// section (`ip ospf network %s`), and one line vtysh rejects fails
					// the entire reload — see schema_ospf_interface_type_8481.go.
					valueType: ValueEnumOf, valueDesc: "OSPF network type",
					valueExamples: OSPFNetworkTypes,
					validator:     ValidateOSPFInterfaceType, children: nil},
				// #8443: modeled ONLY so it is REFUSED — see
				// schema_ospf_authentication_8443.go.
				"authentication-type": unmodeledOSPFAuthTypeLeaf(),
				"cost":                {desc: "Interface cost", args: 1, valueType: ValueInteger, placeholder: "<cost>", validator: ValidateInteger(1, 65535), children: nil},
				"hello-interval":      {desc: "Hello interval (seconds)", args: 1, valueType: ValueInteger, placeholder: "<seconds>", validator: ValidateInteger(1, 65535), children: nil},
				"dead-interval":       {desc: "Dead interval (seconds)", args: 1, valueType: ValueInteger, placeholder: "<seconds>", validator: ValidateInteger(1, 65535), children: nil},
				"retransmit-interval": {desc: "Retransmit interval (seconds)", args: 1, valueType: ValueInteger, placeholder: "<seconds>", validator: ValidateInteger(1, 65535), children: nil},
				"priority":            {desc: "Router priority for DR election", args: 1, valueType: ValueInteger, placeholder: "<priority>", validator: ValidateInteger(0, 255), children: nil},
				// #8443: closed-world. The child keyword IS the algorithm selector
				// (compiler_protocols.go assigns AuthType only from a matched
				// `md5` / `simple-password`), so an unmatched keyword here does
				// not misconfigure authentication — it removes it, silently.
				"authentication": {desc: "Authentication", closedWorld: true, children: map[string]*schemaNode{
					"md5": {desc: "MD5 authentication", args: 1, placeholder: "<key-id>", children: map[string]*schemaNode{
						"key": {desc: "Authentication key", args: 1, placeholder: "<key>", children: nil},
					}},
					"simple-password": {desc: "Simple password", args: 1, placeholder: "<password>", children: nil},
				}},
				"bfd-liveness-detection": {desc: "BFD liveness detection", children: map[string]*schemaNode{
					"minimum-interval": {desc: "Minimum interval (milliseconds)", args: 1, valueType: ValueInteger, placeholder: "<milliseconds>", validator: ValidateInteger(10, 60000), children: nil},
					"multiplier":       {desc: "Multiplier", args: 1, valueType: ValueInteger, placeholder: "<multiplier>", validator: ValidateInteger(2, 255), children: nil},
				}},
			}},
			"area-type": {desc: "Area type", children: map[string]*schemaNode{
				"stub": {desc: "Stub area", children: map[string]*schemaNode{
					"no-summaries": {desc: "No summaries", children: nil},
				}},
				"nssa": {desc: "NSSA area", children: map[string]*schemaNode{
					"no-summaries": {desc: "No summaries", children: nil},
				}},
			}},
			"virtual-link": {desc: "Virtual link", args: 1, placeholder: "<router-id>", keyValidator: ValidateOSPFVirtualLinkNeighbor, children: map[string]*schemaNode{
				"transit-area": {desc: "Transit area", args: 1, valueType: ValueIPAddress, placeholder: "<area-id>", validator: ValidateOSPFArea, children: nil},
			}},
		}},
	}},
	"ospf3": {desc: "OSPFv3 configuration", children: map[string]*schemaNode{
		"router-id": {desc: "Router ID", args: 1, placeholder: "<address>", children: nil},
		"export":    {desc: "Export policy", args: 1, multi: true, placeholder: "<policy-name>", children: nil},
		"area": {desc: "OSPFv3 area", args: 1, placeholder: "<area-id>", keyValidator: ValidateOSPFArea, children: map[string]*schemaNode{
			"interface": {desc: "Interface", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: map[string]*schemaNode{
				"passive":             {desc: "Passive interface", children: nil},
				"cost":                {desc: "Interface cost", args: 1, valueType: ValueInteger, placeholder: "<cost>", validator: ValidateInteger(1, 65535), children: nil},
				"hello-interval":      {desc: "Hello interval (seconds)", args: 1, valueType: ValueInteger, placeholder: "<seconds>", validator: ValidateInteger(1, 65535), children: nil},
				"dead-interval":       {desc: "Dead interval (seconds)", args: 1, valueType: ValueInteger, placeholder: "<seconds>", validator: ValidateInteger(1, 65535), children: nil},
				"retransmit-interval": {desc: "Retransmit interval (seconds)", args: 1, valueType: ValueInteger, placeholder: "<seconds>", validator: ValidateInteger(1, 65535), children: nil},
				"priority":            {desc: "Router priority for DR election", args: 1, valueType: ValueInteger, placeholder: "<priority>", validator: ValidateInteger(0, 255), children: nil},
				"bfd-liveness-detection": {desc: "BFD liveness detection", children: map[string]*schemaNode{
					"minimum-interval": {desc: "Minimum interval (milliseconds)", args: 1, valueType: ValueInteger, placeholder: "<milliseconds>", validator: ValidateInteger(10, 60000), children: nil},
					"multiplier":       {desc: "Multiplier", args: 1, valueType: ValueInteger, placeholder: "<multiplier>", validator: ValidateInteger(2, 255), children: nil},
				}},
			}},
		}},
	}},
	"bgp": {desc: "BGP configuration", children: map[string]*schemaNode{
		"local-as":         {desc: "Local AS number", args: 1, valueType: ValueInteger, placeholder: "<as-number>", validator: ValidateInteger(1, 4294967295), children: nil},
		"router-id":        {desc: "Router ID", args: 1, placeholder: "<address>", children: nil},
		"cluster-id":       {desc: "Cluster ID", args: 1, valueType: ValueIPAddress, valueDesc: "Route-reflector cluster-id (IPv4 dotted-quad, or 32-bit integer 1..4294967295)", valueExamples: []string{"10.0.0.1", "1"}, validator: ValidateBGPClusterID, placeholder: "<id>", children: nil},
		"graceful-restart": {desc: "Graceful restart", children: nil},
		"log-updown":       {desc: "Log up/down events", children: nil},
		"multipath": {desc: "Multipath", children: map[string]*schemaNode{
			"multiple-as": {desc: "Multiple AS", children: nil},
			"ibgp":        {desc: "Enable iBGP multipath", children: nil},
		}},
		"damping": {desc: "Route damping", children: map[string]*schemaNode{
			"half-life":    {desc: "Half life (minutes)", args: 1, valueType: ValueInteger, placeholder: "<minutes>", validator: ValidateInteger(1, 45), children: nil},
			"reuse":        {desc: "Reuse threshold", args: 1, valueType: ValueInteger, placeholder: "<value>", validator: ValidateInteger(1, 20000), children: nil},
			"suppress":     {desc: "Suppress threshold", args: 1, valueType: ValueInteger, placeholder: "<value>", validator: ValidateInteger(1, 20000), children: nil},
			"max-suppress": {desc: "Max suppress time (minutes)", args: 1, valueType: ValueInteger, placeholder: "<minutes>", validator: ValidateInteger(1, 255), children: nil},
		}},
		"export": {desc: "Export policy", args: 1, multi: true, placeholder: "<policy-name>", children: nil},
		"import": {desc: "Import policy", args: 1, multi: true, placeholder: "<policy-name>", children: nil},
		"group": {desc: "BGP group", args: 1, placeholder: "<group-name>", children: map[string]*schemaNode{
			"peer-as":            {desc: "Peer AS number", args: 1, valueType: ValueInteger, placeholder: "<as-number>", validator: ValidateInteger(1, 4294967295), children: nil},
			"local-as":           {desc: "Local AS number for this peering", args: 1, valueType: ValueInteger, placeholder: "<as-number>", validator: ValidateInteger(1, 4294967295), children: nil},
			"local-address":      {desc: "Local address (BGP update-source)", args: 1, valueType: ValueIPAddress, placeholder: "<address>", validator: ValidateIPAddress, children: nil},
			"hold-time":          {desc: "Hold time (seconds)", args: 1, valueType: ValueInteger, placeholder: "<seconds>", validator: ValidateBGPHoldTime, children: nil},
			"passive":            {desc: "Passive mode (do not initiate connections)", children: nil},
			"description":        {desc: "Description", args: 1, scalar: true, placeholder: "<text>", children: nil},
			"multihop":           {desc: "Multihop TTL", args: 1, valueType: ValueInteger, placeholder: "<ttl>", validator: ValidateInteger(1, 255), children: nil},
			"export":             {desc: "Export policy", args: 1, multi: true, placeholder: "<policy-name>", children: nil},
			"import":             {desc: "Import policy", args: 1, multi: true, placeholder: "<policy-name>", children: nil},
			"authentication-key": {desc: "Authentication key", args: 1, placeholder: "<key>", children: nil},
			"default-originate":  {desc: "Default originate", children: nil},
			"loops":              {desc: "Loops", args: 1, placeholder: "<count>", children: nil},
			"remove-private":     {desc: "Remove private AS", children: nil},
			"family": {desc: "Address family", compoundKey: true, children: map[string]*schemaNode{
				"inet": {desc: "IPv4", children: map[string]*schemaNode{
					"unicast": {desc: "Unicast", children: map[string]*schemaNode{
						"prefix-limit": {desc: "Prefix limit", children: map[string]*schemaNode{
							"maximum": {desc: "Maximum prefixes", args: 1, placeholder: "<count>", children: nil},
						}},
					}},
				}},
				"inet6": {desc: "IPv6", children: map[string]*schemaNode{
					"unicast": {desc: "Unicast", children: map[string]*schemaNode{
						"prefix-limit": {desc: "Prefix limit", children: map[string]*schemaNode{
							"maximum": {desc: "Maximum prefixes", args: 1, placeholder: "<count>", children: nil},
						}},
					}},
				}},
			}},
			"bfd-liveness-detection": {desc: "BFD liveness detection", children: map[string]*schemaNode{
				"minimum-interval": {desc: "Minimum interval (milliseconds)", args: 1, valueType: ValueInteger, placeholder: "<milliseconds>", validator: ValidateInteger(10, 60000), children: nil},
				"multiplier":       {desc: "Multiplier", args: 1, valueType: ValueInteger, placeholder: "<multiplier>", validator: ValidateInteger(2, 255), children: nil},
			}},
			"neighbor": {desc: "BGP neighbor", args: 1, placeholder: "<address>", children: map[string]*schemaNode{
				"description":            {desc: "Description", args: 1, scalar: true, placeholder: "<text>", children: nil},
				"peer-as":                {desc: "Peer AS number", args: 1, valueType: ValueInteger, placeholder: "<as-number>", validator: ValidateInteger(1, 4294967295), children: nil},
				"local-as":               {desc: "Local AS number for this peering", args: 1, valueType: ValueInteger, placeholder: "<as-number>", validator: ValidateInteger(1, 4294967295), children: nil},
				"local-address":          {desc: "Local address (BGP update-source)", args: 1, valueType: ValueIPAddress, placeholder: "<address>", validator: ValidateIPAddress, children: nil},
				"hold-time":              {desc: "Hold time (seconds)", args: 1, valueType: ValueInteger, placeholder: "<seconds>", validator: ValidateBGPHoldTime, children: nil},
				"passive":                {desc: "Passive mode (do not initiate connections)", children: nil},
				"multihop":               {desc: "Multihop TTL", args: 1, valueType: ValueInteger, placeholder: "<ttl>", validator: ValidateInteger(1, 255), children: nil},
				"export":                 {desc: "Export policy", args: 1, multi: true, placeholder: "<policy-name>", children: nil},
				"import":                 {desc: "Import policy", args: 1, multi: true, placeholder: "<policy-name>", children: nil},
				"authentication-key":     {desc: "Authentication key", args: 1, placeholder: "<key>", children: nil},
				"route-reflector-client": {desc: "Route reflector client", children: nil},
				"default-originate":      {desc: "Default originate", children: nil},
				"loops":                  {desc: "Loops", args: 1, placeholder: "<count>", children: nil},
				"remove-private":         {desc: "Remove private AS", children: nil},
				"family": {desc: "Address family", compoundKey: true, children: map[string]*schemaNode{
					"inet": {desc: "IPv4", children: map[string]*schemaNode{
						"unicast": {desc: "Unicast", children: map[string]*schemaNode{
							"prefix-limit": {desc: "Prefix limit", children: map[string]*schemaNode{
								"maximum": {desc: "Maximum prefixes", args: 1, placeholder: "<count>", children: nil},
							}},
						}},
					}},
					"inet6": {desc: "IPv6", children: map[string]*schemaNode{
						"unicast": {desc: "Unicast", children: map[string]*schemaNode{
							"prefix-limit": {desc: "Prefix limit", children: map[string]*schemaNode{
								"maximum": {desc: "Maximum prefixes", args: 1, placeholder: "<count>", children: nil},
							}},
						}},
					}},
				}},
				"bfd-liveness-detection": {desc: "BFD liveness detection", children: map[string]*schemaNode{
					"minimum-interval": {desc: "Minimum interval (milliseconds)", args: 1, valueType: ValueInteger, placeholder: "<milliseconds>", validator: ValidateInteger(10, 60000), children: nil},
					"multiplier":       {desc: "Multiplier", args: 1, valueType: ValueInteger, placeholder: "<multiplier>", validator: ValidateInteger(2, 255), children: nil},
				}},
			}},
		}},
	}},
	"rip": {desc: "RIP configuration", children: map[string]*schemaNode{
		// #9151: `group` is a CONTAINER to the compiler and was a LEAF here.
		// compiler_protocols.go's `case "group"` iterates child.Children and
		// reads `neighbor` (-> RIP.Interfaces) and `export` (-> Redistribute),
		// but this node declared `children: nil`, so the closed-world walk had
		// nothing to descend into and nothing to reject. The consequence was
		// operator-reachable: `set protocols rip group g1 authentication-key
		// secret1` committed clean and lost BOTH the group content and the
		// sibling authentication-key -- a RIP auth key, in the subsystem where
		// a dropped authentication-type renders `mode text` (#9105).
		//
		// Both children are multi-value: the compiler reads them through
		// firewallMatchValues, which takes Keys[1:] AND child nodes, so a
		// bracket list `export [ a b ]` is not truncated to its first entry
		// (#3904). Declaring them `multi: true` keeps the schema's account of
		// the leaf and the compiler's read of it in agreement.
		// #9151 (second half): CLOSED-WORLD. Declaring the two children was
		// necessary and NOT sufficient -- the container stayed open-world, so
		// an UNDECLARED trailing statement was still accepted and silently
		// discarded:
		//
		//	set protocols rip group g1 authentication-key secret1
		//	  schema gate = ACCEPT   compile = nil   ifaces=[] redist=[] authKey=""
		//
		// which is the #9148 conjunction: a flat run is accepted iff the
		// container is OPEN-WORLD and the leaf it starts at is UNTYPED. Closing
		// the container breaks the conjunction here.
		//
		// SAFE TO ARM AT THIS NODE, and that is a measured claim rather than a
		// general one. `closedWorld` INHERITS, so arming it on a container with
		// a deep grammar beneath closes all of it -- that is what happened on
		// #9017, where arming it at `firewall family` began rejecting
		// `from source-prefix-list trusted`, valid shipped configuration. Here
		// the subtree is exactly ONE level: both children are leaves with
		// `children: nil`, so inheritance has nowhere to spread. The matrix in
		// TestRipGroupRefusesUndeclaredStatements9151 is what holds that true.
		"group": {desc: "Group", args: 1, placeholder: "<group-name>", closedWorld: true, children: map[string]*schemaNode{
			"neighbor": {desc: "Neighbor interface in this group", args: 1, multi: true,
				valueHint: ValueHintInterfaceName, placeholder: "<interface-name>",
				valueType: ValueInterfaceName, valueDesc: "interface name (ge-0/0/0, reth0.50, st0.1)",
				validator: ValidateRIPNeighborInterface, children: nil},
			"export": {desc: "Protocols redistributed into this group", args: 1, multi: true,
				placeholder: "<protocol>", children: nil},
		}},
		// multi (#3904): `neighbor`/`passive-interface`/`redistribute
		// [ a b ]` bracket lists collapse onto the leaf's Keys[1:] instead
		// of stranding every entry past the first as a child node. The
		// compiler (compiler_protocols.go RIP block) reads every value via
		// firewallMatchValues; the pre-#3904 Keys[1]-only read truncated to
		// the first entry.
		"neighbor":           {desc: "Neighbor", args: 1, multi: true, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: nil},
		"passive-interface":  {desc: "Passive interface", args: 1, multi: true, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: nil},
		"redistribute":       {desc: "Redistribute", args: 1, multi: true, placeholder: "<protocol>", children: nil},
		"authentication-key": {desc: "Authentication key", args: 1, placeholder: "<key>", children: nil},
		"authentication-type": {desc: "Authentication type", args: 1, placeholder: "<type>",
			valueType: ValueEnumOf, valueDesc: "authentication type",
			valueExamples: AuthTypeSpellings(), validator: ValidateAuthType, children: nil},
	}},
	"isis": {desc: "IS-IS configuration", children: map[string]*schemaNode{
		"net": {desc: "NET address", args: 1, valueType: ValueIdentifier, placeholder: "<net-address>", validator: ValidateISISNET, children: nil},
		// #8446: BOTH spell the same concept and both compile into
		// ISISConfig.Level. Typed so a non-canonical value (notably
		// `level-2-only`, the spelling this product's OWN renderer
		// emits) is rejected at commit instead of silently widening
		// the router to level-1-2 via the renderer's missing default.
		"level": {desc: "IS-IS level (alias of is-type)", args: 1, placeholder: "<level>",
			valueType: ValueEnumOf, valueDesc: "IS-IS level",
			valueExamples: ISISLevelSpellings(), validator: ValidateISISLevel, children: nil},
		"is-type": {desc: "IS type (alias of level)", args: 1, placeholder: "<type>",
			valueType: ValueEnumOf, valueDesc: "IS-IS level",
			valueExamples: ISISLevelSpellings(), validator: ValidateISISLevel, children: nil},
		"export": {desc: "Export policy", args: 1, multi: true, placeholder: "<policy-name>", children: nil},
		"interface": {desc: "Interface", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: map[string]*schemaNode{
			// #8450: the PER-INTERFACE circuit type. Typed so a value the FRR
			// renderer cannot express is rejected at commit instead of leaving
			// the interface silently at the router-wide is-type. Wider spelling
			// domain than the router-wide leaf: Junos writes a bare digit here.
			"level": {desc: "IS-IS circuit type for this interface", args: 1, placeholder: "<level>",
				valueType: ValueEnumOf, valueDesc: "IS-IS interface level",
				valueExamples: ISISCircuitTypeSpellings(), validator: ValidateISISCircuitType, children: nil},
			"passive":            {desc: "Passive interface", children: nil},
			"metric":             {desc: "Metric", args: 1, placeholder: "<value>", children: nil},
			"authentication-key": {desc: "Authentication key", args: 1, placeholder: "<key>", children: nil},
			"authentication-type": {desc: "Authentication type", args: 1, placeholder: "<type>",
				valueType: ValueEnumOf, valueDesc: "authentication type",
				valueExamples: AuthTypeSpellings(), validator: ValidateAuthType, children: nil},
			"bfd-liveness-detection": {desc: "BFD liveness detection", children: map[string]*schemaNode{
				"minimum-interval": {desc: "Minimum interval (milliseconds)", args: 1, valueType: ValueInteger, placeholder: "<milliseconds>", validator: ValidateInteger(10, 60000), children: nil},
				"multiplier":       {desc: "Multiplier", args: 1, valueType: ValueInteger, placeholder: "<multiplier>", validator: ValidateInteger(2, 255), children: nil},
			}},
		}},
		"authentication-key": {desc: "Authentication key", args: 1, placeholder: "<key>", children: nil},
		"authentication-type": {desc: "Authentication type", args: 1, placeholder: "<type>",
			valueType: ValueEnumOf, valueDesc: "authentication type",
			valueExamples: AuthTypeSpellings(), validator: ValidateAuthType, children: nil},
		"wide-metrics-only": {desc: "Wide metrics only", children: nil},
		"overload":          {desc: "Overload", children: nil},
	}},
	"router-advertisement": {desc: "Router advertisement", children: map[string]*schemaNode{
		"interface": {desc: "Interface", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: map[string]*schemaNode{
			// #2008 (LOW, RA schema-only): max/min-advertisement-interval,
			// default-lifetime, link-mtu, managed-configuration,
			// other-stateful-configuration and dns-server-address are all
			// compiled (compiler_protocols.go compileRouterAdvertisement)
			// and honored by the RA sender (pkg/ra), but the schema only
			// declared prefix/preference/nat-prefix/nat64prefix — the rest
			// fell through with no completion or commit-time validation. The
			// second-denominated leaves silently compile to 0 on garbage
			// (Atoi error path), so type them as positive integers.
			"managed-configuration":        {desc: "Set the Managed Address Configuration (M) flag", children: nil},
			"other-stateful-configuration": {desc: "Set the Other Stateful Configuration (O) flag", children: nil},
			// #4525: RFC 4861 §6.2.1 bounds. MaxRtrAdvInterval MUST be in
			// [4, 1800] seconds; MinRtrAdvInterval MUST be >= 3 seconds and
			// <= 0.75 * MaxRtrAdvInterval. The old ValidateIntegerMin(1) let
			// max-advertisement-interval 1|2 commit — the RA sender then drew
			// a 0-second periodic delay (minI derives to maxI/3 = 0) and
			// hot-looped sendRA (RA/ND flood + CPU spin). The per-leaf ranges
			// here reject the safety-critical low end at commit; the
			// cross-field min <= 0.75*max relation is enforced in the compiler
			// (crossCheckRAIntervals) where both values are in scope. 1350 is
			// the RFC ceiling for min (0.75 * 1800). The runtime floor in
			// pkg/ra randomAdvInterval is the belt if a stale config bypasses
			// this strict gate via the tolerant load / HA peer-sync path.
			"max-advertisement-interval": {desc: "Maximum time between unsolicited RAs (seconds)", args: 1, placeholder: "<seconds>",
				valueType: ValueInteger, valueDesc: "max RA interval in seconds (RFC 4861 §6.2.1: 4..1800)",
				valueExamples: []string{"600", "1800"}, validator: ValidateInteger(4, 1800), children: nil},
			"min-advertisement-interval": {desc: "Minimum time between unsolicited RAs (seconds)", args: 1, placeholder: "<seconds>",
				valueType: ValueInteger, valueDesc: "min RA interval in seconds (RFC 4861 §6.2.1: 3..1350, and <= 0.75*max)",
				valueExamples: []string{"200", "600"}, validator: ValidateInteger(3, 1350), children: nil},
			// #3895: bound the router lifetime at the RFC 4861 §4.2 16-bit
			// field maximum. A larger value silently wraps in the RA sender's
			// ndp uint16(lifetime) (65536 -> 0 = "not a default router"), so
			// hosts drop their default route.
			// #4119: the floor is 0, not 1, because RFC 4861 §6.2.1 defines
			// Router Lifetime 0 as "this router is NOT a default router" — a
			// valid, deliberate advertisement (advertise prefixes/PREF64 but do
			// not enter host default-router lists). The compiler records an
			// explicit 0 via DefaultLifetimeSet so the sender does not coerce
			// it back to 1800.
			"default-lifetime": {desc: "Router lifetime advertised to hosts (seconds; 0 = not a default router)", args: 1, placeholder: "<seconds>",
				valueType: ValueInteger, valueDesc: "router lifetime in seconds (RFC 4861 §4.2 16-bit; 0 = not a default router)",
				valueExamples: []string{"0", "1800", "9000"}, validator: ValidateInteger(0, RARouterMaxLifetimeSeconds), children: nil},
			// #2497: link-mtu is advertised verbatim via ndp.NewMTU. RFC 8200
			// §5 sets the IPv6 minimum link MTU at 1280 bytes; a smaller value
			// (1-1279) committed today reaches the wire and blackholes hosts
			// that honor it. Floor the leaf at the IPv6 minimum.
			"link-mtu": {desc: "Link MTU option advertised to hosts", args: 1, placeholder: "<mtu>",
				valueType: ValueInteger, valueDesc: "advertised link MTU (RFC 8200 §5 minimum 1280)",
				valueExamples: []string{"1280", "1500"}, validator: ValidateIntegerMin(1280), children: nil},
			// #4307 (I-2): the RFC 4861 §4.2 Reachable Time / Retrans Timer
			// header fields. Both are 32-bit millisecond values the sender
			// emits verbatim on the RA; before this leaf existed they were
			// silently dropped and went on the wire as 0 ("unspecified"), so
			// hosts could not be tuned. 0 keeps the unspecified default.
			"reachable-time": {desc: "Reachable Time advertised to hosts (milliseconds; 0 = unspecified)", args: 1, placeholder: "<milliseconds>",
				valueType: ValueInteger, valueDesc: "RFC 4861 §4.2 Reachable Time in milliseconds (0 = unspecified)",
				valueExamples: []string{"0", "30000"}, validator: ValidateInteger(0, RAReachableRetransMaxMillis), children: nil},
			"retransmit-timer": {desc: "Retrans Timer advertised to hosts (milliseconds; 0 = unspecified)", args: 1, placeholder: "<milliseconds>",
				valueType: ValueInteger, valueDesc: "RFC 4861 §4.2 Retrans Timer in milliseconds (0 = unspecified)",
				valueExamples: []string{"0", "1000"}, validator: ValidateInteger(0, RAReachableRetransMaxMillis), children: nil},
			// #2497: each address is appended to an RFC 8106 RecursiveDNSServer
			// (RDNSS) option, which is IPv6-only. The runtime skips an
			// unparseable string but does NOT family-gate, so a bare IPv4
			// literal was advertised on the wire. Validate as a bare IPv6
			// literal at commit.
			"dns-server-address": {desc: "RDNSS DNS server address advertised to hosts", args: 1, multi: true, placeholder: "<address>",
				valueType: ValueIPAddress, valueDesc: "RDNSS server (IPv6 literal, RFC 8106)",
				valueExamples: []string{"2001:db8::53"}, validator: ValidateIPv6Address, children: nil},
			// #2497: a preference typo (case drift, "mdeium") falls through the
			// RA sender's switch default and silently advertises Medium,
			// perturbing host default-router selection on a multi-router LAN.
			// Constrain to the three RFC 4191 router-selection preferences.
			"preference": {desc: "Default router preference (high|medium|low)", args: 1, placeholder: "<preference>",
				valueType: ValueEnumOf, valueDesc: "router selection preference",
				valueExamples: []string{"high", "medium", "low"}, validator: ValidateEnum([]string{"high", "medium", "low"}), children: nil},
			// #2497: the prefix value is the named-instance identity arg. A
			// typo'd prefix committed today; the RA sender's netip.ParsePrefix
			// error path logs and skips it, so hosts on the link get no PIO and
			// SLAAC silently breaks. Validate it as an IPv6 CIDR at commit.
			"prefix": {desc: "Advertised on-link prefix", args: 1, placeholder: "<prefix>",
				keyValueType: ValueCIDR, keyValueDesc: "IPv6 prefix with length (e.g. 2001:db8::/64)",
				keyValueExamples: []string{"2001:db8::/64"}, keyValidator: ValidateIPv6CIDR,
				children: map[string]*schemaNode{ // prefix <prefix/len>
					"on-link":       {desc: "Set the on-link (L) flag (default)", children: nil},
					"autonomous":    {desc: "Set the autonomous (A) flag (default)", children: nil},
					"no-onlink":     {desc: "Clear the on-link (L) flag", children: nil},
					"no-autonomous": {desc: "Clear the autonomous (A) flag", children: nil},
					// Prefix lifetimes compile with a bare strconv.Atoi
					// (compiler_protocols.go) and treat 0 as "use the SLAAC
					// default" (types_routing.go RAPrefix; pkg/ra sender clamps
					// <=0 to defaultValid/PreferredLifetime). Type them as
					// non-negative integers so the gate rejects garbage (e.g.
					// `valid-lifetime abc`, which previously stayed at 0 and
					// silently fell back to the default) while still accepting
					// an explicit 0.
					// #3895: bound at the RFC 4861 §4.6.2 32-bit PIO lifetime
					// field maximum (0xffffffff = infinity). A larger value
					// silently truncates in the RA sender's ndp uint32(lifetime).
					"valid-lifetime": {desc: "Prefix valid lifetime in seconds (0 = SLAAC default)", args: 1, placeholder: "<seconds>",
						valueType: ValueInteger, valueDesc: "prefix valid lifetime in seconds (RFC 4861 §4.6.2 32-bit)",
						valueExamples: []string{"0", "86400", "2592000"}, validator: ValidateInteger(0, raPrefixMaxLifetimeSeconds), children: nil},
					"preferred-lifetime": {desc: "Prefix preferred lifetime in seconds (0 = SLAAC default)", args: 1, placeholder: "<seconds>",
						valueType: ValueInteger, valueDesc: "prefix preferred lifetime in seconds (RFC 4861 §4.6.2 32-bit)",
						valueExamples: []string{"0", "604800", "86400"}, validator: ValidateInteger(0, raPrefixMaxLifetimeSeconds), children: nil},
				}},
			// #2497: nat-prefix/nat64prefix feed an ndp.PREF64 option whose
			// 3-bit PLC wire field can only encode the RFC 8781 §4 length set
			// {32,40,48,56,64,96}. An out-of-set length committed today parses
			// in netip.ParsePrefix, so the runtime accepts it and mis-encodes
			// or omits the option. Validate as a PREF64-legal IPv6 CIDR at
			// commit, and type the lifetime child as a non-negative integer so
			// garbage no longer silently zeroes (which defaults to the router
			// lifetime).
			"nat-prefix": {desc: "NAT prefix", args: 1, placeholder: "<prefix>",
				keyValueType: ValueCIDR, keyValueDesc: "NAT64 prefix (RFC 8781 length /32 /40 /48 /56 /64 /96)",
				keyValueExamples: []string{"64:ff9b::/96"}, keyValidator: ValidatePREF64CIDR,
				children: map[string]*schemaNode{
					// #3895: bound at the RFC 8781 §4 13-bit scaled-by-8 field
					// maximum (8191*8 = 65528s). A larger value makes
					// ndp.PREF64.marshal fail, aborting the entire RA.
					"lifetime": {desc: "Lifetime", args: 1, placeholder: "<seconds>",
						valueType: ValueInteger, valueDesc: "PREF64 lifetime in seconds (0 = router lifetime; RFC 8781 max 65528)",
						valueExamples: []string{"0", "1800"}, validator: ValidateInteger(0, raPREF64MaxLifetimeSeconds), children: nil},
				}},
			"nat64prefix": {desc: "NAT64 prefix", args: 1, placeholder: "<prefix>",
				keyValueType: ValueCIDR, keyValueDesc: "NAT64 prefix (RFC 8781 length /32 /40 /48 /56 /64 /96)",
				keyValueExamples: []string{"64:ff9b::/96"}, keyValidator: ValidatePREF64CIDR,
				children: map[string]*schemaNode{
					// #3895: bound at the RFC 8781 §4 13-bit scaled-by-8 field
					// maximum (8191*8 = 65528s). A larger value makes
					// ndp.PREF64.marshal fail, aborting the entire RA.
					"lifetime": {desc: "Lifetime", args: 1, placeholder: "<seconds>",
						valueType: ValueInteger, valueDesc: "PREF64 lifetime in seconds (0 = router lifetime; RFC 8781 max 65528)",
						valueExamples: []string{"0", "1800"}, validator: ValidateInteger(0, raPREF64MaxLifetimeSeconds), children: nil},
				}},
		}},
	}},
	"lldp": {desc: "LLDP configuration", children: map[string]*schemaNode{
		"interface": {desc: "Interface", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: map[string]*schemaNode{
			"disable": {desc: "Disable LLDP", children: nil},
		}},
		// #4596: bound to the IEEE 802.1AB LLDP-MIB ranges Junos also
		// enforces — lldpMessageTxInterval (5..32768s) and
		// lldpMessageTxHoldMultiplier (2..10). Their product feeds the LLDP
		// TTL TLV; encodeTTL additionally clamps to 65535 so even the
		// in-range extreme (32768 × 10) cannot wrap the uint16 wire value.
		"transmit-interval": {desc: "Transmit interval", args: 1, placeholder: "<seconds>",
			valueType: ValueInteger, valueDesc: "LLDP transmit interval in seconds (IEEE 802.1AB msgTxInterval, 5..32768)",
			validator: ValidateInteger(5, 32768), children: nil},
		"hold-multiplier": {desc: "Hold multiplier", args: 1, placeholder: "<multiplier>",
			valueType: ValueInteger, valueDesc: "LLDP TTL hold multiplier (IEEE 802.1AB msgTxHold, 2..10)",
			validator: ValidateInteger(2, 10), children: nil},
		"disable": {desc: "Disable LLDP", children: nil},
	}},
}}

var schemaForwardingOptions = &schemaNode{desc: "Packet forwarding options", children: map[string]*schemaNode{
	// #2008 H13 Stage 1: typed presence-flag leaf. Previously this was
	// accepted only via the no-schema-match fall-through and silently
	// dropped. Stage 1 gives it a schema (completion + validation) and a
	// compiler field; the idle-yield dataplane runtime (Stage 2) is
	// lab-gated and emits an accepted-but-unenforced commit warning.
	"allow-dataplane-sleep": {desc: "Allow the dataplane to idle (accepted; idle-yield not yet enforced)", children: nil},
	"family": {desc: "Protocol family forwarding options", compoundKey: true, children: map[string]*schemaNode{
		"inet6": {desc: "IPv6 forwarding options", children: map[string]*schemaNode{
			"mode": {desc: "IPv6 forwarding mode (flow-based|packet-based; packet-based is accepted-only — the dataplane is flow-based, advisory at commit)", args: 1, placeholder: "<mode>", children: nil},
		}},
	}},
	"sampling": {desc: "Traffic sampling for flow export", children: map[string]*schemaNode{
		"instance": {desc: "Sampling instance", args: 1, placeholder: "<instance-name>", children: map[string]*schemaNode{
			// #1979 Layer B (Tier 2): `input rate <n>` feeds the Rust u32
			// SamplingRate wire field (buildFlowExportSnapshot, Layer A caps
			// >u32max). Q3 DECISION: bound is [0, u32max] — EXACT Layer-A
			// agreement. Accept 0 (the documented `0 = sample all` sentinel,
			// types_system.go; Layer A normalizes rate<=0 -> 1), reject only
			// the decode-aborting >u32max.
			"input": {desc: "Sampling input properties (rate)", children: map[string]*schemaNode{
				"rate": {desc: "Sample 1-in-N packets (0 = sample all)", args: 1, placeholder: "<rate>",
					valueType: ValueInteger, valueDesc: "Sampling rate 1-in-N (0..4294967295; 0 = sample all)",
					valueExamples: []string{"1", "1000"}, validator: ValidateInteger(0, maxWireU32), children: nil},
			}},
			"family": {desc: "Address family to sample", compoundKey: true, children: map[string]*schemaNode{
				"inet": {desc: "IPv4 flow sampling", children: map[string]*schemaNode{
					"output": {desc: "Sampling output configuration", children: map[string]*schemaNode{
						"flow-server": samplingFlowServerNode(),
						// Per-output default source-address: the standard
						// Junos hierarchy (`output { source-address X;
						// flow-server Y { ... } }`), sibling of flow-server.
						// Every flow-server under this output inherits it
						// unless it sets its own nested source-address
						// (compiler_services.go compileSamplingFamily, #2605).
						"source-address": {desc: "Default source address for exported flows", args: 1, placeholder: "<address>", children: nil},
						"inline-jflow":   {desc: "Inline flow export (jflow)", children: nil},
					}},
				}},
				"inet6": {desc: "IPv6 flow sampling", children: map[string]*schemaNode{
					"output": {desc: "Sampling output configuration", children: map[string]*schemaNode{
						"flow-server": samplingFlowServerNode(),
						// Per-output default source-address: the standard
						// Junos hierarchy (`output { source-address X;
						// flow-server Y { ... } }`), sibling of flow-server.
						// Every flow-server under this output inherits it
						// unless it sets its own nested source-address
						// (compiler_services.go compileSamplingFamily, #2605).
						"source-address": {desc: "Default source address for exported flows", args: 1, placeholder: "<address>", children: nil},
						"inline-jflow":   {desc: "Inline flow export (jflow)", children: nil},
					}},
				}},
			}},
		}},
	}},
	"port-mirroring": {desc: "Port mirroring", children: map[string]*schemaNode{
		"instance": {desc: "Port mirroring instance", args: 1, placeholder: "<instance-name>", children: map[string]*schemaNode{
			"input": {desc: "Mirrored input traffic (rate, ingress interfaces)", children: map[string]*schemaNode{
				"ingress": {desc: "Interfaces to mirror at ingress", children: nil},
			}},
			"output": {desc: "Mirror destination interface", children: nil},
		}},
	}},
	"dhcp-relay": {desc: "DHCP relay", children: map[string]*schemaNode{
		// server-group is a named container whose children are the
		// free-form server address leaves (same modeling as the
		// sampling flow-server node above).
		"server-group": {desc: "DHCP server group", args: 1, placeholder: "<name>", children: nil},
		"group": {desc: "DHCP relay group", args: 1, placeholder: "<name>", children: map[string]*schemaNode{
			"active-server-group": {desc: "Active server group", args: 1, placeholder: "<server-group>", children: nil},
			"interface":           {desc: "Interface to relay on", args: 1, multi: true, placeholder: "<interface>", children: nil},
			"overrides": {desc: "Relay overrides", children: map[string]*schemaNode{
				"always-broadcast": {desc: "Always broadcast replies to clients", children: nil},
				// #4309 (fable-review-167 I-4): maximum-hop-count is enforced
				// (the relay's RFC 1542 §4.1.1 loop-protection hop limit,
				// previously hardcoded at 16). forward-only and
				// relay-agent-option are accepted-only (a commit-time advisory
				// notes each matches the relay's existing default behavior).
				"maximum-hop-count": {desc: "Drop relayed requests whose hop count reaches this limit", args: 1, placeholder: "<count>",
					valueType: ValueInteger, valueDesc: "relay hop limit (RFC 1542 §4.1.1; 1..16)",
					valueExamples: []string{"4", "16"}, validator: ValidateInteger(1, 16), children: nil},
				// #5670: per-interface ingress rate limit (packets/second). ENFORCED
				// — a token bucket bounds the client-facing admit rate so an
				// untrusted segment cannot CPU-exhaust the relay or amplify a flood
				// into the upstream servers. Unset = default 100 pps; set high to
				// effectively disable.
				"maximum-packet-rate": {desc: "Rate-limit client-facing relay requests (packets/second per interface)", args: 1, placeholder: "<pps>",
					valueType: ValueInteger, valueDesc: "relay ingress rate limit in pps (default 100)",
					valueExamples: []string{"100", "500"}, validator: ValidateInteger(1, 1000000), children: nil},
				"forward-only":       {desc: "Forward without retaining relay state (accepted-only; matches default — #4309)", children: nil},
				"relay-agent-option": {desc: "Insert Option 82 relay agent information (accepted-only; always inserted — #4309)", children: nil},
				// #5414: trust-option-82 marks the group's interfaces as
				// TRUSTED relay uplinks (RFC 3046 §2.1 anti-spoofing). ENFORCED.
				// Default (unset) = untrusted client-facing: a client-forged
				// nonzero giaddr + Option 82 is overwritten, not preserved.
				"trust-option-82": {desc: "Trust a downstream relay's giaddr + Option 82 on this uplink (RFC 3046 §2.1; default untrusted overwrites — #5414)", children: nil},
			}},
		}},
	}},
}}

var schemaBridgeDomains = &schemaNode{desc: "Bridge domain configuration", wildcard: &schemaNode{desc: "Bridge domain name", keyValidator: ValidateBridgeDomainName, children: map[string]*schemaNode{
	"vlan-id-list":      {args: 1, multi: true, desc: "VLAN IDs in this bridge domain", children: nil},
	"routing-interface": {args: 1, desc: "IRB routing interface (e.g. irb.0)", children: nil},
	"domain-type":       {args: 1, desc: "Bridge domain type", children: nil},
}}}

// schemaRoutingInstanceProtocols is the `routing-instances <name> protocols`
// grammar (#9351). Every subtree here is the GLOBAL node, SHARED BY POINTER —
// it is deliberately not a re-declaration.
//
// The two used to be separate literals, and the per-instance copy had drifted
// to a strict subset: 68 schema paths against the global node's 169, with
// `rip` missing outright. That is not a completion gap. SetPath resolves a
// flat-set statement's packed tail THROUGH THE SCHEMA (#8787 / #2419), so an
// undeclared keyword terminates the walk and the remaining tokens are PACKED
// onto the last node's key, where no compiler reads them. MEASURED before this
// change, on 122 enumerated global `protocols` leaf paths, the flat-set AST
// shape differed inside a routing instance on 53 of them. Two of the
// resulting losses, with the identical global spelling as the control:
//
//	set protocols bgp group g1 neighbor 10.0.0.1 local-address 10.0.0.2
//	  -> neighbor addr="10.0.0.1" local-address="10.0.0.2"        CORRECT
//	set routing-instances V protocols bgp group g1 neighbor 10.0.0.1 local-address 10.0.0.2
//	  -> [neighbor 10.0.0.1 local-address 10.0.0.2] packed
//	  -> neighbor addr="10.0.0.1" local-address=""                DROPPED
//
//	set routing-instances V protocols rip group r1 neighbor ge-0/0/0.0
//	  -> [rip group r1 neighbor ge-0/0/0.0] packed under `protocols`
//	  -> ri.RIP = &RIPConfig{} with Interfaces=[]     WHOLE BLOCK DROPPED
//
// The configured case and the never-configured case are byte-identical, on a
// clean commit with no error and no warning — the fail-OPEN direction. The
// BRACED spelling of both lines compiled correctly the whole time, which is
// why nothing tripped over it: the packing is a property of the flat-set
// walk, and every fixture in the tree that configures a per-instance protocol
// writes braces.
//
// Sharing rather than re-declaring is what removes the class instead of the
// instance. It is also an established shape here: init() already wires
// `groups <name>` to every top-level node by pointer, so the schema is
// already a DAG. Before the swap the per-instance copy was measured to be an
// attribute-identical STRICT SUBSET of the global node — 0 paths present only
// per-instance and 0 attribute differences at the 68 shared paths — so the
// swap loses nothing.
//
// The member set is the COMPILER's, not a judgement call: exactly the five
// fields compileRoutingInstances copies out of the compileProtocols result.
// `lldp` and `router-advertisement` are compiled by compileProtocols and then
// NOT copied into the instance, so declaring them here would offer completion
// for a keyword that is silently discarded. TestRoutingInstanceProtocolsShareTheGlobalGrammar9351
// derives that boundary from the assignment block itself and fails if either
// side moves.
var schemaRoutingInstanceProtocols = &schemaNode{desc: "Protocols configuration", children: map[string]*schemaNode{
	"ospf":  schemaProtocols.children["ospf"],
	"ospf3": schemaProtocols.children["ospf3"],
	"bgp":   schemaProtocols.children["bgp"],
	"rip":   schemaProtocols.children["rip"],
	"isis":  schemaProtocols.children["isis"],
}}

var schemaRoutingInstances = &schemaNode{desc: "Routing instance configuration", // #9323: the admissible children of `routing-instances <name>` are gated by
	// validateRoutingInstanceChildTokensAST (compiler_routing_children_9323.go),
	// NOT by `closedWorld: true` on this wildcard.
	//
	// That was the first attempt and it is wrong for the same reason it was wrong
	// at the config root and at `firewall family` (#9017): the flag INHERITS down
	// every level. MEASURED with it armed — `go test ./...` rejected zero configs,
	// which reads like a clean board, and a targeted over-reach probe then found
	// `routing-instances <n> protocols bgp group <g> neighbor <ip> peer-as <n>`
	// REJECTED, because the per-instance `protocols bgp group` subtree does not
	// declare `neighbor` while the shared compiler (compileProtocols) handles it
	// fully. BGP neighbours inside a VRF are ordinary configuration and no fixture
	// in the tree writes one, so the suite was blind to it. Arming here exposes
	// every incompleteness in the per-instance protocol grammar; the gate below
	// is scoped to this level and inherits nothing.
	wildcard: &schemaNode{desc: "Routing instance name", placeholder: "<instance-name>", children: map[string]*schemaNode{
		// #8787: instance-type and interface ARE declared here, and the rationale
		// that used to sit in this spot -- "NOT listed here -> they become leaf
		// nodes" -- was true when written and stopped being true when packed-tail
		// resolution landed.
		//
		// An undeclared keyword still becomes a leaf in the BRACED spelling, which
		// is what that note observed. But the packed reader resolves a stanza's
		// tail THROUGH THE SCHEMA, so an undeclared keyword there terminates the
		// walk and the whole stanza is dropped. Measured before this change:
		//
		//	routing-instances { ri1 { instance-type forwarding; } }   1 instance, type=forwarding
		//	routing-instances { ri1 instance-type forwarding; }       0 instances
		//	routing-instances { ri1 interface ge-0/0/0.0; }           0 instances
		//
		// Not a lost leaf -- the entire routing instance vanishes, on a commit
		// that reports success. The harmful direction is `forwarding`:
		// InstanceType == "forwarding" is what makes the daemon SKIP VRF creation
		// (daemon_apply_interfaces.go), so a dropped value creates a VRF the
		// operator asked NOT to have and moves interfaces into it.
		//
		// Reachable from a loaded or peer-synced config FILE, not from flat `set`
		// (which builds a chain and compiles correctly) -- so the boot and HA-sync
		// paths, not the CLI.
		//
		// Since #9620 the #8662 normalizer splits a packed instance run by these
		// declarations (normalizeElidedRoutingInstance9620), before group expansion
		// and validation; the compiler reads only the braced shape.
		//
		// `interface` is multi: the compiler reads it with firewallMatchValues,
		// and the #3904 note there records that reading only the first value
		// stranded the remaining ports outside the instance -- a VRF isolation
		// break. Declaring it single-valued would reintroduce that.
		// #9323: DECLARED BEFORE the closed world was armed, because arming it
		// without them is a REGRESSION, and the test suite is blind to that —
		// measured: `go test ./...` with closedWorld armed and these four still
		// undeclared rejects nothing at all, because no fixture writes them. A
		// targeted probe is what found it.
		//
		// All four are admitted by the COMPILER (compileRoutingInstances), and
		// `description` is read into
		// RoutingInstanceConfig.Description, so rejecting it would refuse a value
		// the tree stores. The other three are accepted-and-inert — standard Junos
		// L3VPN keywords the compiler admits and compiles to no field, exactly as
		// #9055 recorded. Their descs say so, so
		// completion offers them with their real status rather than implying
		// support (the `interface-specific` convention in schema_cos.go).
		//
		// Since #9620 these declarations also split a brace-elided instance
		// (normalizeElidedRoutingInstance9620), so the compiler keeps no keyword
		// list of its own to drift from. TestRoutingInstanceSchemaAndCompilerAgree9323
		// binds that every keyword the compiler reads is declared.
		// #9323: MEASURED, not derived. `interface-routes` appears DIRECTLY under a
		// routing instance in the shipped contract — `set routing-instances dmz-vr
		// interface-routes rib-group inet dmz-leak` is the #2226 rib-group
		// reference test's own spelling, in both AST shapes — while the schema
		// declared it only under `routing-options` and
		// the compiler's packed-run keyword list (removed in #9620) did not name it. Neither of those
		// two sources is the admissible set; the corpus is. Enumerating it is what
		// found this (and `apply-macro`, handled as a universal meta keyword in the
		// gate rather than declared here).
		"interface-routes": {desc: "Interface routes (rib-group leaking) for this instance", children: map[string]*schemaNode{
			"rib-group": {desc: "RIB group", children: map[string]*schemaNode{
				"inet":  {desc: "IPv4 RIB group", args: 1, placeholder: "<group-name>", children: nil},
				"inet6": {desc: "IPv6 RIB group", args: 1, placeholder: "<group-name>", children: nil},
			}},
		}},
		"description":         {desc: "Routing instance description", args: 1, placeholder: "<text>", children: nil},
		"vrf-target":          {desc: "VRF route target (accepted; xpf compiles no BGP/MPLS VPN state from it)", args: 1, placeholder: "<target>", children: nil},
		"vrf-table-label":     {desc: "VRF table label (accepted; xpf compiles no BGP/MPLS VPN state from it)", children: nil},
		"route-distinguisher": {desc: "VRF route distinguisher (accepted; xpf compiles no BGP/MPLS VPN state from it)", args: 1, placeholder: "<rd>", children: nil},

		"instance-type": {desc: "Routing instance type", args: 1, placeholder: "<type>", children: nil},
		"interface":     {desc: "Interfaces bound to this routing instance", args: 1, multi: true, placeholder: "<interface>", children: nil},
		"routing-options": {desc: "Routing options", children: map[string]*schemaNode{
			"static": {desc: "Static routes", children: map[string]*schemaNode{
				"route": staticRouteNode(),
			}},
			"rib": {desc: "Routing information base", args: 1, placeholder: "<rib-name>", children: map[string]*schemaNode{
				"static": {desc: "Static routes", children: map[string]*schemaNode{
					"route": staticRouteNode(),
				}},
			}},
			"interface-routes": {desc: "Interface routes", children: map[string]*schemaNode{
				"rib-group": {desc: "RIB group", children: map[string]*schemaNode{
					"inet":  {desc: "IPv4 RIB group", args: 1, placeholder: "<group-name>", children: nil},
					"inet6": {desc: "IPv6 RIB group", args: 1, placeholder: "<group-name>", children: nil},
				}},
			}},
		}},
		// #9351: the per-instance protocol grammar IS the global one — the same
		// compiler reads both. compileRoutingInstances' `case "protocols"` calls
		// compileProtocols on this node and copies OSPF/OSPFv3/BGP/RIP/ISIS out of
		// the result, so two schema declarations of one grammar is drift, and this
		// node used to be the drifted copy.
		"protocols": schemaRoutingInstanceProtocols,
	}}}
