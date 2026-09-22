package appid

import (
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// CatalogEntry is one application's L3/L4 classification rule, carrying the
// numeric app_id that the dataplane stamps on a matching session. One config
// application can expand to multiple entries (e.g. an omitted protocol means
// "TCP or UDP", which yields one entry per protocol) but every expansion shares
// the same AppID and Name.
//
// Port boundaries are inclusive. A zero DstPortLow/DstPortHigh pair (the
// default for a protocol-only application such as ICMP) means "no destination
// port constraint" — the entry matches on protocol alone. SrcPortLow/High of 0
// means "no source-port constraint".
type CatalogEntry struct {
	Name        string
	AppID       uint16
	Protocol    uint8
	DstPortLow  uint16
	DstPortHigh uint16
	SrcPortLow  uint16
	SrcPortHigh uint16
}

// Catalog is the ordered application catalog plus the app_id -> name index. The
// AppNames map is the SAME map shape that pkg/dataplane's compileApplications
// builds (CompileResult.AppNames) and that pkg/appid.ResolveSessionName
// consumes when resolving a session's app_id back to a name. Both are derived
// from CatalogNames in the identical sorted order with IDs assigned from 1, so
// an app_id stamped by the dataplane resolves to the same name the show path
// reports.
type Catalog struct {
	Entries  []CatalogEntry
	AppNames map[uint16]string
}

// BuildCatalog produces the ordered application catalog for a config. The id
// assignment MUST stay in lock-step with pkg/dataplane.compileApplications:
// names come from CatalogNames(cfg, ApplicationIdentification), sorted, with
// app_id assigned sequentially from 1. The id<->name correspondence is kept
// byte-identical to pkg/dataplane/compiler.go's AppNames assignment, which is
// what ResolveSessionName consumes.
//
// id-bump rule (unchanged, #2065): the loop-tail appID++ is SKIPPED only when
// the DESTINATION port fails to parse — compileApplications `continue`s in that
// case, so a dest-port-malformed application does NOT consume an id slot (the
// next good application overwrites the same id). Every other application — a
// reversed range or a bad source-port included — DOES consume its id, matching
// compileApplications which bumps its id in those cases.
//
// AppNames / entry rule (#3725 M04/M07/H03): AppNames[appID]=name and the
// CatalogEntry rows are recorded ONLY for an EMITTABLE application — one whose
// destination range is non-inverted, whose source-port parses, and whose source
// range is non-inverted. Recording the name BEFORE the port parse (the old
// behavior) left AppNames holding a name at an id no CatalogEntry can stamp when
// the malformed app sorted last, so a skewed/stale app_id resolved to the
// malformed name instead of UNKNOWN. compileApplications gates its AppNames the
// same way, so the two maps stay byte-identical (appid_catalog_parity_test.go).
func BuildCatalog(cfg *config.Config) (Catalog, error) {
	cat := Catalog{AppNames: map[uint16]string{}}
	if cfg == nil {
		return cat, nil
	}

	names, err := CatalogNames(cfg, cfg.Services.ApplicationIdentification)
	if err != nil {
		return cat, err
	}

	// #5296: assign a STABLE, name-derived app_id to every catalog name through
	// the shared config.AssignStableAppIDs SSOT. dataplane.compileApplications
	// assigns ids through the SAME helper, so the two AppNames maps stay
	// byte-identical (appid_catalog_parity_test.go). This replaces the legacy
	// sorted 1..N positional counter, whose ids shifted whenever an
	// earlier-sorting name was inserted and then mis-resolved a RETAINED
	// session's frozen app_id against the rebuilt catalog (see StableAppID).
	// The #3438 H4 uint16-overflow fail-closed boundary now lives inside
	// AssignStableAppIDs (a config with >65535 distinct apps is rejected).
	idByName, err := config.AssignStableAppIDs(names)
	if err != nil {
		return cat, err
	}

	userApps := cfg.Applications.Applications
	for _, name := range names {
		appID := idByName[name]
		app, found := config.ResolveApplication(name, userApps)
		if !found {
			// compileApplications hard-errors here; the snapshot builder must
			// not abort the whole apply over one stray name, so skip it and do
			// NOT consume an id slot (compileApplications would have failed the
			// commit before producing AppNames at all, so there is no id to
			// keep in step with).
			continue
		}
		if app == nil {
			// #4865: a tolerated nil user-application value
			// (cfg.Applications.Applications["x"] = nil, e.g. a JSON null
			// decoding to a nil pointer on a lenient/HA-synced load, #3494)
			// resolves as (nil, true) — ResolveApplication reports found=true,
			// so the !found guard above does NOT catch it, and dereferencing
			// app.Protocol below would panic BuildCatalog during snapshot/apply,
			// turning the tolerant "warn/skip and keep running" posture into a
			// control-plane crash. Skip it exactly like the not-found case and do
			// NOT consume an id slot (compileApplications rejects the nil app
			// before producing AppNames, so there is no id to keep in step with).
			continue
		}

		// #4887: honor ProtocolNumber's ok bit. catalogProtocolNumber (still used
		// by the drift-guard test) drops ok, collapsing an EXPLICIT but
		// unrepresentable protocol token (e.g. `protocol junos-foobar` surviving a
		// tolerant/HA-sync load that strict commit would reject) to byte 0. That
		// byte-0 fan-out shipped a live Protocol:0 (HOPOPT) catalog row whose
		// app_id the Rust helper stamps on genuine protocol-0 sessions — a false
		// AppID label for an application whose protocol was known-malformed. An
		// unresolvable token is unemittable (folded into `emittable` below): no
		// catalog row, no stampable AppNames name. An EXPLICIT `protocol 0`
		// resolves to (0, true) and is preserved.
		proto, protoOK := ProtocolNumber(app.Protocol)

		dstLow, dstHigh, derr := parsePortRange(app.DestinationPort)
		// #5194 A3-b1-F2: sanitize an EXPLICIT destination port so a literal
		// 0/0-0 (which parsePortRange returns as the (0,0) "no constraint"
		// sentinel) does not ship a catalog row that over-matches every port.
		// Only the EMPTY spec legitimately encodes unconstrained; skip it here.
		dstOK := true
		if derr == nil && app.DestinationPort != "" {
			dstLow, dstHigh, dstOK = NormalizeExplicitPortRange(dstLow, dstHigh)
		}
		if derr != nil {
			// Mirror the compiler EXACTLY (pkg/dataplane/compiler.go): on a
			// bad destination port it slog.Warns and `continue`s, which SKIPS
			// the loop-tail appID++. The id is NOT consumed — the next good
			// application overwrites this same id. So do NOT bump appID here;
			// emit no catalog entry (and #3725 M04: no AppNames row) for the
			// unparsable port and fall through to the next name. (Bumping here
			// is the #2065-review bug: it would shift every subsequent id by
			// one vs CompileResult.AppNames, so the Rust-stamped app_id would
			// resolve to the wrong name.)
			continue
		}

		// #3725 H03/M06: a bad source-port must NOT be discarded to zero bounds
		// (SrcPortLow=0/High=0 = UNCONSTRAINED source), which made a leniently-
		// loaded "destination-port 80 source-port 70000" stamp ANY TCP/80 flow
		// as that app (fail-OPEN over-broad labeling). Parse it and, on a parse
		// error, mark the app unemittable so no over-broad row is shipped.
		srcOK := true
		var srcLow, srcHigh uint16
		if app.SourcePort != "" {
			var serr error
			srcLow, srcHigh, serr = parsePortRange(app.SourcePort)
			if serr != nil {
				srcOK = false
			} else {
				// #5194 A3-b1-F2: same sanitization for an explicit source port
				// so a literal 0/0-0 source-port does not become the (0,0)
				// unconstrained-source sentinel and over-match every source port.
				srcLow, srcHigh, srcOK = NormalizeExplicitPortRange(srcLow, srcHigh)
			}
		}

		// #3725 M07: a reversed range (low>high) from the tolerant-load path
		// must not ship inverted bounds (dst_low=200,dst_high=100). The Rust
		// matcher tests p>=low && p<=high so it would never stamp anyway, but
		// shipping garbage bounds diverges from strict commit (validatePortSpec
		// rejects start>end) and the NAT parser (appPortsFromSpec #3726). Treat
		// a reversed dst or src range — and a bad source-port — as unemittable:
		// emit no catalog row (fail CLOSED, no mislabel), but still consume the
		// id below so the app_id sequence stays in lock-step with
		// compileApplications (which bumps its id in exactly these cases).
		// protoEmittable (#4887) joins the port gates. An OMITTED protocol (empty
		// spec) is the intended "any L4" case and fans out to TCP+UDP below, so it
		// stays emittable even though ProtocolNumber("") reports ok=false. An
		// EXPLICIT but unrepresentable protocol emits no row and no AppNames name,
		// but still consumes the id below so the app_id sequence stays lock-step
		// with compileApplications (which applies the identical gate for AppNames
		// parity — appid_catalog_parity_test.go).
		protoEmittable := protoOK || strings.TrimSpace(app.Protocol) == ""
		emittable := protoEmittable && srcOK && dstOK && dstLow <= dstHigh && srcLow <= srcHigh

		if emittable {
			// #3725 M04: record the id->name mapping ONLY for an app that emits
			// at least one catalog entry. Recording it before the port parse
			// (the old catalog.go / compiler.go:569 behavior) left AppNames
			// holding a name at an id no CatalogEntry can stamp when the
			// malformed app sorted last, so a skewed/stale app_id resolved to
			// the malformed name instead of UNKNOWN. compileApplications is
			// fixed the same way to keep the two AppNames maps byte-identical
			// (appid_catalog_parity_test.go).
			//
			// #3781: the id->name row is recorded here EVEN for a
			// type-constrained ICMP app whose over-matching CatalogEntry is
			// dropped below, because compileApplications also records that app's
			// AppNames row (it too is "emittable" — an ICMP app has an empty,
			// non-inverted port range). Keeping the row in lock-step preserves
			// the AppNames parity contract; the dropped entry simply means the
			// helper never stamps that id, so the name is inert (resolves for no
			// live session) rather than a false label.
			cat.AppNames[appID] = name

			// #3781 interim (log-integrity): an ICMP/ICMPv6 application that
			// carries a type/code constraint (e.g. junos-ping = icmp type 8)
			// cannot express that constraint on the L3/L4-only catalog wire, so a
			// protocol-only row would match EVERY ICMP message type. A non-echo
			// ICMP (destination-unreachable, timestamp, ICMPv6 ND) that correctly
			// falls to default-deny would then be stamped with the ping app label
			// even though the echo-only verdict engine never matched it. Until the
			// type/code-aware catalog wire lands (DEFERRED per the #3781 /research
			// plan), drop the over-matching row: the AppNames id is still recorded
			// above and consumed below, so such ICMP resolves to an honest UNKNOWN
			// (or junos-icmp-all, when a protocol-only ICMP app is also referenced)
			// rather than a false type-constrained label. An ICMP app WITHOUT a
			// type/code constraint (junos-icmp-all, a user protocol-only ICMP app)
			// is unaffected and still ships its protocol-only row.
			if !icmpTypeConstrained(app) {
				// An OMITTED protocol (empty spec) means "any L4":
				// compileApplications installs one entry per TCP and UDP (the
				// Junos custom-application default). An EXPLICIT protocol —
				// including `protocol 0` (HOPOPT), which ProtocolNumber resolves
				// to (0, true) — matches that single protocol only.
				//
				// #4008: the old trigger keyed the fan-out on the RESOLVED number
				// being 0 (`proto == 0`), which conflated three distinct cases
				// that all yield proto 0: an omitted protocol (the intended
				// fan-out), an EXPLICIT `protocol 0` (a specific IANA protocol,
				// NOT a wildcard), and an unrepresentable token on the tolerant-
				// load path (ProtocolNumber ok=false). So a single-protocol
				// `protocol 0` app fanned out to BOTH TCP and UDP → a policy
				// referencing it over-matched (a TCP-only intent also matched the
				// UDP flow). Key the fan-out on the protocol being ABSENT instead:
				// only an omitted spec fans out; an explicit protocol (0 or any
				// other) stays single. The `app.Protocol != "icmp"` guard is now
				// subsumed — a non-empty protocol never fans out.
				protos := []uint8{proto}
				if strings.TrimSpace(app.Protocol) == "" {
					protos = []uint8{6, 17}
				}
				for _, p := range protos {
					cat.Entries = append(cat.Entries, CatalogEntry{
						Name:        name,
						AppID:       appID,
						Protocol:    p,
						DstPortLow:  dstLow,
						DstPortHigh: dstHigh,
						SrcPortLow:  srcLow,
						SrcPortHigh: srcHigh,
					})
				}
			}
		}
	}

	// #5296: emit entries in ASCENDING app_id order. The catalog snapshot the
	// Rust classifier consumes (buildAppCatalogSnapshot) iterates this slice, and
	// AppCatalog::from_snapshot resolves an exact-destination-port COLLISION by
	// keeping the FIRST-emitted entry for that port (`exact_dst.or_insert`). Under
	// the legacy positional ids sorted-name order == ascending-id order, so that
	// first-writer was the lowest id; under the #5296 stable name-hash ids the two
	// orders diverge, so we sort by id here to keep "first writer == lowest app_id"
	// — the property the Rust exact-port tiebreak (and the scan-list min-id
	// tiebreak) rely on to agree with the AppID-disabled Go fallback
	// (resolveTupleFallback, keyed on lowest StableAppID). Secondary keys make the
	// order fully deterministic for fan-out/same-id rows.
	sort.Slice(cat.Entries, func(i, j int) bool {
		a, b := cat.Entries[i], cat.Entries[j]
		if a.AppID != b.AppID {
			return a.AppID < b.AppID
		}
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		if a.DstPortLow != b.DstPortLow {
			return a.DstPortLow < b.DstPortLow
		}
		if a.DstPortHigh != b.DstPortHigh {
			return a.DstPortHigh < b.DstPortHigh
		}
		return a.SrcPortLow < b.SrcPortLow
	})

	return cat, nil
}

// ProtocolNumber is the single source of truth (#2124) for resolving an IANA
// protocol name, a Junos predefined-protocol alias, or a numeric string to its
// IANA protocol number. It is the centralized replacement for the formerly
// duplicated tables in pkg/appid (catalogProtocolNumber) and pkg/dataplane
// (protocolNumber); both now delegate here so the userspace policy capability
// gate, the legacy compiler, and the app-identification catalog agree on
// exactly which protocols are representable.
//
// ok=false means the token is neither a known name/alias nor a valid 0..255
// numeric. Crucially, the deliberate "protocol 0" (HOPOPT) resolves to
// (0, true) — distinct from the unrepresentable (0, false) case — so callers
// that fail closed on unrepresentable protocols (#2124 Layer G) do not also
// reject a legitimate "protocol 0".
//
// pkg/appid is a leaf package (imports only pkg/config), so housing the helper
// here keeps it importable by both pkg/dataplane (which already imports
// pkg/appid) and pkg/dataplane/userspace without an import cycle.
func ProtocolNumber(name string) (uint8, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "tcp", "junos-tcp-any":
		return 6, true
	case "udp", "junos-udp-any":
		return 17, true
	case "icmp", "junos-icmp-all", "junos-ping":
		return 1, true
	case "icmpv6", "icmp6", "junos-icmp6-all", "junos-pingv6":
		return 58, true
	case "gre", "junos-gre":
		return 47, true
	case "ospf", "junos-ospf":
		return 89, true
	case "junos-ip-in-ip", "junos-ipip", "ipip":
		return 4, true
	case "ipv6":
		// IANA protocol 41 (IPv6 encapsulation). This is the reverse of
		// ProtocolName(41)=="ipv6" — added in #3393 so the canonical
		// display name round-trips through the SSOT. ProtocolName renders
		// it, so it must parse back to the same number.
		return 41, true
	case "egp":
		return 8, true
	case "igmp":
		return 2, true
	case "pim":
		return 103, true
	case "ah":
		return 51, true
	case "esp":
		return 50, true
	case "sctp":
		return 132, true
	case "vrrp":
		return 112, true
	default:
		// Numeric protocol number, including the deliberate "0" (HOPOPT).
		// Canonical raw ASCII decimal only (#9899 F102): no sign, no
		// surrounding whitespace — same token, same meaning across readers.
		if n, err := config.ParseCanonicalUint(name); err == nil && n >= 0 && n < 256 {
			return uint8(n), true
		}
		return 0, false
	}
}

// ProtocolNumberLenient resolves an operator protocol-FILTER token (a
// name, alias, or numeric 0-255) to its IP protocol number for the
// session-inspection surfaces. It accepts everything ProtocolNumber
// resolves PLUS any display-only name that ProtocolName renders but
// ProtocolNumber does not reverse.
//
// Since #3393 closed the strict round-trip (every name ProtocolName
// emits — including "ipv6"=41 — now reverses through ProtocolNumber), the
// ProtocolName reverse-scan below is a belt-and-suspenders backstop rather
// than a behavioral difference: for the current tables this function is
// equal to ProtocolNumber. It is retained as a stable seam for the filter
// callers (cmd/cli, gRPC session filters) so that if ProtocolName ever
// gains a render-only name ahead of its ProtocolNumber reverse, the
// read/filter side still accepts the name the system displays rather than
// rejecting it as an invalid filter.
func ProtocolNumberLenient(name string) (uint8, bool) {
	if n, ok := ProtocolNumber(name); ok {
		return n, true
	}
	t := strings.ToLower(strings.TrimSpace(name))
	if t == "" {
		return 0, false
	}
	// ProtocolName is the display SSOT; accept any token it can render.
	for p := 0; p < 256; p++ {
		if ProtocolName(uint8(p)) == t {
			return uint8(p), true
		}
	}
	return 0, false
}

// ParseProtocolFilterToken resolves one non-empty session-filter token through
// the Lenient protocol taxonomy. Callers must keep their token != "" guard so
// an absent or explicitly empty filter remains "no protocol filter"; both
// absence and invalid non-empty input return (0, false).
func ParseProtocolFilterToken(token string) (proto uint8, ok bool) {
	if token == "" {
		return 0, false
	}
	return ProtocolNumberLenient(token)
}

// ProtoFilterMatches compares a session protocol with a parsed filter pair.
// A false hasProto bit means no protocol filter; callers parse and validate
// the token once before walking sessions, preserving protocol 0 as a valid
// filter value.
func ProtoFilterMatches(protocol, filterProto uint8, hasProto bool) bool {
	return !hasProto || protocol == filterProto
}

// ProtocolName is the single source of truth for rendering an IP protocol
// number as a canonical lowercase protocol name. It returns "" for a
// protocol that has no display name here, letting callers fall back to the
// numeric form.
//
// This renders the named protocol set the operator surfaces have
// historically displayed (matching the prior gRPC switch); it is NOT a
// complete inverse of ProtocolNumber. ProtocolNumber resolves additional
// protocols (ospf/egp/igmp/pim/ah/sctp/vrrp/...) that have no display
// mapping here. But the converse round-trip DOES hold for the entire set
// ProtocolName renders: every name it returns parses back to the same
// number, i.e. ProtocolNumber(ProtocolName(p)) == p for every p with a
// display name. #3393 closed the last gap — ProtocolName(41)=="ipv6" now
// reverses through ProtocolNumber("ipv6")==41, so a rendered protocol name
// re-parses safely (no accepted-but-never-matches / mislabel for proto 41).
//
// This is the SSOT for the named-protocol set rendered by every operator
// surface (REST pkg/api, gRPC pkg/grpcapi). Before #2949 each surface kept its
// own switch: REST rendered only tcp/udp/icmp/icmpv6 while gRPC also rendered
// gre/esp/ipip/ipv6, so a REST `protocol=gre` NAMED filter silently failed to
// match and a GRE/ESP session displayed numeric on REST but named on gRPC.
// Housing the table here (a leaf package importing only pkg/config) keeps the
// REST and gRPC name sets identical from one definition.
//
// Casing is a per-surface concern, not part of this SSOT: REST upper-cases the
// result to preserve its historical TCP/UDP/ICMP display; gRPC uses the
// lowercase form directly. The named SET (which protocols are named at all) is
// identical across surfaces.
func ProtocolName(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 58:
		return "icmpv6"
	case 47:
		return "gre"
	case 50:
		return "esp"
	case 4:
		return "ipip"
	case 41:
		return "ipv6"
	default:
		return ""
	}
}

// icmpTypeConstrained reports whether an application carries an ICMP/ICMPv6
// type or code constraint (e.g. junos-ping = icmp type 8, predefined.go). Such
// an app's L3/L4 match rule — the catalog CatalogEntry and the display tuple
// fallback — is protocol-only (the catalog wire has no icmp type/code fields,
// #3781), so a protocol-only row / tuple match would over-match EVERY ICMP
// message type and falsely label a non-echo ICMP (destination-unreachable,
// timestamp, ICMPv6 ND) that correctly fell to default-deny as the ping app.
//
// The strict commit gate (validateApplicationSpecsStrict, #3348) rejects a code
// without a type and a type on a non-ICMP protocol, so on the strict path a set
// ICMPCode implies a set ICMPType. This predicate also treats a stray
// code-only app (admissible on the tolerant-load path) as constrained so no
// over-broad ICMP label leaks there either. The fully type/code-aware catalog
// wire + classifier is DEFERRED per the #3781 /research plan; this is the
// Go-only interim that removes the false label immediately.
func icmpTypeConstrained(app *config.Application) bool {
	return app != nil && (app.ICMPType != nil || app.ICMPCode != nil)
}

// catalogProtocolNumber resolves a protocol to its byte for the app-id catalog,
// returning 0 for an unrepresentable token (the catalog's historical
// "unknown -> 0" behavior). Delegates to ProtocolNumber (#2124) so the catalog
// and the capability gate share one table.
func catalogProtocolNumber(name string) uint8 {
	n, _ := ProtocolNumber(name)
	return n
}

// parsePortRange mirrors pkg/dataplane.parsePortRange. Inclusive boundaries;
// empty spec means no constraint (0,0).
func parsePortRange(spec string) (uint16, uint16, error) {
	if spec == "" {
		return 0, 0, nil
	}
	if strings.Contains(spec, "-") {
		parts := strings.SplitN(spec, "-", 2)
		low, err := strconv.ParseUint(parts[0], 10, 16)
		if err != nil {
			return 0, 0, err
		}
		high, err := strconv.ParseUint(parts[1], 10, 16)
		if err != nil {
			return 0, 0, err
		}
		return uint16(low), uint16(high), nil
	}
	port, err := strconv.ParseUint(spec, 10, 16)
	if err != nil {
		return 0, 0, err
	}
	return uint16(port), uint16(port), nil
}

// NormalizeExplicitPortRange sanitizes a NON-EMPTY parsed application port
// range so it can never collide with the (0,0) pair the Rust matcher reserves
// for "no port constraint" (#5194 A3-b1-F2). Only an EMPTY port spec
// legitimately encodes the unconstrained sentinel — parsePortRange returns
// (0,0) for "" — so the caller must NOT route the empty case through here.
//
// Port 0 is reserved by IANA and never appears on the wire, so a range whose
// low bound is 0 but whose high bound is a real port is narrowed to 1..high. A
// range that consists solely of port 0 — a bare "0" or "0-0" — has no
// representable, non-sentinel port; it is reported unemittable (ok=false) so
// the caller ships no catalog row, exactly mirroring the reversed-range
// fail-closed behavior. Without this a tolerantly-loaded `destination-port 0`
// application emitted a (0,0) catalog row that over-matched EVERY port of its
// protocol.
func NormalizeExplicitPortRange(low, high uint16) (nlow, nhigh uint16, ok bool) {
	if high == 0 {
		// Either a bare "0"/"0-0" (low==0) or a reversed "N-0" (low>0); neither
		// has a representable, non-sentinel port. Fail closed.
		return low, high, false
	}
	if low == 0 {
		low = 1
	}
	return low, high, true
}
