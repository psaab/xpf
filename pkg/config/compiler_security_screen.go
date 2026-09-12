package config

import (
	"fmt"
	"math"
	"sort"
	"strconv"
)

// #4114: the port-scan / ip-sweep `threshold` is a Junos MICROSECOND
// detection WINDOW (not a distinct-destination count). The detection COUNT is
// a fixed constant (scanSweepDetectCount, 10). Junos accepts a window in the
// range [1000, 1000000] us (default 5000). xpf preserves any operator value
// (no clamp — a window is a time, not a bounded count) and emits a commit-time
// ADVISORY when the value falls outside the Junos range so a count-shaped
// legacy value (e.g. a pre-#4114 `threshold 10`) is flagged for re-check.
//
// scanSweepDetectCount MUST stay in sync with the Rust SCAN_DETECT_COUNT in
// userspace-dp/src/screen/scan.rs.
const (
	minScanSweepWindowMicros = 1_000
	maxScanSweepWindowMicros = 1_000_000
	scanSweepDetectCount     = 10
)

// defaultSynFloodAttackThreshold is the Junos SRX default attack-threshold
// (SYN segments per second) applied when a syn-flood screen is enabled
// without an explicit `attack-threshold`. Matching Junos, configuring
// syn-flood with only source/destination-threshold or timeout still arms
// the screen at this rate. See pkg/config/compiler_security.go syn-flood
// parse and the dataplane gate in pkg/dataplane/compiler_iface.go (#3024).
const defaultSynFloodAttackThreshold = 200

// Junos SRX default thresholds applied when the corresponding screen check is
// enabled WITHOUT an explicit threshold. The Rust screen engine
// (userspace-dp/src/screen/mod.rs, scan.rs) gates every check on
// `threshold > 0`, so an enabled-but-unset check would compile to 0 and be
// silently skipped. These are the siblings of #3024 (#3230).
const (
	// defaultICMPFloodThreshold matches the Junos SRX `icmp flood threshold`
	// default of 1000 ICMP packets per second.
	defaultICMPFloodThreshold = 1000

	// defaultUDPFloodThreshold matches the Junos SRX `udp flood threshold`
	// default of 1000 UDP packets per second.
	defaultUDPFloodThreshold = 1000

	// defaultPortScanThreshold / defaultIPSweepThreshold supply a default for
	// `tcp port-scan` / `ip ip-sweep` when enabled without a threshold. #4114:
	// the `threshold` is the Junos detection WINDOW in MICROSECONDS (the
	// detection COUNT is the fixed scanSweepDetectCount = 10). Junos flags a
	// port scan / address sweep when one source reaches 10 distinct
	// destination ports / addresses within this window; its default window is
	// 5000 us. The dataplane resets its per-source distinct-destination set
	// each window and fires at the fixed count (SCAN_DETECT_COUNT in scan.rs).
	defaultPortScanThreshold = 5000
	defaultIPSweepThreshold  = 5000
)

// synFloodSrcAttackRatioAdvisoryThreshold is the attack-threshold /
// source-threshold ratio above which the dataplane's per-source count-min
// sketch (SRC_COLS columns, #3315) can begin to false-throttle legitimate
// sources under a sub-aggregate spoofed spread. It mirrors the Rust SRC_COLS
// width (2048) rounded down to a round number; setting source-threshold orders
// of magnitude below attack-threshold is the only regime where per-source
// over-count becomes plausible, and even then the cookie-active gate confines
// it. We advise (never reject) so the config still commits.
const synFloodSrcAttackRatioAdvisoryThreshold = 1000

// validateScreenSynFloodSubThresholds emits a WARNING (never a hard reject) for
// the one risky SYN-flood sub-threshold band (#3315):
//
//   - an attack-threshold orders of magnitude above source-threshold is the one
//     pathological band where the per-source count-min sketch can false-throttle
//     legitimate sources; advise the operator (per the converged plan §5b).
//
// It fires on BOTH the strict and lenient compile paths: the values are valid
// and parseable, the dataplane just cannot fully honour them.
//
// #3527: the `timeout` leaf NO LONGER warns. It is now enforced as a per-zone
// override of the half-open session window (tcp_opening_ns) — see
// pkg/dataplane/userspace/screens.go (SYNFloodTimeout) and the dataplane's
// SessionTable opening overrides. The historical accepted-but-inert advisory
// is removed now that the leaf is effective.
func validateScreenSynFloodSubThresholds(cfg *Config) []string {
	var warnings []string
	names := make([]string, 0, len(cfg.Security.Screen))
	for name := range cfg.Security.Screen {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		sp := cfg.Security.Screen[name]
		if sp == nil || sp.TCP.SynFlood == nil {
			continue
		}
		sf := sp.TCP.SynFlood
		if sf.SourceThreshold > 0 && sf.AttackThreshold > 0 &&
			sf.AttackThreshold/sf.SourceThreshold > synFloodSrcAttackRatioAdvisoryThreshold {
			warnings = append(warnings, fmt.Sprintf(
				"security screen ids-option %s tcp syn-flood source-threshold %d is "+
					"more than %dx below attack-threshold %d; the per-source detector "+
					"is a count-min sketch and may false-throttle legitimate sources in "+
					"this regime — consider raising source-threshold",
				name, sf.SourceThreshold, synFloodSrcAttackRatioAdvisoryThreshold, sf.AttackThreshold))
		}
	}
	return warnings
}

// validateScreenScanSweepWindows emits a WARNING (never a hard reject) for any
// screen profile whose port-scan or ip-sweep `threshold` — a Junos MICROSECOND
// detection WINDOW (#4114) — falls outside the Junos range
// [minScanSweepWindowMicros, maxScanSweepWindowMicros]. We preserve the
// operator's configured value (no mutation, no rejection — existing configs
// keep booting on BOTH the strict and lenient compile paths) and advise a
// re-check. This is the migration safety net for the pre-#4114 count->window
// semantic flip: a small count-shaped legacy value (e.g. `threshold 10`) now
// reads as a 10 us window (an extremely tight, near-never-firing window), so
// the advisory tells the operator their old count is now a time.
func validateScreenScanSweepWindows(cfg *Config) []string {
	var warnings []string
	// Deterministic order so the warning set is stable across runs.
	names := make([]string, 0, len(cfg.Security.Screen))
	for name := range cfg.Security.Screen {
		names = append(names, name)
	}
	sort.Strings(names)
	warnWindow := func(name, path string, val int) string {
		return fmt.Sprintf(
			"security screen ids-option %s %s %d is outside the Junos detection-window "+
				"range [%d, %d] microseconds; #4114 reads this value as a MICROSECOND "+
				"time window (detection count is a fixed %d), not a count — a small "+
				"count-shaped value now arms an extremely tight window. Re-check the "+
				"intended window.",
			name, path, val, minScanSweepWindowMicros, maxScanSweepWindowMicros, scanSweepDetectCount)
	}
	outOfRange := func(v int) bool {
		return v > 0 && (v < minScanSweepWindowMicros || v > maxScanSweepWindowMicros)
	}
	for _, name := range names {
		sp := cfg.Security.Screen[name]
		if sp == nil {
			continue
		}
		if outOfRange(sp.TCP.PortScanThreshold) {
			warnings = append(warnings, warnWindow(name, "tcp port-scan threshold", sp.TCP.PortScanThreshold))
		}
		if outOfRange(sp.IP.IPSweepThreshold) {
			warnings = append(warnings, warnWindow(name, "ip ip-sweep threshold", sp.IP.IPSweepThreshold))
		}
	}
	return warnings
}

func compileScreen(node *Node, sec *SecurityConfig) error {
	for _, inst := range namedInstances(node.FindChildren("ids-option")) {
		profile := &ScreenProfile{Name: inst.name}

		// parseThresh parses an explicitly-provided screen numeric value. An
		// EMPTY value means the leaf was enabled without an explicit threshold:
		// ok=false signals the caller to apply the Junos default (#3230) — that
		// is NOT a bad value. A non-empty value that fails to parse or is not a
		// positive integer is recorded on profile.BadNumeric for
		// validateScreenNumericStrict (#3317): before this the strconv error was
		// swallowed and the leaf silently became the default or zero/disabled
		// (fail-open). ok=false on a bad value too, so the lenient / load path
		// still falls back to the default and boots (#1960 no-brick).
		parseThresh := func(path, val string) (int, bool) {
			if val == "" {
				return 0, false
			}
			n, err := strconv.Atoi(val)
			// Reject non-numeric, non-positive, AND > math.MaxUint32. Every
			// published screen threshold is cast to uint32 in the snapshot
			// builder (pkg/dataplane/userspace/screens.go) — a value above
			// 2^32-1 (e.g. 4294967296) would WRAP on that cast (uint32(2^32)==0),
			// and the Rust screen treats a zero threshold as unset and OMITS the
			// check. That is the exact fail-open class #3317 closes, so the gate
			// must reject it at commit rather than let it wrap silently. int64(n)
			// keeps the comparison portable: on a 32-bit `int` platform an
			// over-2^32 literal already fails Atoi (err != nil), so this only
			// adds a real bound on 64-bit. Dataplane-meaningful ranges are
			// narrower still (e.g. the port-scan/ip-sweep microsecond WINDOW is
			// advised to the Junos [1000, 1000000] range downstream, #4114), but
			// math.MaxUint32 is the required floor that prevents the wrap.
			if err != nil || n < 1 || int64(n) > math.MaxUint32 {
				profile.BadNumeric = append(profile.BadNumeric,
					ScreenBadNumeric{Path: path, Value: val})
				return 0, false
			}
			return n, true
		}
		// numVal extracts the numeric value a screen leaf carries at Keys[keyIdx].
		// In both AST shapes a leaf collapses its tokens onto Keys, so the value
		// is at a fixed offset: a `threshold <N>` leaf carries it at Keys[1]
		// (keyIdx=1); a `flood threshold <N>` leaf carries the intermediate
		// `threshold` keyword at Keys[1] and the number at Keys[2] (keyIdx=2).
		// nodeVal (Keys[1]) is the fallback only when Keys is too short. An empty
		// result means the leaf was enabled without an explicit value.
		numVal := func(n *Node, keyIdx int) string {
			if len(n.Keys) > keyIdx {
				return n.Keys[keyIdx]
			}
			return nodeVal(n)
		}

		// recordKeyExtras flags trailing tokens collapsed onto a RECOGNIZED
		// screen leaf's Keys beyond the tokens compileScreen legitimately
		// reads (#3332). In the flat-set AST a leaf with no schema children
		// absorbs every trailing token onto its Keys, so `tcp land bogus`
		// lands as Keys=["land","bogus"] and the compiler reads only the
		// keyword (and, for value leaves, a fixed Keys index), silently
		// dropping the rest — a typo'd extra token is accepted with no
		// warning. `allowed` is the total Keys length the leaf legitimately
		// carries: 1 for a boolean flag (`land`), 2 for a single-value leaf
		// whose value sits at Keys[1] (`port-scan threshold <n>`,
		// `syn-flood attack-threshold <n>`, `limit-session source-ip-based
		// <n>` value tail), 3 for `flood threshold <n>` (value at Keys[2]).
		// Each token past that span is operator garbage; record it on
		// UnknownLeaves so validateScreenUnknownStrict rejects the commit
		// (the tolerant load / peer-sync path downgrades to a warning —
		// #3318 / #1960 no-brick). This is distinct from the #3318 unknown-
		// KEYWORD gate: here the leaf keyword itself IS supported.
		recordKeyExtras := func(prefix string, n *Node, allowed int) {
			for i := allowed; i < len(n.Keys); i++ {
				profile.UnknownLeaves = append(profile.UnknownLeaves, prefix+" "+n.Keys[i])
			}
		}
		// recordChildExtras flags unexpected CHILD nodes hanging off a
		// recognized screen leaf that takes no sub-stanza (#3332). A leaf
		// declared with args>0 in setSchema (limit-session source-ip-based /
		// destination-ip-based) has SetPath consume its value into Keys and
		// park any further trailing token as a CHILD node rather than on
		// Keys, so recordKeyExtras cannot see it. The leaf models no children,
		// so every child here is garbage that would otherwise be silently
		// dropped.
		recordChildExtras := func(prefix string, n *Node) {
			for _, c := range n.Children {
				if c == nil || len(c.Keys) == 0 {
					continue
				}
				profile.UnknownLeaves = append(profile.UnknownLeaves, prefix+" "+c.Keys[0])
			}
		}

		// #6683: `ids-option s1 icmp ping-death;` packs the WHOLE body onto
		// the ids-option node's Keys, leaving Children empty — every check in
		// the profile compiled DISABLED while the profile itself survived and
		// bound to a zone normally, so the operator got no protection from a
		// check they configured and nothing said so.
		idsSchema := schemaForPath("security", "screen", "ids-option")
		body := packedBody(inst.node, idsSchema)

		// #9421: #6683 normalised the ids-option node's packed tail and
		// stopped there. A FAMILY node one level in (`icmp ping-death;`,
		// `icmp [ ping-death fragment ]`, `tcp bogus-check;`) carries its
		// body on its own Keys with ZERO children, so every loop below runs
		// zero times — the check compiled DISABLED and, because nothing
		// reached UnknownLeaves, the #3318 gate never armed either. The flat
		// spelling of the same statement builds a chain and does not lose it,
		// so the two AST shapes disagreed on the strict verdict, on the
		// compiled boolean and on whether the gate fired. Normalise here so
		// both shapes reach the identical readers.
		body = screenNormalizeFamilies(body, idsSchema)

		// screenOpt normalises ONE family-option node so a sub-knob written
		// packed (`flood threshold 500;`) is read from the same CHILD shape as
		// the block spelling (`flood { threshold 500; }`). #7460: the two
		// spellings were read by two different readers — ip-sweep/port-scan/
		// syn-flood iterated Children and never saw the packed form, so the
		// configured threshold was silently replaced by the default.
		screenOpt := func(famSchema *schemaNode, n *Node) *Node {
			if famSchema == nil || n == nil || len(n.Keys) == 0 {
				return n
			}
			return packedBody(n, resolveSchemaChild(famSchema, n.Keys[0]))
		}
		famSchema := func(fam string) *schemaNode {
			if idsSchema == nil {
				return nil
			}
			return resolveSchemaChild(idsSchema, fam)
		}

		// #3318: the screen schema subtrees are open. Record any unknown/
		// unsupported top-level screen family so validateScreenUnknownStrict can
		// reject the commit fail-closed instead of silently dropping it.
		for _, fam := range body.Children {
			switch fam.Name() {
			case "icmp", "ip", "tcp", "udp", "limit-session":
				// handled below
			case "alarm-without-drop":
				// Junos profile-wide audit/log-only mode. A boolean flag
				// leaf directly under the ids-option (no value, no
				// sub-stanza). When set, every check in this profile that
				// would drop instead raises a log-only alarm and forwards
				// (the dataplane converts the Drop verdict to a
				// PERMIT/alarm). Record any trailing garbage so the #3318
				// unknown-leaf gate still rejects it. Because the leaf is a
				// known childless schema node, a flat-set trailing token
				// (`alarm-without-drop bogus`) parks as a CHILD rather than
				// collapsing onto Keys, so both shapes are checked.
				profile.AlarmWithoutDrop = true
				recordKeyExtras("alarm-without-drop", fam, 1)
				recordChildExtras("alarm-without-drop", fam)
			default:
				profile.UnknownLeaves = append(profile.UnknownLeaves, fam.Name())
			}
		}

		icmpNode := body.FindChild("icmp")
		if icmpNode != nil {
			icmpSchema := famSchema("icmp")
			for _, rawOpt := range icmpNode.Children {
				opt := screenOpt(icmpSchema, rawOpt)
				switch opt.Name() {
				case "ping-death":
					profile.ICMP.PingDeath = true
					recordKeyExtras("icmp ping-death", opt, 1)
					recordChildExtras("icmp ping-death", opt)
				case "fragment":
					profile.ICMP.Fragment = true
					recordKeyExtras("icmp fragment", opt, 1)
					recordChildExtras("icmp fragment", opt)
				case "flood":
					recordKeyExtras("icmp flood", opt, 3)
					// #7460: read the threshold from the CHILD shape too, which
					// is what the expander normalises the packed spelling into
					// and what ip-sweep / port-scan / syn-flood already read.
					// Before this, `flood` was the ONLY sub-knob reading Keys,
					// so it accepted the spelling its siblings rejected and
					// rejected the one they accepted.
					floodVal := ""
					if len(opt.Keys) > 2 {
						floodVal = opt.Keys[2]
					}
					for _, fOpt := range opt.Children {
						if fOpt.Name() != "threshold" {
							profile.UnknownLeaves = append(profile.UnknownLeaves, "icmp flood "+fOpt.Name())
							continue
						}
						recordKeyExtras("icmp flood threshold", fOpt, 2)
						// Prefix is the FLOOD path, not the threshold path: a
						// trailing token after the value is garbage on `icmp flood`,
						// and that is the leaf name the #3332 gate reports.
						recordChildExtras("icmp flood", fOpt)
						floodVal = numVal(fOpt, 1)
					}
					if n, ok := parseThresh("icmp flood", floodVal); ok {
						profile.ICMP.FloodThreshold = n
					}
					// icmp flood enabled without an explicit threshold: arm at
					// the Junos default (1000 pps) so the dataplane `>0` gate
					// fires rather than silently skipping the check (#3230).
					if profile.ICMP.FloodThreshold <= 0 {
						profile.ICMP.FloodThreshold = defaultICMPFloodThreshold
					}
				default:
					profile.UnknownLeaves = append(profile.UnknownLeaves, "icmp "+opt.Name())
				}
			}
		}

		ipNode := body.FindChild("ip")
		if ipNode != nil {
			ipSchema := famSchema("ip")
			for _, rawOpt := range ipNode.Children {
				opt := screenOpt(ipSchema, rawOpt)
				switch opt.Name() {
				case "source-route-option":
					profile.IP.SourceRouteOption = true
					recordKeyExtras("ip source-route-option", opt, 1)
					recordChildExtras("ip source-route-option", opt)
				case "tear-drop":
					profile.IP.TearDrop = true
					recordKeyExtras("ip tear-drop", opt, 1)
					recordChildExtras("ip tear-drop", opt)
				case "ip-sweep":
					for _, swOpt := range opt.Children {
						switch swOpt.Name() {
						case "threshold":
							recordKeyExtras("ip ip-sweep threshold", swOpt, 2)
							recordChildExtras("ip ip-sweep threshold", swOpt)
							if n, ok := parseThresh("ip ip-sweep threshold", numVal(swOpt, 1)); ok {
								profile.IP.IPSweepThreshold = n
							}
						default:
							profile.UnknownLeaves = append(profile.UnknownLeaves, "ip ip-sweep "+swOpt.Name())
						}
					}
					// ip-sweep enabled without an explicit threshold: arm at the
					// Junos default detection WINDOW (5000 us, #4114) so the
					// dataplane `>0` gate fires rather than skipping the check
					// (#3230).
					if profile.IP.IPSweepThreshold <= 0 {
						profile.IP.IPSweepThreshold = defaultIPSweepThreshold
					}
				default:
					profile.UnknownLeaves = append(profile.UnknownLeaves, "ip "+opt.Name())
				}
			}
		}

		tcpNode := body.FindChild("tcp")
		if tcpNode != nil {
			tcpSchema := famSchema("tcp")
			for _, rawOpt := range tcpNode.Children {
				opt := screenOpt(tcpSchema, rawOpt)
				switch opt.Name() {
				case "land":
					profile.TCP.Land = true
					recordKeyExtras("tcp land", opt, 1)
					recordChildExtras("tcp land", opt)
				case "winnuke":
					profile.TCP.WinNuke = true
					recordKeyExtras("tcp winnuke", opt, 1)
					recordChildExtras("tcp winnuke", opt)
				case "syn-frag":
					profile.TCP.SynFrag = true
					recordKeyExtras("tcp syn-frag", opt, 1)
					recordChildExtras("tcp syn-frag", opt)
				case "syn-fin":
					profile.TCP.SynFin = true
					recordKeyExtras("tcp syn-fin", opt, 1)
					recordChildExtras("tcp syn-fin", opt)
				case "no-flag":
					profile.TCP.NoFlag = true
					recordKeyExtras("tcp no-flag", opt, 1)
					recordChildExtras("tcp no-flag", opt)
				case "fin-no-ack":
					profile.TCP.FinNoAck = true
					recordKeyExtras("tcp fin-no-ack", opt, 1)
					recordChildExtras("tcp fin-no-ack", opt)
				case "syn-flood":
					sf := &SynFloodConfig{}
					for _, sfOpt := range expandResolvingRuns9792(opt.Children, synFloodSchema9792()) { // #9792: lenient-path packed run
						val := numVal(sfOpt, 1)
						switch sfOpt.Name() {
						case "alarm-threshold":
							recordKeyExtras("tcp syn-flood alarm-threshold", sfOpt, 2)
							recordChildExtras("tcp syn-flood alarm-threshold", sfOpt)
							if n, ok := parseThresh("tcp syn-flood alarm-threshold", val); ok {
								sf.AlarmThreshold = n
							}
						case "attack-threshold":
							recordKeyExtras("tcp syn-flood attack-threshold", sfOpt, 2)
							recordChildExtras("tcp syn-flood attack-threshold", sfOpt)
							if n, ok := parseThresh("tcp syn-flood attack-threshold", val); ok {
								sf.AttackThreshold = n
							}
						case "source-threshold":
							recordKeyExtras("tcp syn-flood source-threshold", sfOpt, 2)
							recordChildExtras("tcp syn-flood source-threshold", sfOpt)
							if n, ok := parseThresh("tcp syn-flood source-threshold", val); ok {
								sf.SourceThreshold = n
							}
						case "destination-threshold":
							recordKeyExtras("tcp syn-flood destination-threshold", sfOpt, 2)
							recordChildExtras("tcp syn-flood destination-threshold", sfOpt)
							if n, ok := parseThresh("tcp syn-flood destination-threshold", val); ok {
								sf.DestinationThreshold = n
							}
						case "timeout":
							recordKeyExtras("tcp syn-flood timeout", sfOpt, 2)
							recordChildExtras("tcp syn-flood timeout", sfOpt)
							if n, ok := parseThresh("tcp syn-flood timeout", val); ok {
								sf.Timeout = n
							}
						default:
							profile.UnknownLeaves = append(profile.UnknownLeaves, "tcp syn-flood "+sfOpt.Name())
						}
					}
					// Junos applies a default attack-threshold of 200
					// SYN segments/second when syn-flood screening is
					// enabled without an explicit attack-threshold. Without
					// this fallback the downstream dataplane gate (which
					// requires AttackThreshold > 0) would silently leave
					// SYN-flood protection — including syn-cookie — disabled
					// even though the operator configured it (#3024).
					if sf.AttackThreshold <= 0 {
						sf.AttackThreshold = defaultSynFloodAttackThreshold
					}
					profile.TCP.SynFlood = sf
				case "port-scan":
					for _, psOpt := range opt.Children {
						switch psOpt.Name() {
						case "threshold":
							recordKeyExtras("tcp port-scan threshold", psOpt, 2)
							recordChildExtras("tcp port-scan threshold", psOpt)
							if n, ok := parseThresh("tcp port-scan threshold", numVal(psOpt, 1)); ok {
								profile.TCP.PortScanThreshold = n
							}
						default:
							profile.UnknownLeaves = append(profile.UnknownLeaves, "tcp port-scan "+psOpt.Name())
						}
					}
					// port-scan enabled without an explicit threshold: arm at
					// the Junos default detection WINDOW (5000 us, #4114) so the
					// dataplane `>0` gate fires rather than skipping the check
					// (#3230).
					if profile.TCP.PortScanThreshold <= 0 {
						profile.TCP.PortScanThreshold = defaultPortScanThreshold
					}
				default:
					profile.UnknownLeaves = append(profile.UnknownLeaves, "tcp "+opt.Name())
				}
			}
		}

		udpNode := body.FindChild("udp")
		if udpNode != nil {
			udpSchema := famSchema("udp")
			for _, rawOpt := range udpNode.Children {
				opt := screenOpt(udpSchema, rawOpt)
				switch opt.Name() {
				case "flood":
					recordKeyExtras("udp flood", opt, 3)
					// #7460: read the threshold from the CHILD shape too, which
					// is what the expander normalises the packed spelling into
					// and what ip-sweep / port-scan / syn-flood already read.
					// Before this, `flood` was the ONLY sub-knob reading Keys,
					// so it accepted the spelling its siblings rejected and
					// rejected the one they accepted.
					floodVal := ""
					if len(opt.Keys) > 2 {
						floodVal = opt.Keys[2]
					}
					for _, fOpt := range opt.Children {
						if fOpt.Name() != "threshold" {
							profile.UnknownLeaves = append(profile.UnknownLeaves, "udp flood "+fOpt.Name())
							continue
						}
						recordKeyExtras("udp flood threshold", fOpt, 2)
						// Prefix is the FLOOD path, not the threshold path: a
						// trailing token after the value is garbage on `udp flood`,
						// and that is the leaf name the #3332 gate reports.
						recordChildExtras("udp flood", fOpt)
						floodVal = numVal(fOpt, 1)
					}
					if n, ok := parseThresh("udp flood", floodVal); ok {
						profile.UDP.FloodThreshold = n
					}
					// udp flood enabled without an explicit threshold: arm at
					// the Junos default (1000 pps) so the dataplane `>0` gate
					// fires rather than silently skipping the check (#3230).
					if profile.UDP.FloodThreshold <= 0 {
						profile.UDP.FloodThreshold = defaultUDPFloodThreshold
					}
				default:
					profile.UnknownLeaves = append(profile.UnknownLeaves, "udp "+opt.Name())
				}
			}
		}

		limitNode := body.FindChild("limit-session")
		if limitNode != nil {
			limitsessionSchema := famSchema("limit-session")
			// #9792: a packed one-line run reaches this reader on the lenient path
			// (Store.Load / Store.SyncApply); expand it as #9235 does. Lenient path only.
			for _, rawOpt := range expandResolvingRuns9792(limitNode.Children, limitSessionSchema9792()) {
				opt := screenOpt(limitsessionSchema, rawOpt)
				val := numVal(opt, 1)
				switch opt.Name() {
				case "source-ip-based":
					recordKeyExtras("limit-session source-ip-based", opt, 2)
					recordChildExtras("limit-session source-ip-based", opt)
					if n, ok := parseThresh("limit-session source-ip-based", val); ok {
						profile.LimitSession.SourceIPBased = n
					}
				case "destination-ip-based":
					recordKeyExtras("limit-session destination-ip-based", opt, 2)
					recordChildExtras("limit-session destination-ip-based", opt)
					if n, ok := parseThresh("limit-session destination-ip-based", val); ok {
						profile.LimitSession.DestinationIPBased = n
					}
				default:
					profile.UnknownLeaves = append(profile.UnknownLeaves, "limit-session "+opt.Name())
				}
			}
		}

		sec.Screen[profile.Name] = profile
	}
	return nil
}
