package userspace

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

func buildScreenSnapshots(cfg *config.Config) []ScreenProfileSnapshot {
	if cfg == nil || len(cfg.Security.Screen) == 0 || len(cfg.Security.Zones) == 0 {
		return nil
	}
	var out []ScreenProfileSnapshot
	// Iterate zones in a deterministic (sorted-by-name) order. Ranging the
	// cfg.Security.Zones map directly yields nondeterministic iteration order,
	// which shifts the serialized snapshot's byte order build-to-build even
	// for an UNCHANGED config. That defeats the snapshotContentHash dedup
	// (builder.go) — the hash differs every build, the reconcile never skips,
	// and the dataplane re-applies the whole screen config on every reconcile
	// (needless control-socket + dataplane work, can re-arm SYN-cookie state).
	// Sorting by zone name (the wire key, == the map key) makes the wire bytes
	// stable so the content hash matches and the reconcile skips (#3962).
	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		zoneNames = append(zoneNames, name)
	}
	sort.Strings(zoneNames)
	for _, name := range zoneNames {
		zone := cfg.Security.Zones[name]
		if zone == nil || zone.ScreenProfile == "" {
			continue
		}
		sp := cfg.Security.Screen[zone.ScreenProfile]
		if sp == nil {
			continue
		}
		snap := ScreenProfileSnapshot{
			Zone:         zone.Name,
			Land:         sp.TCP.Land,
			SynFin:       sp.TCP.SynFin,
			NoFlag:       sp.TCP.NoFlag,
			FinNoAck:     sp.TCP.FinNoAck,
			WinNuke:      sp.TCP.WinNuke,
			PingDeath:    sp.ICMP.PingDeath,
			ICMPFragment: sp.ICMP.Fragment,
			Teardrop:     sp.IP.TearDrop,
			SynFrag:      sp.TCP.SynFrag, // #1137 — port from typed config
			SourceRoute:  sp.IP.SourceRouteOption,
			// Profile-wide audit/log-only modifier. Not a "check" itself —
			// it is intentionally omitted from the emit-gate below, so a
			// profile carrying ONLY alarm-without-drop (no enabled check)
			// does not make the zone enforcing and is not published here.
			// When any check IS enabled it rides along and flips every drop
			// to a log-only alarm.
			//
			// #9425: "is a no-op" was the wrong word and it hid a defect. The
			// zone still lands in the INERT set, where #7888 substitutes
			// `conservative_default()` and DROPS the malformed-packet set —
			// so the modifier was not inert, it was INVERTED. The flag now
			// travels on ScreenInertProfileRefs.AlarmWithoutDrop so the
			// substituted checks still run and alarm instead of dropping.
			AlarmWithoutDrop: sp.AlarmWithoutDrop,
		}
		if sp.ICMP.FloodThreshold > 0 {
			snap.ICMPFloodThreshold = uint32(sp.ICMP.FloodThreshold)
		}
		if sp.UDP.FloodThreshold > 0 {
			snap.UDPFloodThreshold = uint32(sp.UDP.FloodThreshold)
		}
		if sp.TCP.SynFlood != nil && sp.TCP.SynFlood.AttackThreshold > 0 {
			snap.SYNFloodThreshold = uint32(sp.TCP.SynFlood.AttackThreshold)
			snap.SYNCookie = cfg.Security.Flow.SynFloodProtectionMode == "syn-cookie"
			// #3315: carry the SYN-flood sub-thresholds across the wire. The
			// #3024 default guarantees AttackThreshold > 0 whenever a syn-flood
			// screen is enabled, so this block is the single publish gate for
			// every syn-flood control. alarm/source/destination are non-zero only
			// when the operator configured them.
			if sp.TCP.SynFlood.AlarmThreshold > 0 {
				snap.SYNFloodAlarmThreshold = uint32(sp.TCP.SynFlood.AlarmThreshold)
			}
			if sp.TCP.SynFlood.DestinationThreshold > 0 {
				snap.SYNFloodDstThreshold = uint32(sp.TCP.SynFlood.DestinationThreshold)
			}
			if sp.TCP.SynFlood.SourceThreshold > 0 {
				snap.SYNFloodSrcThreshold = uint32(sp.TCP.SynFlood.SourceThreshold)
			}
			// #3527: carry `syn-flood timeout` (seconds) so the dataplane can
			// enforce it as a per-zone override of the half-open session window
			// (tcp_opening_ns). It maps to the session layer, not the screen-rate
			// substrate above; closing the #3315 deferred leaf.
			if sp.TCP.SynFlood.Timeout > 0 {
				snap.SYNFloodTimeout = uint32(sp.TCP.SynFlood.Timeout)
			}
		}
		if sp.LimitSession.SourceIPBased > 0 {
			snap.SessionLimitSrc = uint32(sp.LimitSession.SourceIPBased)
		}
		if sp.LimitSession.DestinationIPBased > 0 {
			snap.SessionLimitDst = uint32(sp.LimitSession.DestinationIPBased)
		}
		if sp.TCP.PortScanThreshold > 0 {
			snap.PortScanThreshold = uint32(sp.TCP.PortScanThreshold)
		}
		if sp.IP.IPSweepThreshold > 0 {
			snap.IPSweepThreshold = uint32(sp.IP.IPSweepThreshold)
		}
		// Only publish profiles that actually enforce something (#7059: this is
		// the SAME predicate the inert-profile surface reports on — see
		// enforcesAnyCheck).
		if snap.enforcesAnyCheck() {
			out = append(out, snap)
		}
	}
	return out
}

// enforcesAnyCheck reports whether this snapshot enables at least one screen
// check, i.e. whether the dataplane will enforce anything for the zone.
//
// It is the EMIT GATE for buildScreenSnapshots and, since #7059, the same
// computation behind the inert-profile observability surface. Those two must
// never disagree: a profile that is published but reported inert (or reported
// enforcing but never published) is a security-control misreport in one
// direction or a false alarm in the other, and BOTH are always bugs. So this is
// single-sourced rather than bound by an agreement test — there is no
// legitimate reason for the two readings to differ, and a shared function
// cannot drift from itself.
//
// Two profile-wide leaves are deliberately NOT counted as checks:
//
//   - AlarmWithoutDrop (`alarm-without-drop`) is a MODIFIER. It changes the
//     disposition of checks that trip from drop to log-only; with no check
//     enabled there is nothing whose disposition it could change, so a profile
//     carrying only this enforces nothing. It is a real Junos knob that commits
//     clean on its own, which makes it the most reachable way to land in the
//     inert state (#7059 reachability path 1).
//   - SYNCookie is read from cfg.Security.Flow.SynFloodProtectionMode, a GLOBAL
//     flow setting rather than a per-profile check. Counting it would make every
//     defined profile on a syn-cookie box look enforcing regardless of its own
//     contents.
//
// The syn-flood SUB-thresholds (alarm/source/destination/timeout) are likewise
// absent, and that is correct rather than an oversight: the compiler defaults
// AttackThreshold to 200 whenever ANY syn-flood leaf is configured, so
// SYNFloodThreshold > 0 already covers every syn-flood shape. Measured, not
// assumed — a profile set only to `syn-flood timeout 30` compiles with
// AttackThreshold 200 and publishes a snapshot.
func (s ScreenProfileSnapshot) enforcesAnyCheck() bool {
	return s.Land || s.SynFin || s.NoFlag || s.FinNoAck ||
		s.WinNuke || s.PingDeath || s.ICMPFragment || s.Teardrop ||
		s.SynFrag || s.SourceRoute ||
		s.ICMPFloodThreshold > 0 || s.UDPFloodThreshold > 0 ||
		s.SYNFloodThreshold > 0 ||
		s.SessionLimitSrc > 0 || s.SessionLimitDst > 0 ||
		s.PortScanThreshold > 0 || s.IPSweepThreshold > 0
}

// ScreenMissingProfileRefs is the EXPORTED single source of truth for "which
// zones claim a screen profile that is not defined" (#5806). It is the same
// function that builds ConfigSnapshot.ScreenMissingProfiles for the dataplane,
// so the Prometheus series, the `show security screen` status line, and the
// dataplane's runtime WARN are all derived from ONE computation and cannot
// disagree about which references are unresolved — the same SSOT discipline
// AddresslessEnforcingZones/Interfaces use for their metrics.
//
// Deriving these observability surfaces from the config is correct rather than a
// desired-vs-applied gap, and the distinction is worth keeping straight: the
// defect this exposes IS a property of the configuration — the config claims a
// screen is attached and none is enforced — so the config is the authoritative
// statement of the unresolved reference. That is the opposite of #6828, where an
// authoritative zero was published from config while a fence was actively
// dropping; there the config was the wrong source, here it is the only correct
// one.
//
// Callers MUST go through this function rather than re-deriving the predicate.
// That is the stated contract, not an implementation convenience: this is the
// same computation that fills ConfigSnapshot.ScreenMissingProfiles. State the
// guarantee that buys with its condition (#6839 round 2): WHENEVER a snapshot has
// been published for the config being rendered, that snapshot's
// ScreenMissingProfiles and every surface reading this function are the same
// function of the same input, so no surface can report a different set than the
// helper was told about. That identity is Go-struct to Go-struct; the helper
// reads JSON, so struct → wire → decoder is a SECOND hop and is NOT part of
// this argument. It is bound separately rather than assumed:
// TestScreenMissingProfilesPublishedToSnapshot
// (screens_ssot_source_5806_test.go) marshals the snapshot and pins the wire key
// `screen_missing_profile_zones` with its `zone`/`profile` elements — the names
// the Rust decoder reads. The unqualified form — "can never report a different
// set" — is false whenever NO snapshot has been published: a config-only /
// degraded boot, which is exactly the case these surfaces exist to cover (this
// PR's own metrics fixture compiles a config with a nil dataplane). There is no
// told-about set to disagree with then, and what the surfaces report is the set
// the helper WOULD be told on the next publish. A re-derived copy would be free
// to drift the moment either side's notion of "unresolved" changes, which is
// what the contract actually prevents, in both cases.
func ScreenMissingProfileRefs(cfg *config.Config) []ScreenMissingProfileRef {
	return buildScreenMissingProfileRefs(cfg)
}

// ScreenUnresolvedDisposition describes what the dataplane CURRENTLY does with a
// zone whose screen profile does not resolve. It is deliberately narrow: the
// screen checks are skipped, and nothing else about the packet's treatment
// changes. An earlier draft said the traffic "is forwarded UNSCREENED", which
// reads as a permit — an operator could take it to mean the firewall is passing
// traffic it would otherwise deny. It is not: zone security policy still
// evaluates the packet normally.
//
// The #5806 tag in the text is load-bearing, NOT decoration. The decision this
// sentence describes lives in the Rust runtime
// (userspace-dp/src/screen/mod.rs returns ScreenVerdict::Pass on the None
// branch) and is NOT derivable from the Go control plane, so this string is a
// hardcoded claim about code that lives somewhere else — precisely the shape
// that goes stale silently when the other side changes. The fail-closed-vs-pass
// posture is an OPEN design decision owned by #5806; when it is settled, a grep
// for 5806 must land on every place that asserts today's behaviour, including
// this one.
// #7888 RE-SHARED the consequence half, which #7168 had split.
//
// The history is worth carrying because it is a single fact moving, not a
// preference oscillating. A shared tail existed originally (#7059) because both
// no-enforcement states had an IDENTICAL consequence and differed only in WHY.
// #7168 gave the UNRESOLVED state a substituted conservative default, so "no
// screen checks are applied" became false for it and true only for the inert
// one — the fact diverged, so the sentences had to. #7888 then settled the same
// posture for the INERT state, on the ground that two configurations with the
// identical consequence must not get different protection, and that the one
// which looks MORE correct to an operator must not get LESS. The fact converged
// again, so the sentences do too.
//
// What must never happen is the two surfaces stating this one fact from two
// literals: the nine substituted check names would then drift the first time
// that set changes. Hence one tail, two prefixes.
const screenSubstitutedDefaultTail = "so " +
	"the dataplane enforces a substituted conservative default for this zone — the " +
	"threshold-free malformed-packet checks only (land, teardrop, winnuke, syn-fin, " +
	"no-flag, fin-no-ack, syn-frag, ping-death, source-route-option), with NO " +
	"flood, scan or session-limit thresholds synthesised; policy evaluation is " +
	"unaffected. The zone is protected but its configured profile is NOT in " +
	"effect, so the reference still needs fixing"

// ScreenUnresolvedDisposition's VALUE is unchanged by the #7888 refactor — it is
// a shipped, documented string and this change re-sources it without editing it.
const ScreenUnresolvedDisposition = "the profile reference does not resolve, " +
	screenSubstitutedDefaultTail + " (#5806 posture, resolved in #7168)"

// ScreenUnresolvedProfileLines renders the operator-facing status block for
// every zone whose configured screen profile does not resolve (#5806). Returns
// nil when every reference resolves, so a caller can append unconditionally.
//
// It exists so the local-CLI and gRPC `show security screen` renderers emit ONE
// wording from ONE predicate — the same no-drift discipline
// config.ScreenEnabledCheckList enforces for the enabled-check inventory. Both
// renderers otherwise early-return "No screen profiles configured" when
// cfg.Security.Screen is empty, which is EXACTLY the tolerant-load shape that
// strands a zone's screen reference: the profile definitions are gone, the zone
// still claims one, and the operator is told there is simply nothing configured.
// Callers must therefore emit these lines BEFORE that early return.
//
// The disposition is ONE trailing line, not a per-zone annotation: it is a
// global statement about the current implementation, identical for every zone,
// so repeating it per row would be noise.
func ScreenUnresolvedProfileLines(cfg *config.Config) []string {
	return ScreenUnresolvedProfileLinesFor(cfg, "")
}

// ScreenUnresolvedProfileLinesFor is ScreenUnresolvedProfileLines restricted to
// the zones referencing ONE profile name (#7060). An empty profileName means
// "every profile", which is what the wide renderers pass — so the narrow
// per-profile command and the wide command render the same sentence for the same
// condition, and a reword lands on both at once. A second hand-written block for
// the narrow command would be a copy that could drift.
func ScreenUnresolvedProfileLinesFor(cfg *config.Config, profileName string) []string {
	refs := screenRefsForProfile(ScreenMissingProfileRefs(cfg), profileName)
	if len(refs) == 0 {
		return nil
	}
	lines := make([]string, 0, len(refs)+2)
	lines = append(lines, "Unresolved screen profile references:")
	for _, r := range refs {
		lines = append(lines,
			fmt.Sprintf("  Zone %s references undefined screen profile '%s' "+
				"— none of its configured checks are in effect; the substituted "+
				"conservative default below applies", r.Zone, r.Profile))
	}
	lines = append(lines, "  Disposition: "+ScreenUnresolvedDisposition+".")
	return lines
}

// CheckScreenUnresolvedRenderOrder enforces the ORDERING half of the
// ScreenUnresolvedProfileLines contract stated above — the block must reach the
// operator BEFORE the empty-inventory line, not after it. It returns nil when
// rendered `show security screen` output satisfies that, and an error naming
// both byte offsets when it does not.
//
// It is ONE check because there is ONE contract. Both renderers ship it
// (pkg/cli/cli_show_security_screen.go and
// pkg/grpcapi/server_show_security_text.go), so a divergence between two
// hand-written guards is always a bug rather than a legitimate difference —
// which is the condition under which single-sourcing beats binding two copies.
// Through #6839 round 2 only the gRPC guard checked order at all: the local-CLI
// guard asserted structure INSIDE the block and never mentioned the
// empty-inventory line, so moving the emit into the early-return branch AFTER
// that line was measured rc=0 on ./pkg/cli/ and rc=0 across all four packages.
//
// The presence check is not redundant with whatever else a caller asserts:
// without it, output carrying NEITHER string compares -1 > -1 and the ordering
// check passes vacuously.
//
// The empty-inventory wording is re-typed here deliberately. An assertion that
// read its expected value out of the renderer it is checking would assert
// nothing; this is an independent statement of what the operator reads, so
// changing either renderer's wording without revisiting this contract fails
// here rather than silently agreeing with itself.
func CheckScreenUnresolvedRenderOrder(out string) error {
	return checkScreenBlockBeforeAnchor(out, "unresolved-reference", ScreenUnresolvedDisposition, ScreenEmptyInventoryLine)
}

// ScreenEmptyInventoryLine and ScreenProfileNotFoundPrefix are the two "nothing
// to show" lines a screen renderer can print. They are the anchors the
// diagnostic blocks must precede: an operator who reads either one FIRST has
// already been told nothing is there, and a correction printed below it is not
// the same signal.
const (
	ScreenEmptyInventoryLine    = "No screen profiles configured"
	ScreenProfileNotFoundPrefix = "Screen profile '"
)

// CheckScreenInertRenderOrder is CheckScreenUnresolvedRenderOrder for the #7059
// inert block.
func CheckScreenInertRenderOrder(out string) error {
	return checkScreenBlockBeforeAnchor(out, "inert-profile", ScreenInertDisposition, ScreenEmptyInventoryLine)
}

// CheckScreenDiagnosticRenderOrderBefore asserts the ordering for whichever of
// the two diagnostic blocks are PRESENT in out, against a caller-supplied anchor
// (#7060). The per-profile renderers print "Screen profile '<name>' not found"
// rather than the empty-inventory line, so they need the same contract with a
// different anchor — and extending this single-sourced check is what stops a
// third hand-written ordering assertion being written for them.
//
// Unlike the two functions above it does NOT require a block to be present: a
// caller rendering a profile that is perfectly healthy has neither block, and
// that is not an ordering violation. It DOES require the anchor, so a test that
// forgets to drive the anchor path fails loudly instead of passing vacuously.
func CheckScreenDiagnosticRenderOrderBefore(out, anchor string) error {
	anchorIdx := strings.Index(out, anchor)
	if anchorIdx < 0 {
		return fmt.Errorf("the anchor %q is absent, so this ordering check would pass "+
			"vacuously; rendered output:\n%s", anchor, out)
	}
	for _, d := range []struct{ name, disposition string }{
		{"unresolved-reference", ScreenUnresolvedDisposition},
		{"inert-profile", ScreenInertDisposition},
	} {
		idx := strings.Index(out, d.disposition)
		if idx < 0 {
			continue // that condition does not hold for this config
		}
		if idx > anchorIdx {
			return fmt.Errorf("the %s block must be rendered BEFORE %q (block at byte "+
				"%d, anchor at byte %d). An operator who reads the anchor first has "+
				"already been told nothing is there; a correction printed below it is "+
				"not the same signal. Containment assertions alone cannot see this — "+
				"they stay green with the emit moved after the line; rendered "+
				"output:\n%s", d.name, anchor, idx, anchorIdx, out)
		}
	}
	return nil
}

// checkScreenBlockBeforeAnchor is the shared body of the two exported
// require-both-present ordering checks. blockName is threaded through so the
// inert caller does not report an "unresolved-reference" violation — a
// diagnostic that names the wrong condition sends the reader to the wrong code.
func checkScreenBlockBeforeAnchor(out, blockName, disposition, emptyInventory string) error {
	blockIdx := strings.Index(out, disposition)
	emptyIdx := strings.Index(out, emptyInventory)
	if blockIdx < 0 || emptyIdx < 0 {
		return fmt.Errorf("both the %s disposition and %q must be "+
			"present for the ordering check to mean anything (disposition at byte %d, "+
			"empty-inventory line at byte %d); rendered output:\n%s",
			blockName, emptyInventory, blockIdx, emptyIdx, out)
	}
	if blockIdx > emptyIdx {
		return fmt.Errorf("the %s block must be rendered BEFORE %q "+
			"(disposition at byte %d, empty-inventory line at byte %d). An operator who "+
			"reads the empty-inventory line first has already been told nothing was "+
			"configured; a correction printed below it is not the same signal. "+
			"Containment assertions alone cannot see this — they stay green with the "+
			"emit moved after the line; rendered output:\n%s",
			blockName, emptyInventory, blockIdx, emptyIdx, out)
	}
	return nil
}

// buildScreenMissingProfileRefs records every zone that REFERENCES a screen
// profile which is NOT defined in the config (#3082). buildScreenSnapshots
// silently skips these zones (`sp == nil`), so without this the dataplane
// cannot tell "zone has no screen configured" (legit Pass) apart from "zone
// references a MISSING screen" (error → should signal). Reachable on the
// lenient/HA-sync path where a dangling screen reference loads with only an
// apply-time warning. The dataplane uses this to emit a rate-limited runtime
// WARN; the verdict stays Pass (the fail-closed posture is deferred).
//
// #5806: exported through ScreenMissingProfileRefs so the observability
// surfaces share this computation instead of re-deriving the predicate.
func buildScreenMissingProfileRefs(cfg *config.Config) []ScreenMissingProfileRef {
	if cfg == nil || len(cfg.Security.Zones) == 0 {
		return nil
	}
	var out []ScreenMissingProfileRef
	// Same determinism requirement as buildScreenSnapshots (#3962): this slice
	// is carried in ConfigSnapshot.ScreenMissingProfiles and so feeds the
	// snapshotContentHash dedup. Ranging the zones map directly would shift the
	// wire byte order build-to-build. Sort by zone name for a stable order.
	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		zoneNames = append(zoneNames, name)
	}
	sort.Strings(zoneNames)
	for _, name := range zoneNames {
		zone := cfg.Security.Zones[name]
		if zone == nil || zone.ScreenProfile == "" {
			// No screen configured for this zone — legit Pass, not a
			// missing reference.
			continue
		}
		if cfg.Security.Screen[zone.ScreenProfile] != nil {
			// Reference resolves to a defined profile.
			continue
		}
		// The loop iterates sorted map KEYS but labels with zone.Name. Those are
		// two different expressions, and the divergence was raised and REFUTED in
		// #6839 round 1 — recorded here so it is not re-raised, and so that if the
		// premise ever stops holding the reader is standing on the line that
		// breaks.
		//
		// What would happen if they diverged: two zones whose Name collapsed to
		// one value would emit the SAME {zone, profile} label pair, Prometheus
		// would reject the duplicate const-metric, and the collector error takes
		// the WHOLE /metrics endpoint to 500 — every series, not just this one.
		// That outcome is real and was reproduced mechanically by hand-building
		// the struct.
		//
		// Why it is unreachable, verified rather than assumed: compileZones is the
		// only constructor (compiler_security_zones.go) and it writes
		// `zone = &ZoneConfig{Name: inst.name}` immediately followed by
		// `sec.Zones[inst.name] = zone` — one variable, both places. No
		// deserialization path bypasses it: active.json holds the AST
		// (json.Unmarshal into ConfigTree, configstore/envelope.go + db.go) and
		// Store.Load recompiles it, and the HA peer-sync ingress likewise goes
		// through compileTreeLenient. So Name == key holds for every Config any
		// production path can produce, and switching this to `name` would change
		// nothing observable. Left as zone.Name deliberately: it says what the
		// label MEANS.
		out = append(out, ScreenMissingProfileRef{
			Zone:    zone.Name,
			Profile: zone.ScreenProfile,
		})
	}
	return out
}

// synCookieEpochSecs mirrors SynCookieCodec::EPOCH_SECS in userspace-dp: the
// cookie epoch every minted ISN carries.
const synCookieEpochSecs = 64

// synCookieKeyPeriodSecs is the SYN-cookie key rotation period (#9173): just
// under an hour, and a whole number of cookie epochs, so each cookie's own epoch
// names exactly one rotation period. The helper fails closed a ring whose period
// is not such a multiple.
const synCookieKeyPeriodSecs = 56 * synCookieEpochSecs

// synCookieNow is the clock the SYN-cookie keys are built from; tests replace it.
var synCookieNow = time.Now

// synCookieProcessSecret is the random secret a node with no chassis cluster
// authentication-key derives its SYN-cookie keys from (#9173). It is drawn once
// per daemon start and never persisted, so that node's key changes across a
// restart. A keyed cluster deliberately does not use it, so its nodes can
// validate each other's cookies after a failover; docs/syn-cookie-flood-protection.md
// ("When two nodes agree") lists what else that takes.
var synCookieProcessSecret = sync.OnceValue(newSynCookieProcessSecret)

func newSynCookieProcessSecret() []byte {
	secret := make([]byte, 32)
	// Since Go 1.24 crypto/rand.Read never returns an error; it aborts the
	// process instead, so the secret is never silently left zero.
	_, _ = rand.Read(secret)
	return secret
}

// synCookieDigestSalt keys the fingerprints that stand in for SYN-cookie keys
// inside snapshotContentHash (#9173). Drawn once per daemon start and never
// persisted.
var synCookieDigestSalt = sync.OnceValue(newSynCookieProcessSecret)

// synCookieDigestFingerprint replaces a hex key with an HMAC of it under the
// per-start digest salt. An empty key stays empty.
func synCookieDigestFingerprint(key string) string {
	if key == "" {
		return ""
	}
	mac := hmac.New(sha256.New, synCookieDigestSalt())
	mac.Write([]byte("xpf-syncookie-digest\x00"))
	mac.Write([]byte(key))
	return hex.EncodeToString(mac.Sum(nil))
}

// synCookieRingDigestFingerprint copies ring with every base fingerprinted. The
// period and accept-only marks are not secret and are kept.
func synCookieRingDigestFingerprint(ring *SYNCookieKeyRingSnapshot) *SYNCookieKeyRingSnapshot {
	if ring == nil {
		return nil
	}
	out := &SYNCookieKeyRingSnapshot{PeriodSecs: ring.PeriodSecs, Bases: make([]SYNCookieKeyBaseSnapshot, len(ring.Bases))}
	for i, b := range ring.Bases {
		b.Base = synCookieDigestFingerprint(b.Base)
		out.Bases[i] = b
	}
	return out
}

// buildSYNCookieKeys derives the snapshot's SYN-cookie key material (#9173).
//
// A BASE is HMAC-SHA256 over a domain label, the cluster identity and the
// screened zones. A keyed cluster keys it with `chassis cluster
// authentication-key`; anything else uses synCookieProcessSecret. A period's key
// is HMAC-SHA256 of the base over a second label and the rotation epoch (unix
// seconds / synCookieKeyPeriodSecs), truncated to 16 bytes: deriveSYNCookieEpochKey
// here, and SynCookieKeyRing in the helper, which derives every period's key
// itself. Keys therefore rotate on the wall clock with no control-plane
// republish, and two nodes holding one base derive the same key for the same
// period (which nodes hold one: docs/syn-cookie-flood-protection.md, "When two
// nodes agree").
//
// None of it is a function of the root password verifier. On a keyed cluster a
// base, and every key derived from it, is still an offline check on guesses at
// the authentication-key, so it is only as strong as that key's entropy. Every
// base must stay secret: skip_serializing on the helper wire, redacted in Debug,
// and only a salted HMAC of it in the #9520 content digest.
//
// The first result is now's period key. It keeps the meaning
// syn_cookie_master_key always had -- the key to mint and validate with -- so an
// older helper that ignores the ring still works, on the key of the period its
// last full snapshot was built in. The ring holds the primary base, plus an
// accept-only base derived from `additional-authentication-key` while a #6630
// PSK rotation window is open.
func buildSYNCookieKeys(cfg *config.Config, now time.Time) (string, *SYNCookieKeyRingSnapshot) {
	if !userspaceSynCookieProtectionActive(cfg) {
		return "", nil
	}
	zones := synCookieScreenedZones(cfg)
	if len(zones) == 0 {
		return "", nil
	}
	primary, additional, identity := synCookieKeyMaterial(cfg)
	primaryBase := deriveSYNCookieBase(primary, identity, zones)
	ring := &SYNCookieKeyRingSnapshot{
		PeriodSecs: synCookieKeyPeriodSecs,
		Bases:      []SYNCookieKeyBaseSnapshot{{Base: hex.EncodeToString(primaryBase)}},
	}
	if len(additional) > 0 {
		ring.Bases = append(ring.Bases, SYNCookieKeyBaseSnapshot{
			Base:       hex.EncodeToString(deriveSYNCookieBase(additional, identity, zones)),
			AcceptOnly: true,
		})
	}
	return deriveSYNCookieEpochKey(primaryBase, synCookieRotationEpoch(now)), ring
}

// synCookieKeyMaterial returns the secret to mint with, a secret whose cookies
// are also accepted (nil outside a #6630 rotation window), and the identity mixed
// into the derivation.
func synCookieKeyMaterial(cfg *config.Config) (primary, additional []byte, identity string) {
	cluster := cfg.Chassis.Cluster
	if cluster == nil {
		return synCookieProcessSecret(), nil, "standalone"
	}
	identity = fmt.Sprintf("cluster-id=%d", cluster.ClusterID)
	// Emptiness is tested the way the control channel tests it (len > 0), so a
	// node keys its cookies from the PSK exactly when its heartbeats are keyed.
	// The additional key follows the heartbeat's #6630 widening as an accept-only
	// base: it validates and never mints. Whether that lets two nodes validate
	// each other's cookies is docs/syn-cookie-flood-protection.md, "When two nodes
	// agree".
	key := cluster.ControlLinkAuthKey.Reveal()
	if key == "" {
		// An unkeyed cluster (the lenient load path; the strict commit gate
		// refuses one) has no shared secret, so its cookies do not survive a
		// failover. Config validation warns.
		return synCookieProcessSecret(), nil, identity
	}
	if alt := cluster.ControlLinkAuthKeyAlt.Reveal(); alt != "" {
		additional = []byte(alt)
	}
	return []byte(key), additional, identity
}

func synCookieRotationEpoch(now time.Time) uint64 {
	secs := now.Unix()
	if secs < 0 {
		return 0
	}
	return uint64(secs) / synCookieKeyPeriodSecs
}

// deriveSYNCookieBase is the base every period's key derives from: one per keyed
// cluster, or one per daemon start. Every variable-length field is
// length-prefixed, so no identity or zone/profile name -- a quoted identifier may
// contain a NUL -- can frame the same bytes as a different screened-zone set.
func deriveSYNCookieBase(secret []byte, identity string, zones [][2]string) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("xpf-syncookie\x00v3-base\x00"))
	var n [4]byte
	field := func(s string) {
		binary.BigEndian.PutUint32(n[:], uint32(len(s)))
		mac.Write(n[:])
		mac.Write([]byte(s))
	}
	field(identity)
	binary.BigEndian.PutUint32(n[:], uint32(len(zones)))
	mac.Write(n[:])
	for _, zone := range zones {
		field(zone[0])
		field(zone[1])
	}
	return mac.Sum(nil)
}

// deriveSYNCookieEpochKey is one rotation epoch's key, as 32 hex characters.
// userspace-dp's SynCookieKeyRing derives the same bytes; the known-answer
// vector in TestSYNCookieEpochKeyMatchesTheHelper9173 and its Rust twin pins
// both.
func deriveSYNCookieEpochKey(base []byte, epoch uint64) string {
	mac := hmac.New(sha256.New, base)
	mac.Write([]byte("xpf-syncookie\x00v3-epoch\x00"))
	var epochBytes [8]byte
	binary.BigEndian.PutUint64(epochBytes[:], epoch)
	mac.Write(epochBytes[:])
	return hex.EncodeToString(mac.Sum(nil)[:16])
}

// synCookieScreenedZones lists (zone, profile) for every zone whose screen profile
// has a SYN-flood attack threshold, sorted so the key is deterministic.
func synCookieScreenedZones(cfg *config.Config) [][2]string {
	var zones [][2]string
	for _, zone := range cfg.Security.Zones {
		if zone == nil || zone.ScreenProfile == "" {
			continue
		}
		profile := cfg.Security.Screen[zone.ScreenProfile]
		if profile == nil || profile.TCP.SynFlood == nil ||
			profile.TCP.SynFlood.AttackThreshold <= 0 {
			continue
		}
		zones = append(zones, [2]string{zone.Name, zone.ScreenProfile})
	}
	sort.Slice(zones, func(i, j int) bool {
		if zones[i][0] != zones[j][0] {
			return zones[i][0] < zones[j][0]
		}
		return zones[i][1] < zones[j][1]
	})
	return zones
}

func userspaceSynCookieProtectionActive(cfg *config.Config) bool {
	if cfg == nil || cfg.Security.Flow.SynFloodProtectionMode != "syn-cookie" {
		return false
	}
	for _, zone := range cfg.Security.Zones {
		if zone == nil || zone.ScreenProfile == "" {
			continue
		}
		profile := cfg.Security.Screen[zone.ScreenProfile]
		if profile != nil && profile.TCP.SynFlood != nil &&
			profile.TCP.SynFlood.AttackThreshold > 0 {
			return true
		}
	}
	return false
}

// ScreenInertDisposition describes what the dataplane does with a zone whose
// screen profile is DEFINED but enables no checks (#7059). Worded distinctly
// from ScreenUnresolvedDisposition on purpose: the reference resolves, so
// telling an operator it "does not resolve" would send them looking for a
// missing definition that is in fact present.
//
// #7888 changed the CONSEQUENCE half. This used to end "so no screen checks are
// applied to this zone ... pending the #5806 enforcement-posture decision", and
// both halves of that are now false: the dataplane enforces the substituted
// conservative default for this zone, and the posture is no longer pending. A
// surface left asserting the old sentence would be telling an operator that a
// zone is unprotected while the dataplane drops LAND and teardrop on it — the
// same class of false statement about enforcement that #7059 and #7888 exist to
// remove, just pointing the other way.
const ScreenInertDisposition = "the profile is defined but enables no checks, " +
	screenSubstitutedDefaultTail + " (#7059 posture, resolved in #7888)"

// ScreenInertProfileRefs is the EXPORTED single source of truth for "which zones
// resolve to a screen profile that enforces NOTHING" (#7059).
//
// This is the third state, and the one every #5806 surface previously reported
// as healthy. A zone's screen reference has three outcomes, not two:
//
//  1. The profile is not defined — ScreenMissingProfileRefs. Strict commit
//     REJECTS this, so it is reachable only through the tolerant paths (HA
//     config-sync from a schema-skewed peer, tolerant load of an older or
//     externally modified active.json).
//  2. The profile IS defined and enables no check — this function. The
//     dataplane publishes no snapshot for the zone, ScreenState::zones has no
//     entry, and check_packet_with_zone_id takes the None branch. Nothing is
//     enforced. Critically this passes STRICT commit with zero warnings, which
//     makes it strictly more reachable than case 1.
//  3. The profile is defined and enables at least one check — enforcing, and
//     reported by neither surface.
//
// Before #7059 states 2 and 3 rendered identically: `show security screen`
// printed the profile with its zone list and no indication that the check
// inventory was empty, the metric was absent, and the dataplane's runtime WARN
// was silent too (the zone is not in the missing-profile set). An operator
// reading any of the three surfaces saw a screened zone. That is a check failing
// to a value INDISTINGUISHABLE FROM HEALTHY — the same class as an unbound CoS
// rewrite rule printing "Enforced: yes", which cosRewriteRuleEnforcement exists
// to prevent.
//
// The membership test is deliberately "did the real publisher emit a snapshot
// for this zone", not a re-derivation of the emit gate. buildScreenSnapshots IS
// the authority on what the dataplane will enforce, so asking it directly means
// this surface cannot drift from the thing it describes — including for reasons
// that are not the gate at all, such as the len(cfg.Security.Screen) == 0 early
// return. A copy of the gate predicate could disagree; a call to the publisher
// cannot.
func ScreenInertProfileRefs(cfg *config.Config) []ScreenMissingProfileRef {
	return buildScreenInertProfileRefs(cfg)
}

func buildScreenInertProfileRefs(cfg *config.Config) []ScreenMissingProfileRef {
	if cfg == nil || len(cfg.Security.Zones) == 0 {
		return nil
	}
	// What the dataplane will actually enforce, from the authority itself.
	published := make(map[string]struct{})
	for _, snap := range buildScreenSnapshots(cfg) {
		published[snap.Zone] = struct{}{}
	}
	// Same determinism requirement as buildScreenSnapshots (#3962) — this feeds
	// a wire field and the snapshotContentHash dedup, so the order must be
	// stable build-to-build.
	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		zoneNames = append(zoneNames, name)
	}
	sort.Strings(zoneNames)
	var out []ScreenMissingProfileRef
	for _, name := range zoneNames {
		zone := cfg.Security.Zones[name]
		if zone == nil || zone.ScreenProfile == "" {
			continue // no screen configured — legit Pass, not a finding
		}
		if cfg.Security.Screen[zone.ScreenProfile] == nil {
			continue // UNDEFINED — that is ScreenMissingProfileRefs' surface, not this one
		}
		if _, ok := published[zone.Name]; ok {
			continue // defined AND enforcing at least one check
		}
		out = append(out, ScreenMissingProfileRef{
			Zone:    zone.Name,
			Profile: zone.ScreenProfile,
			// #9425: carry the operator's audit request. The profile is
			// DEFINED here (the undefined case returned above), so this is a
			// statement the operator actually wrote, and it is the only route
			// by which the dataplane can honour it — an inert zone has no
			// `screens` entry for the resolved lookup to find.
			AlarmWithoutDrop: cfg.Security.Screen[zone.ScreenProfile].AlarmWithoutDrop,
		})
	}
	return out
}

// ScreenInertProfileLines renders the operator-facing block for the inert
// profiles, mirroring ScreenUnresolvedProfileLines' shape so the two read as
// siblings. The profile name is QUOTED for the same reason the CoS dangling
// reference is: a bare "enables no checks" reads as "you forgot to configure
// it" to an operator who did configure it — just with everything under a knob
// that turns out to be a modifier rather than a check.
func ScreenInertProfileLines(cfg *config.Config) []string {
	return ScreenInertProfileLinesFor(cfg, "")
}

// ScreenInertProfileLinesFor is ScreenInertProfileLines restricted to one
// profile name (#7060); an empty profileName means every profile.
func ScreenInertProfileLinesFor(cfg *config.Config, profileName string) []string {
	refs := screenRefsForProfile(ScreenInertProfileRefs(cfg), profileName)
	if len(refs) == 0 {
		return nil
	}
	lines := make([]string, 0, len(refs)+2)
	lines = append(lines, "Screen profiles enforcing nothing:")
	for _, r := range refs {
		lines = append(lines,
			fmt.Sprintf("  Zone %s references screen profile '%s', which is defined but "+
				"enables no checks — none of its configured checks are in effect; the "+
				"substituted conservative default below applies", r.Zone, r.Profile))
	}
	lines = append(lines, "  Disposition: "+ScreenInertDisposition+".")
	return lines
}

// screenRefsForProfile filters refs to those naming profileName. An empty
// profileName is the identity filter ("all profiles"), so the wide renderers and
// the per-profile renderers share one code path rather than one of them growing
// a second copy of the wording.
func screenRefsForProfile(refs []ScreenMissingProfileRef, profileName string) []ScreenMissingProfileRef {
	if profileName == "" {
		return refs
	}
	var out []ScreenMissingProfileRef
	for _, r := range refs {
		if r.Profile == profileName {
			out = append(out, r)
		}
	}
	return out
}
