package dataplane

// #4960: validate-before-mutate pre-pass.
//
// CompileConfig runs at APPLY time, after the commit has already succeeded --
// `pkg/configstore` has zero imports of `pkg/dataplane`, so `commit check`
// validates only the pure `pkg/config.CompileConfig` and never reaches this
// one (the two share a name, which is much of why this reads as safer than it
// is). Phase 2 `compileZones` then performs the FIRST and ONLY destructive host
// netlink mutation in the whole function -- `ensureVLANSubInterface` creates and
// links up VLAN devices, `reconcileInterfaceAddresses` deletes and adds
// addresses -- and every later phase is a bare `return nil, err` with no undo
// path. An input that passes config-compile and trips a later phase therefore
// leaves VLANs created and addresses reconciled on the live host, the control
// plane reporting failure, and the dataplane on the old snapshot. The codebase
// documents such an input class itself at `userspace/flow.go`: a malformed
// application-set reference or an app_id-space overflow (#3438 H4) makes
// compileApplications -- Phase 4 -- "hard-error and abort the apply".
//
// This pre-pass runs the fallible HOST-PURE phases against a discarding
// dataplane BEFORE compileZones touches the host, so those failures are
// returned with nothing mutated.
//
// It is deliberately ADDITIVE rather than a reordering. Moving the real phases
// ahead of compileZones would be a silent fail-open: compileFirewallFilters and
// compilePortMirroring resolve VLAN SUB-INTERFACE names that exist only because
// Phase 2 created them, and a miss there is `slog.Warn(...); continue` -- so a
// reorder would leave firewall filters unassigned on every apply, trading a
// loud post-mutation abort for a quiet security fail-open. Every existing call
// keeps its current position and preconditions; the only new behaviour is an
// early abort.
//
// Scope: this is NOT the apply-transaction redesign. Making the Go and Rust
// planes re-converge on a dataplane NACK is a separate half of #4960, tracked
// on `research/4960-apply-txn` (twice PLAN-NEEDS-MAJOR). That work is about
// what happens AFTER the dataplane is asked; this is about not wrecking the
// host BEFORE it is asked. The host-netlink purity this relies on is
// independently derived in that plan's section 4.4.
//
// That scope line has a STATED boundary, because "before the dataplane is
// asked" is not the same as "before the apply can still fail". Three fallible
// steps run AFTER compileZones has mutated the host and BEFORE the new
// snapshot is published, so by the line above they belong to THIS half, and
// none of them is covered here (#6894 r2 F2):
//
//   - `preflightCheckIfindexCaps` (loader.go, #5836). It CANNOT be hoisted:
//     it consumes `result.pendingXDP`, which only compileZones populates. Its
//     input does not exist until the mutation has already happened, so closing
//     it needs the ifindex set derived without the host pass -- a different
//     change, not an extra row in the table below.
//   - `attachUserspaceShimXDP` (loader.go), whose tail returns
//     `attach userspace XDP shim generic to ifindex %d`. This is the REACHABLE
//     one: an ordinary XDP attach failure on a driver that rejects a generic
//     attach leaves VLANs created and addresses reconciled while the apply
//     reports failure -- exactly the #4960 shape, on a path this pre-pass does
//     not defend.
//   - `buildSnapshotWithSchedulerStateAndNATCounters`
//     (userspace/manager_compile.go), whose builders return errors (#2514,
//     #3438, #3772). The #3438 address-book case specifically IS caught
//     earlier, by `compileApplications` (the `applications` row below), which is why the
//     headline example above holds; the builder family as a whole is not.
//
// So the guarantee this file provides is bounded to the phases in
// validationPhases. A failure in any of the three above still lands
// post-mutation.
//
// A FOURTH class is worth stating separately, because it is not "a phase we do
// not run" but "a phase we DO run that was not strict enough" (#6894 r9 F1).
// A covered row that ACCEPTS what the Rust helper later REJECTS reproduces the
// exact #4960 shape from inside the guard: the helper's rejection lands in
// publishSnapshotFailClosedLocked, after compileZones has mutated the host.
// NPTv6 was such a row. `Match = "2001:db8:9::/48"` with `Then =
// "not-a-prefix"` is retained by lenient validation with a warning, warned-and-
// skipped by compileNPTv6, copied verbatim into the snapshot, and then rejected
// WHOLE by Nptv6State::try_from_snapshots (userspace-dp/src/nptv6.rs,
// #2240/#4519). compileNPTv6 now returns an error for the parse class the
// HELPER REFUSES, so the same certain failure happens before the mutation
// rather than after it. THREE properties keep that from over-rejecting, and
// all three matter:
//
//   - It fires only for rules that actually REACH the helper. The snapshot
//     builder drops a rule carrying an unsupported match scope (#5818), and
//     today's apply succeeds without it, so those keep warn-and-skip.
//     `config.NPTv6ScopeUnsupported` is the shared predicate; the builder and
//     this compiler read the same answer.
//
//   - It fires only for rules the helper actually REFUSES, which is NOT the
//     same as "Go cannot parse it" and cost a regression to learn (#7077).
//     Rust's parse_prefix parses the mask with u8::from_str, which takes a
//     leading `+`; Go's net.ParseCIDR does not. So `fd00:9::/+48` is a Go parse
//     error and a helper ACCEPT -- today's apply succeeds and installs the
//     translation -- and hard-erroring on it failed an apply that works, on the
//     tolerant-load / peer-sync path #1960 exists to keep booting.
//     `nptv6HelperWouldInstall` (compiler_nptv6_helper_grammar.go) mirrors the
//     helper's grammar so that class keeps warn-and-skip. Note this could NOT
//     have been discriminated as "strict vs lenient" instead: validateNPTv6Strict
//     rejects EVERY malformed class at commit, so a malformed rule only ever
//     arrives here from the lenient path and "warn when lenient" would be a
//     full revert.
//   - It cannot brick a boot or a peer sync, and the reason is STRUCTURAL
//     rather than a property of today's call sites. pkg/dataplane is not in
//     pkg/configstore's dependency closure at all -- not merely un-imported
//     directly, but unreachable through any intermediate package -- so no
//     tolerant load (Store.Load) or HA peer sync (Store.SyncApply) can enter
//     this pre-pass. They compile through pkg/config.compileTreeLenient, the
//     config still loads with the lenient warning validateNPTv6Strict emits,
//     and only the dataplane apply fails -- which already failed at publish
//     before this change.
//
//     Stated as an import closure deliberately: a call trace answers "is this
//     reached today", which one new call site invalidates silently, while the
//     closure answers "is this expressible at all", which cannot change without
//     a visible new dependency edge. Re-verify with
//
//     go list -deps       ./pkg/configstore | grep -c psaab/xpf/pkg/dataplane
//     go list -deps -test ./pkg/configstore | grep -c psaab/xpf/pkg/dataplane
//
//     Both must be 0 (the -test variant matters: a _test.go import is a real
//     edge for this purpose). Run the POSITIVE CONTROL alongside them or the
//     zeros prove nothing -- a broken query, a wrong module path or a swallowed
//     build failure also prints 0:
//
//     go list -deps ./pkg/daemon | grep -c psaab/xpf/pkg/dataplane
//
//     which must be NON-ZERO, because pkg/daemon genuinely does depend on the
//     dataplane. The exact count is deliberately not written here; this file
//     already carries one lesson about a number stated in a comment going stale
//     (see the "ONE such error" note in validationPhases below). Non-zero is
//     the property that makes the query trustworthy; the value is not.
//
// RESIDUAL, named rather than papered over: the helper ALSO rejects overlapping
// NPTv6 prefixes (#2241), partitioned by zone scope (#5176). That partitioning
// is not replicated here. Replicating it coarsely — as validateNPTv6Strict's
// commit-time overlap check does, which does not partition — would reject
// configs the helper ACCEPTS, turning a post-mutation failure into a failed
// apply for a working config. An overlap therefore still lands post-mutation.

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
)

// discardingDataPlane satisfies DataPlane for the validation pre-pass. It
// embeds the interface and overrides only the methods the validated phases
// actually call.
//
// This is a deliberate INVERSION of the LegacyDataPlaneAdapter pattern, not the
// same thing (#6894 r1 F5): that adapter embeds a NON-nil DataPlane
// (legacy_dataplane.go sets adapter.DataPlane = the shim manager) and delegates
// everything it does not override. This one leaves the embedded interface NIL,
// so an un-overridden method panics rather than silently succeeding against a
// real dataplane -- the pre-pass must never write.
//
// The panic is the desired failure mode but is NOT compile-time enforced: the
// override set is complete for today's call graph, and a newly added,
// CONDITIONALLY reached dp.X() inside a validated phase would ship green and
// panic in production (the only recover() on the apply path is scoped to
// host-auth closeout). TestPrePassShimCoversTheCalledSurface_4960 is what
// enforces it -- it drives the pre-pass over a config reaching every covered
// phase, so a new call surfaces as a test panic. Widen its fixture,
// idProbeConfig, when adding a phase.
//
// "Reaching every covered phase" was not enough, and that is worth stating
// because it took two rounds to notice (#6894 r3 F1). A phase can be entered
// and still leave its WRITE SURFACE untouched: at r2 the fixture reached every
// phase but only 28 of the 40 overrides, and nine -- the destination-NAT,
// static-NAT, NPTv6, NAT64, v6-pool/v6-SNAT and SNAT-egress writes -- were
// called by no test in the package. Any one of them could be deleted with the
// whole suite green, while an ordinary `security nat destination` stanza
// nil-panicked the daemon on apply. idProbeConfig was widened to close that,
// and it is still what keeps this shim honest. Adding an override without a
// config shape that REACHES it re-opens the same hole.
//
// #6420 changed WHICH of these overrides can still be reached, and the count is
// deliberately not restated here because it is the part that rots. The NAT
// record construction in compiler_nat.go was deleted -- every one of those
// writes was a `return nil` on the production shim -- so the NAT setters and
// stale-NAT deleters below are no longer called by any phase and their
// overrides are now DEFENSIVE. They are kept, not deleted, because retiring the
// DataPlane NAT interface surface itself (maps_nat.go and the two shims) is the
// sibling cleanup, and a shim that stops overriding a method the interface
// still declares would promote a future caller to the retired eBPF writer.
// TestNATCompilerCallsNoDataplaneNATWriter_6420 is what asserts they stay
// uncalled: it arms each one to FAIL and requires the pre-pass to validate
// clean.
type discardingDataPlane struct{ DataPlane }

func (discardingDataPlane) IsLoaded() bool                                                { return true }
func (discardingDataPlane) SetZonePairPolicy(fromZone, toZone uint16, ps PolicySet) error { return nil }
func (discardingDataPlane) SetPolicyRule(policySetID uint32, ruleIndex uint32, rule PolicyRule) error {
	return nil
}
func (discardingDataPlane) SetDefaultPolicy(action uint8) error                     { return nil }
func (discardingDataPlane) SetAddressBookEntry(cidr string, addressID uint32) error { return nil }
func (discardingDataPlane) SetAddressMembership(resolvedID, setID uint32) error     { return nil }
func (discardingDataPlane) ClearAddressBookV4() error                               { return nil }
func (discardingDataPlane) ClearAddressBookV6() error                               { return nil }
func (discardingDataPlane) ClearAddressMembership() error                           { return nil }
func (discardingDataPlane) SetApplication(protocol uint8, dstPort uint16, appID uint32, timeout uint32, algType uint8, srcPortLow, srcPortHigh uint16) error {
	return nil
}
func (discardingDataPlane) SetAppRange(index uint32, entry AppRangeEntry) error { return nil }
func (discardingDataPlane) SetDNATEntry(key DNATKey, val DNATValue) error       { return nil }
func (discardingDataPlane) SetDNATEntryV6(key DNATKeyV6, val DNATValueV6) error { return nil }

func (discardingDataPlane) SetScreenConfig(profileID uint32, cfg ScreenConfig) error { return nil }
func (discardingDataPlane) SetFlowTimeout(idx, seconds uint32) error                 { return nil }
func (discardingDataPlane) SetFlowConfig(cfg FlowConfigValue) error                  { return nil }
func (discardingDataPlane) DeleteStaleZonePairPolicies(written map[ZonePairKey]bool) {}
func (discardingDataPlane) DeleteStaleApplications(written map[AppKey]bool)          {}

func (discardingDataPlane) DeleteStaleDNATStatic(written map[DNATKey]bool)     {}
func (discardingDataPlane) DeleteStaleDNATStaticV6(written map[DNATKeyV6]bool) {}
func (discardingDataPlane) DeleteStaleStaticNAT(writtenV4 map[StaticNATKeyV4]bool, writtenV6 map[StaticNATKeyV6]bool) {
}
func (discardingDataPlane) ZeroStaleScreenConfigs(maxID uint32) {}
func (discardingDataPlane) GetPersistentNAT() *PersistentNATTable {
	var z *PersistentNATTable
	return z
}

// validateBeforeMutate runs every fallible HOST-PURE compile phase against a
// discarding dataplane, so a config that trips one of them is rejected before
// Phase 2 mutates the host. It writes nothing: the CompileResult it builds is
// local and discarded, and every dataplane call lands on discardingDataPlane.
//
// COVERAGE, stated precisely because the gap is deliberate. The table below is
// the authority on what is covered; do not restate its size in prose -- the
// count is the part that rots, and it has already gone stale once here.
// `TestValidationPhaseTableMatchesDocumentedCoverage_4960` pins the table's
// length AND its name order, so a row added or removed without updating this
// comment reds.
//
// What is EXCLUDED, which is the part worth stating: `compilePortMirroring`
// entirely, and all of `compileFirewallFilters` EXCEPT its cfg-pure prefix
// `validateFilterProtocols` (hoisted in as its own row -- see below). Both
// resolve VLAN sub-interface names through `result.cachedInterfaceByName`, and
// those devices do not exist until Phase 2 creates them. Running them here would
// evaluate a different world than the real pass -- every lookup would miss and
// take the `slog.Warn(...); continue` soft skip -- so the pre-pass would emit
// misleading warnings on every successful commit and would still not faithfully
// predict the real run. A hard failure inside that excluded remainder therefore
// still occurs post-mutation; that residual is named rather than papered over,
// and closing it needs the interface-resolution soft skips addressed first
//
// One more site sits outside BOTH the table and the exclusion prose above:
// the post-recompile FIB generation bump (compiler.go ->
// bumpFIBGenerationAfterRecompile, compiler_fibgen.go). It is listed here only
// so a reader auditing coverage does not have to rediscover that it is neither
// covered nor an omission -- it cannot produce a returned CompileConfig error,
// so it is out of scope by construction rather than by choice
// (#6893).
//
// Do not read that as "so the error does not matter" -- an earlier revision of
// this paragraph said the caller "deliberately discards" it under a
// fire-and-forget contract, and that was the justification for a real defect
// (#7149). Out of scope FOR THE PRE-PASS is not the same as harmless: the bump
// is the only compiler dataplane call that is not a shim no-op on the live
// userspace path, and a silent failure publishes a snapshot carrying the
// previous FIB generation. It is now reported at the call site; what stays true
// here is only that the pre-pass cannot and need not cover it.
//
// The double compile is safe with respect to ID assignment:
// TestPrePassDoesNotPerturbIDAssignment_4960 measures that two passes with a
// fresh CompileResult assign byte-identical ZoneIDs, ScreenIDs, AddrIDs,
// AppIDs, PoolIDs, NATCounterIDs and implicitSets -- including the #5099
// NAT-counter family whose streaming assignment was once compile-order
// dependent on a hash collision.
func validateBeforeMutate(cfg *config.Config) error {
	return validateBeforeMutateWith(discardingDataPlane{}, cfg)
}

// validateBeforeMutateWith is validateBeforeMutate with the discarding shim
// injectable. Production has exactly one caller and it passes
// discardingDataPlane{}; the seam exists so a test can fail exactly ONE
// dataplane method and prove which ROW of the table surfaces it.
//
// That is not a convenience. Five of the thirteen rows -- nptv6, screen
// profiles, default policy, flow timeouts, flow config -- have NO
// config-shaped hard error at all: every bad input inside them is a
// `slog.Warn(...); continue`, so their only `return err` is a dataplane
// failure. Without this seam those five could not be bound to their bodies by
// any config fixture, and `func() error { return nil }` in place of the body
// would stay green (#6894 r2 F3). `validationPhases` was already
// dp-parameterised for the same reason; this completes it.
//
// Any dp passed here must keep the xpfValidationPass marker
// (isValidationPass) and the never-write override set, so in practice it should
// embed discardingDataPlane.
//
// What is actually checked is the MARKER, not the embedding (#6894 r7 C4). The
// earlier wording said embedding "is enforced"; it is not. An in-package type
// can implement `xpfValidationPass() bool { return true }` while delegating
// SetAddressBookEntry to a LIVE dataplane, and this function would accept it
// and program live state from a compile whose result is discarded. Production
// is safe because the only caller constructs discardingDataPlane{} directly,
// and the marker is unexported so the hole is in-package only — but that is a
// property of the call site, not an enforced invariant, and claiming
// enforcement here would let a future in-package caller believe it was
// covered.
func validateBeforeMutateWith(dp DataPlane, cfg *config.Config) error {
	return validateBeforeMutateWithResult(dp, cfg, newValidationResult())
}

// validateBeforeMutateWithResult is validateBeforeMutateWith with the
// CompileResult injectable as well. Production never calls it directly; the
// extra seam exists because one compileNAT BRANCH is not reachable from cfg
// alone: the interface-SNAT branch resolves the egress zone's member through
// result.cachedInterfaceByName and soft-skips when the lookup misses, so on a
// host without that link the branch body never executes. Seeding a synthetic
// result.ifCache entry reaches it without naming a live link in a fixture --
// which is what TestPrePassShimCoversTheCalledSurface_4960 and
// TestNATCompilerCallsNoDataplaneNATWriter_6420 both do (#6894 r3 F1, #6420).
func validateBeforeMutateWithResult(dp DataPlane, cfg *config.Config, result *CompileResult) error {
	if !isValidationPass(dp) {
		return fmt.Errorf("validate pre-pass: dataplane %T does not carry the "+
			"discardingDataPlane marker — the pre-pass would program the live "+
			"tables from a compile whose result is thrown away (#4960)", dp)
	}
	if cfg == nil {
		return nil
	}

	// Phases 1 / 1.5 are pure and produce the IDs the later phases read.
	assignZoneIDs(result, cfg)
	assignScreenIDs(result, cfg)

	for _, phase := range validationPhases(dp, cfg, result) {
		if err := phase.run(); err != nil {
			return fmt.Errorf("validate %s: %w", phase.name, err)
		}
	}
	return nil
}

// validationPhase is one entry in the pre-pass table. The table is a named
// function rather than a literal inside validateBeforeMutate so a test can
// assert over its CONTENTS: the call site being bound proves the pre-pass
// RUNS, not that it still covers what the doc comment claims it covers. At
// round 1, ten of the eleven rows then present could be deleted with the whole
// package suite still green, because a single behavioural fixture pins exactly
// one row (#6894 r1 F1).
//
// So the two kinds of binding are DIFFERENT and neither substitutes for the
// other, and BOTH are now present -- stated precisely, because the earlier
// wording here ("no row can vanish silently") claimed more than its guard
// delivered (#6894 r2 F3):
//
//   - `TestValidationPhaseTableMatchesDocumentedCoverage_4960` binds INDEX ->
//     NAME: the row count and the name at each position. It asserts on
//     `got[i].name` ONLY, so it protects the LABEL. Replacing the BODY of a
//     row with `func() error { return nil }` -- names and order untouched --
//     left the whole package green.
//   - `TestEachValidationPhaseRowRunsItsOwnCompiler_4960` binds NAME -> BODY:
//     every row is driven against an input its own compiler rejects, and the
//     error must arrive prefixed `validate <that row's name>: `. A gutted or
//     swapped body reds there.
//
// Together those pin the table: a row cannot be deleted (count/name), cannot
// be renamed (name), cannot be reordered relative to its siblings (index ->
// name), and cannot stop validating (name -> body). The two behavioural
// fixtures (`applications` via an unresolvable application name, `nat` via an
// unresolvable pool) additionally bind that the pre-pass rejects BEFORE
// compileZones, which is the property of the whole change rather than of any
// one row.
type validationPhase struct {
	name string
	run  func() error
}

// validationPhases lists the phases the pre-pass validates, in the same order
// CompileConfig runs them, so a config that fails several reports the same
// phase it would have reported post-mutation.
//
// "The same order" is a claim about PRODUCTION's order, not about this list's
// internal logic, and the two came apart once (#6894 r5 F5 — see the first
// row). When adding a row, place it where CompileConfig reaches it, including
// checks hoisted INSIDE a phase: compileZones is the first phase, so anything
// it validates up front sorts ahead of every compileX row here.
//
// The name set is asserted by TestValidationPhaseTableMatchesDocumentedCoverage_4960.
// Adding or removing a row without updating that test -- and the coverage
// paragraph above -- is a test failure by construction.
func validationPhases(dp DataPlane, cfg *config.Config, result *CompileResult) []validationPhase {
	return []validationPhase{
		// FIRST, because compileZones is CompileConfig's first phase and
		// validateZoneScreenReferences is the first thing inside it
		// (compiler_iface.go). #6894 r5 F5: this row sat eighth, directly after
		// "screen profiles", on the reasoning that it reads result.ScreenIDs and
		// so belongs after the row that confirms the profile set. That reasoning
		// was about a data dependency the table does not have — assignScreenIDs
		// populates ScreenIDs before the table runs at all — and it broke the
		// property the ordering exists for. A config with BOTH a bad address-book
		// entry and a stale zone screen reference was reported by the pre-pass as
		// "address book" while production would abort in compileZones on the
		// screen reference, so the pre-pass named a different phase than the one
		// the operator would otherwise have seen. Nothing caught it: the coverage
		// test compares this list against another hand-written list, so the two
		// were wrong together.
		//
		// It covers the zone -> profile REFERENCE, which "screen profiles" does
		// not: compileScreenProfiles compiles the profile SET, while what aborts
		// is a zone naming a profile the set lacks, resolved per zone inside
		// compileZones after an earlier zone has already been through
		// SetZoneConfig and, if it carries interfaces, real netlink and
		// /proc/sys writes.
		{"zone screen references", func() error { return validateZoneScreenReferences(cfg, result) }},
		{"address book", func() error { return compileAddressBook(dp, cfg, result) }},
		{"applications", func() error { return compileApplications(dp, cfg, result) }},
		{"policies", func() error { return compilePolicies(dp, cfg, result) }},
		{"nat", func() error { return compileNAT(dp, cfg, result) }},
		{"static nat", func() error { return compileStaticNAT(dp, cfg, result) }},
		{"nat64", func() error { return compileNAT64(dp, cfg, result) }},
		{"nptv6", func() error { return compileNPTv6(dp, cfg) }},
		{"screen profiles", func() error { return compileScreenProfiles(dp, cfg, result) }},
		{"default policy", func() error { return compileDefaultPolicy(dp, cfg) }},
		{"flow timeouts", func() error { return compileFlowTimeouts(dp, cfg) }},
		// #6894 r1 F2: a config-shape hard error that was reachable after the
		// mutation point. It was described here as the ONE such error, and that
		// was wrong — the zone -> screen-profile reference was a second, and the
		// paragraph below acknowledged it while simultaneously claiming nothing
		// reached the dataplane. Both could not be true; the sweep added in
		// #6894 r5 ("zone screen references", above) is what makes the second
		// half true. Do not restore the "ONE" claim without re-deriving it: a
		// count stated in a comment is what let a live half-mutation hide for
		// four rounds.
		//
		// validateFilterProtocols is the first FALLIBLE
		// statement of Phase 10 -- one local map init precedes it
		// (compiler_filter.go:19), so it is not literally the first statement --
		// and is purely a function of cfg: no result, no dp, no logging. So
		// validating it here cannot read anything a later phase set up, and the
		// existing in-place call is left untouched. Reachable via the TOLERANT
		// load paths (Store.Load boot, Store.SyncApply HA peer-sync), which
		// downgrade the strict rejection to a warning and then reach
		// CompileConfig.
		//
		// PRECEDENCE, deliberate: hoisting this changes which error an operator
		// SEES when a config carries both a Phase-2 fault and a bad filter
		// protocol. The whole pre-pass runs before compileZones, and the pre-pass
		// returns on the FIRST failing row — so precedence is row order, not
		// phase order.
		//
		// MEASURED at this head, not reasoned: `zone screen references` sits
		// EARLIER in validationPhases than `firewall filter protocols`, so a
		// config carrying an unknown screen-profile ref AND
		// `from protocol bogus-proto` reports the SCREEN error. An earlier
		// revision of this paragraph asserted the opposite — that the filter
		// error now wins where the screen error used to — and both halves were
		// wrong once the screen sweep joined the table ahead of it.
		//
		// Stated as an ORDER, deliberately, not as row numbers: the indices shift
		// whenever a row is inserted, and two readers already disagreed on whether
		// to count them from 0 or 1. If you add a row, re-derive this example by
		// reading the table, not by editing the prose around it — a precedence
		// claim written from intent rather than from the table is exactly what
		// went stale here.
		//
		// Both are hard errors and both abort the same apply, so only the message
		// changes. Do not "fix" this by moving the row later; the ordering is
		// what keeps the mutation point clean.
		//
		// That "nothing reaches the dataplane either way" was true only for the
		// filter-protocol half. The screen-reference half DID reach it:
		// programZoneMaps ranges a map, so an unknown reference on the second
		// zone visited aborted after the first was already through
		// SetZoneConfig and its interfaces' netlink / procfs writes. The "zone
		// screen references" row plus the sweep at the top of compileZones is
		// what makes the sentence true for both halves.
		{"firewall filter protocols", func() error { return validateFilterProtocols(cfg) }},
		{"flow config", func() error { return compileFlowConfig(dp, cfg, result) }},
	}
}

// newValidationResult builds a zero-valued CompileResult with every map
// allocated. CompileConfig and validateBeforeMutate share it deliberately: if
// the two initialised the struct separately they could drift, and the pre-pass
// would then validate against a differently-shaped result than the real pass
// programs from -- the exact class of divergence this whole change exists to
// avoid.
func newValidationResult() *CompileResult {
	return &CompileResult{
		ZoneIDs:             make(map[string]uint16),
		ScreenIDs:           make(map[string]uint16),
		AddrIDs:             make(map[string]uint32),
		AppIDs:              make(map[string]uint32),
		PoolIDs:             make(map[string]uint8),
		implicitSets:        make(map[string]uint32),
		NATCounterIDs:       make(map[string]uint32),
		FilterSpans:         make(map[string]FilterCounterSpan),
		Lo0FilterV4:         0xFFFFFFFF, // sentinel: no lo0 filter
		Lo0FilterV6:         0xFFFFFFFF,
		ifCache:             make(map[string]*net.Interface),
		linkCache:           make(map[string]netlink.Link),
		linkIdxMap:          make(map[int]netlink.Link),
		rxTagStripOffCache:  make(map[string]bool),
		ethtoolApplied:      make(map[string]bool),
		genericXDPIfindexes: make(map[int]bool),
	}
}

// compileInfo / compileWarn are the CHOKE POINT for log records emitted inside
// the validation pre-pass's phases (#6903).
//
// The pre-pass runs `validationPhases` against a discarding shim before the
// real pass runs the same phases against the real dataplane, so any record a
// covered phase emits unconditionally is printed TWICE for one apply — and the
// two copies can disagree, which is the operator-facing harm #6894 fixed for
// `lo0_filter_v4`.
//
// A helper rather than ~19 inline `if !isValidationPass(dp)` blocks, because
// the failure this issue documents is an OMISSION: #6894's gate was correct
// where wired and simply incomplete, and nothing detected the gap. Inline
// blocks leave every future site equally forgettable; a helper plus the guard
// in compiler_validation_gate_6903_test.go makes the omission a test failure.
//
// NOT for every log site in these files. A phase the pre-pass does NOT run —
// `compilePortMirroring`, or `CompileConfig` itself — emits its record exactly
// once, and routing it through here would DELETE that record rather than
// de-duplicate it. The predicate is "reached by the pre-pass", which is the
// `validationPhases` table, not "has dp in scope".
func compileInfo(dp DataPlane, msg string, args ...any) {
	if isValidationPass(dp) {
		return
	}
	slog.Info(msg, args...)
}

// compileWarn is compileInfo for WARN records. See compileInfo.
func compileWarn(dp DataPlane, msg string, args ...any) {
	if isValidationPass(dp) {
		return
	}
	slog.Warn(msg, args...)
}

// isValidationPass reports whether dp is the pre-pass's discarding shim.
//
// #6894 r1 F3: the covered phases log unconditionally, so running them twice
// repeats their INFO output, and one line printed a value that was FALSE for
// the run the operator cares about:
// compileFlowConfig logs lo0_filter_v4 from a pass where compileFirewallFilters
// has not run, so the sentinel 65535 is emitted immediately before the real
// pass logs the armed id. An operator asking "did my lo0 filter arm?" read NO
// then YES for one apply. CLAUDE.md restricts slog.Info to state transitions and
// one-time events; a discarded validation pass is neither.
//
// SCOPE — this gate is PARTIAL, and reading it as "the pre-pass no longer
// double-logs" is wrong. It suppresses the sites it is wired into; a
// substantial inventory of INFO/WARN sites inside the covered phases still
// logs unconditionally and therefore still emits twice. Measured on a
// composite config: 25 INFO/WARN records, of which eleven distinct
// covered-phase records appeared twice. The known-ungated sites are the
// application compiler (compiler.go), the NAT/DNAT/static-NAT/NPTv6/NAT64
// families (compiler_nat.go), and the flow-timeouts record (compiler.go).
// Tracked as #6903 — do NOT infer from this comment that a duplicate you are
// looking at is impossible.
//
// The marker rides on the DATAPLANE rather than on CompileResult because two of
// the validated phases (compileDefaultPolicy, compileFlowTimeouts) do not take a
// result, so a result field could not gate them without a signature change.
func isValidationPass(dp DataPlane) bool {
	v, ok := dp.(interface{ xpfValidationPass() bool })
	return ok && v.xpfValidationPass()
}

func (discardingDataPlane) xpfValidationPass() bool { return true }
