package config

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Schema validators used by #1319 SchemaValidate. Each returns nil for
// accepted input and a descriptive error otherwise. They run at commit
// check time only — the existing compiler parsers (parseBandwidthLimit,
// parseBurstSizeLimit, ...) keep their zero-return-on-error contract so
// downstream callers don't need to learn new error paths.
//
// Validators take a (raw string, cfg *Config) pair so future validators
// can cross-reference compiled state (e.g. "scheduler X must exist").
// Today the schedulers leaves don't need cfg, so they ignore it.

// LeafValidator is the function signature for typed-leaf validators.
// The mirrored cmdtree.LeafValidator alias has the same shape so
// cmdtree Nodes can hold one of these directly. We define it here too
// (rather than importing cmdtree) to avoid a config→cmdtree→config
// import cycle.
type LeafValidator func(raw string, cfg *Config) error

// PositionalKeyValidator is the POSITION-AWARE variant of LeafValidator
// used for a named-instance key slot with more than one identity arg
// (#5576). The walker passes the 0-based arg index of each identity
// token so a node whose args are POSITIONAL (each slot has a distinct
// grammar) can validate them per-position instead of accepting the
// union in every slot. route-filter (`from route-filter <prefix>
// <match-type>`) is the motivating case: arg 0 must be a CIDR and arg 1
// must be a supported match-type keyword.
type PositionalKeyValidator func(argIdx int, raw string, cfg *Config) error

// validateEnum returns a closure that accepts only one of the listed
// names (case-sensitive, exact match).
func ValidateEnum(allowed []string) LeafValidator {
	sorted := append([]string(nil), allowed...)
	sort.Strings(sorted)
	set := make(map[string]struct{}, len(sorted))
	for _, a := range sorted {
		set[a] = struct{}{}
	}
	return func(raw string, _ *Config) error {
		if _, ok := set[raw]; ok {
			return nil
		}
		return fmt.Errorf("invalid value %q (expected one of: %s)", raw, strings.Join(sorted, ", "))
	}
}

// MasterPasswordPRFNames is the set of `system master-password
// pseudorandom-function <fn>` selector names the configstore key-derivation
// (configstore.prfHash) understands. prfHash is the SSOT for the
// name->hash.Hash mapping; this list mirrors only the accepted NAMES so a
// commit-time typo is caught before it reaches the encrypt path (#4578). Keep
// the two in sync — a name added to prfHash must be added here. It is exported
// so a configstore test can drift-guard it against prfHash across the package
// boundary (config→configstore would be an import cycle, so the guard lives on
// the configstore side).
//
// configstore.prfHash lower-cases its input before matching, so
// ValidateMasterPasswordPRF matches case-insensitively too: any spelling the
// runtime would accept commits, and only a genuine typo/unknown selector is
// rejected.
var MasterPasswordPRFNames = []string{
	"juniper-prf1",
	"hmac-sha2-256", "sha256",
	"hmac-sha2-384", "sha384",
	"hmac-sha2-512", "sha512",
	"hmac-sha1", "sha1",
}

// ValidateMasterPasswordPRF accepts only a pseudorandom-function selector the
// configstore master-password key-derivation understands
// (configstore.prfHash), matched case-insensitively. Without this gate a
// typo'd selector (e.g. "hmac-sha256" missing the "2-", or "bugus-prf") is
// accepted open-world, then falls through configstore.masterPasswordPRF's
// default and silently DISABLES at-rest config encryption — or fails the
// persisted-tree write with an opaque error. Rejecting it at commit turns a
// silent security downgrade into a clear commit error (#4578). Pairs with the
// closedWorld flag on the master-password subtree (schema_system.go), which
// catches a typo in the KEYWORD (`pseudo-random-fnuction`) rather than the
// value.
func ValidateMasterPasswordPRF(raw string, _ *Config) error {
	lower := strings.ToLower(strings.TrimSpace(raw))
	for _, name := range MasterPasswordPRFNames {
		if lower == name {
			return nil
		}
	}
	return fmt.Errorf("invalid pseudorandom-function %q (expected one of: %s)", raw, strings.Join(MasterPasswordPRFNames, ", "))
}

// ValidateIntegerMin returns a closure that accepts any bare integer
// >= min — the "no upper bound" spelling for typed leaves whose runtime
// consumes the full integer range. The representational maximum is
// implied by strconv.ParseInt's 64-bit limit (larger inputs fail as
// "not an integer"). Preferred over ValidateInteger(min, math.MaxInt64)
// so the operator error reads "must be at least N" instead of quoting a
// 19-digit range bound.
// ValidateVRRPGroupID (#8839) validates a VRRP group's IDENTITY token -- the
// `<id>` in `vrrp-group <id>`, not a value under it.
//
// It checks ONLY that the token is an integer, deliberately, because that is
// exactly what the compiler does: parseVRRPGroups calls strconv.Atoi on the
// instance name and `continue`s on error, so a non-numeric id silently drops
// the entire group. Measured before choosing the shape:
//
//	vrrp-group 1     strict accepts, 1 group compiled          correct
//	vrrp-group foo   strict ACCEPTS, 0 groups compiled         SILENT DROP
//	vrrp-group 300   strict REJECTS                            already gated
//	vrrp-group -5    strict REJECTS                            already gated
//
// Range and sign are therefore ALREADY caught by an existing strict gate, and
// duplicating them here would add a second source of truth for the same rule.
// Only the non-numeric case was unguarded, and it is the one that fails
// silently rather than loudly.
func ValidateVRRPGroupID(raw string, _ *Config) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("missing VRRP group id (expected an integer)")
	}
	if _, err := strconv.Atoi(raw); err != nil {
		return fmt.Errorf("VRRP group id %q is not an integer; the compiler parses "+
			"this token with strconv.Atoi and silently discards the whole group when "+
			"it fails, so the group would commit and then not exist", raw)
	}
	return nil
}

func ValidateIntegerMin(min int64) LeafValidator {
	return func(raw string, _ *Config) error {
		if strings.TrimSpace(raw) == "" {
			return fmt.Errorf("missing value (expected integer)")
		}
		v, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return fmt.Errorf("not an integer: %q", raw)
		}
		if v < min {
			return fmt.Errorf("integer must be at least %d (got %d)", min, v)
		}
		return nil
	}
}

// validateInteger returns a closure that accepts a bare integer in
// [min, max] inclusive. min > max disables the range check.
func ValidateInteger(min, max int64) LeafValidator {
	// #8358: a reversed range SILENTLY DISABLED the check. The body below
	// guards its comparison with `min <= max`, so `ValidateInteger(1, 0)` --
	// the shape a caller reaches for when they mean "at least 1" and mis-order
	// the arguments -- returned a validator that accepted EVERY integer, and
	// nothing said so. That is the worst shape a check can have: it fails to a
	// value indistinguishable from a healthy one, and the leaf reads as
	// validated in review because a validator is right there.
	//
	// Measured before adding this: all 35+ literal call sites and every
	// named-constant site in the tree are well-ordered, so no caller relies on
	// the disable, and nothing has ever needed it. `ValidateIntegerMin` is the
	// "no upper bound" spelling and is documented as such.
	//
	// A panic rather than an error, because this is a PROGRAMMING error and not
	// an operator one. `setSchema` is a package-level var built at init, so a
	// reversed range fails every test in every package that imports pkg/config,
	// immediately and unmissably. It cannot reach an operator: it cannot get
	// past a build.
	if min > max {
		panic(fmt.Sprintf(
			"config: ValidateInteger(%d, %d) has min > max, which would silently "+
				"accept every integer. Use ValidateIntegerMin(%d) for a lower bound "+
				"with no ceiling, or order the arguments (min, max).",
			min, max, min))
	}
	return func(raw string, _ *Config) error {
		if strings.TrimSpace(raw) == "" {
			return fmt.Errorf("missing value (expected integer)")
		}
		v, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return fmt.Errorf("not an integer: %q", raw)
		}
		// The `min <= max` term is now guaranteed by the constructor guard
		// above. Kept rather than simplified: it is what made the reversed-range
		// case silent, and leaving it visible next to the panic documents the
		// pairing. Deleting it would also make the closure unsafe on its own if
		// the guard were ever removed.
		if min <= max && (v < min || v > max) {
			return fmt.Errorf("integer out of range [%d..%d] (got %d)", min, max, v)
		}
		return nil
	}
}

// MaxLogicalUnit is the logical `unit <n>` ceiling: Junos accepts a logical
// unit number of 0 through 16385 and the runtime keys
// InterfaceConfig.Units by this int (#5829).
const MaxLogicalUnit = 16385

// CanonicalLogicalUnit is the ONE canonical normalizer for a logical
// `unit <n>` identity (#5878). It maps every textual spelling of a numeric
// logical unit to its shared canonical identity: it parses the raw token as a
// base-10 integer (so `01`==`1`, `+1`==`1`, `-0`==`0`, `00`==`0` all collapse)
// and returns the canonical int plus its canonical decimal string
// (strconv.FormatInt). A truly-malformed identity — non-numeric, negative
// non-zero, integer overflow, or out-of-range [0..MaxLogicalUnit] — is rejected
// via the same ValidateInteger check ValidateLogicalUnit has always used, so
// the acceptance set and error text are unchanged.
//
// The canonicalization the compiler performs ad hoc via `strconv.Atoi` at ~10
// call sites (compileInterfaces keys `ifc.Units[unitNum]` by the parsed int)
// is centralized here so a collision gate, and eventually the zone/NAT/routing
// reference binders (phase 2, #5878), can share one identity: two spellings
// that fold to the same canonical unit are the SAME unit.
func CanonicalLogicalUnit(raw string) (int, string, error) {
	// Delegate the acceptance/range check to ValidateInteger so the error
	// text is byte-identical to ValidateLogicalUnit's historical output
	// (the #5829 tests and operator diagnostics depend on it). ValidateInteger
	// ignores the *Config argument, so nil is safe here.
	if err := ValidateInteger(0, MaxLogicalUnit)(raw, nil); err != nil {
		return 0, "", err
	}
	// ParseInt with the same base/bitsize accepts exactly what ValidateInteger
	// just accepted, so this never fails on the post-validate path.
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, "", err
	}
	return int(v), strconv.FormatInt(v, 10), nil
}

// CanonicalInterfaceUnitRef canonicalizes the optional ".<unit>" suffix of a
// cross-subsystem interface reference (#5878 phase 2) so two textual spellings
// of one logical unit — ge-0/0/0.01, ge-0/0/0.1, ge-0/0/0.+1 — resolve to ONE
// runtime identity when a reference binder keys a map by the reference. The
// suffix is split on the FIRST "." — exactly how each subsystem's runtime split
// the reference before #9821 (buildInterfaceZoneMap,
// buildInterfaceRoutingInstances, buildInterfaceRouteTables,
// buildInterfaceHostInboundMap, junosHostZoneByInterface,
// zoneIfaceLogicalKeys) — so schema acceptance, validation, and binding stay
// aligned. Interface names carry no "." except the unit suffix ON THE CFG-FREE
// PATHS THAT CALL THIS. A declared interface name MAY contain a dot
// (ValidateInterfaceName allows it); callers WITH a *Config must resolve
// through SplitInterfaceUnitRef instead, which applies the #8994
// declared-name-first precedence this function cannot express.
//
// A bare interface (no "."), a trailing-dot form ("base." — the runtime treats
// it as bare), or a suffix that is not a valid logical unit is returned
// UNCHANGED: a malformed suffix is rejected at commit by the strict #5933
// reference gate (validateInterfaceUnitReferencesStrict) and stays inert on the
// tolerant load / peer-sync path exactly as before — canonicalization never
// changes the acceptance set, only which runtime unit a VALID reference binds.
func CanonicalInterfaceUnitRef(ref string) string {
	base, unitTok, hasUnit := strings.Cut(ref, ".")
	if !hasUnit || unitTok == "" {
		return ref
	}
	_, canon, err := CanonicalLogicalUnit(unitTok)
	if err != nil {
		return ref
	}
	return base + "." + canon
}

// InterfaceRefSplit is one parsed cross-subsystem interface reference
// (#9821). The tuple shape mirrors strings.Cut deliberately so every
// call-site swap reads as `Cut(x, ".")` → `Split(x)`, with declared-name
// precedence centralized in the splitter instead of distributed per caller.
type InterfaceRefSplit struct {
	// Base is the interface: the DECLARED name when one matched (exact or
	// longest dot-prefix), else the legacy first-dot base (or the whole
	// ref when dot-free).
	Base string
	// UnitTok is the RAW suffix after Base ("" when bare or trailing-dot).
	// It is NOT validated here; callers run CanonicalLogicalUnit /
	// ValidateLogicalUnit exactly as before, so malformed suffixes keep
	// their current disposition at every call site.
	UnitTok string
	// HasUnit reports a ".<suffix>" was present — including trailing-dot
	// and malformed forms, exactly as strings.Cut would.
	HasUnit bool
	// Literal is the canonical single-key form: Base when bare;
	// Base+"."+canon(UnitTok) when the suffix validates;
	// Base+"."+UnitTok otherwise. On the legacy path (step 4) this is
	// byte-equal to CanonicalInterfaceUnitRef(ref) in every case: a valid
	// suffix canonicalizes identically, an invalid/trailing suffix is
	// returned unchanged by both.
	Literal string
}

// SplitInterfaceUnitRef splits a cross-subsystem interface reference into its
// interface base and optional ".<unit>" suffix, with a DECLARED name outranking
// a parse (#8994, extended by #9821 from the kernel-name resolver to every
// member consumer). Precedence is centralized HERE, in order:
//
//  1. raw exact-declared (non-nil stanza) → bare. A padded declared name
//     (`p.01`) is never normalized away; the raw spelling wins over a
//     canonical alias when both `p.01` and `p.1` are declared.
//  2. legacy-canon alias: CanonicalInterfaceUnitRef(raw) exact-declared →
//     bare with Base/Literal = the canon (`ge-0/0/5.00` → `ge-0/0/5.0`;
//     #5878 canonical identity honored for declarations too).
//  3. longest declared dot-prefix of RAW + any suffix → unit (suffix NOT
//     validated here — see InterfaceRefSplit.UnitTok).
//  4. else (no declared match, nil receiver/map) → legacy Cut of the legacy
//     canon, byte-identical to the pre-#9821 behavior on every input.
//
// No slash/dash aliasing HERE: #8829 linux-name matching stays local to its
// daemon consumers, which extend it explicitly. Central aliasing would change
// plain dash-spelled bare/unit members tree-wide.
//
// Nil-receiver safe: a nil *Config (or nil interface map) degrades to step 4,
// so cfg-free callers behave exactly as before.
func (c *Config) SplitInterfaceUnitRef(ref string) InterfaceRefSplit {
	isDeclared := func(string) bool { return false }
	if c != nil && c.Interfaces.Interfaces != nil {
		declared := c.Interfaces.Interfaces
		// Present-but-nil slots count as ABSENT (#5886 LookupInterface
		// doctrine): only a real stanza outranks a parse.
		isDeclared = func(name string) bool {
			ifc, ok := declared[name]
			return ok && ifc != nil
		}
	}
	return splitInterfaceRefWithDeclared(isDeclared, ref)
}

// splitInterfaceRefWithDeclared is SplitInterfaceUnitRef over an abstract
// declared-name predicate, so AST-side consumers (which hold node names, not
// a *Config) share the ONE precedence implementation instead of re-deriving
// it. The *Config method delegates to this; their agreement is pinned by
// TestSplitInterfaceUnitRefAgreesWithDeclaredSet9821.
func splitInterfaceRefWithDeclared(isDeclared func(string) bool, ref string) InterfaceRefSplit {
	if isDeclared == nil {
		isDeclared = func(string) bool { return false }
	}
	// Step 1: raw exact-declared.
	if isDeclared(ref) {
		return InterfaceRefSplit{Base: ref, Literal: ref}
	}
	// Step 2: legacy-canon alias of a declaration.
	canon := CanonicalInterfaceUnitRef(ref)
	if canon != ref && isDeclared(canon) {
		return InterfaceRefSplit{Base: canon, Literal: canon}
	}
	// Step 3: longest declared dot-prefix of RAW, scanning back to front so
	// the first hit wins (`p.0.1` with `p`+`p.0` declared → base `p.0`,
	// never `p` + invalid `0.1`).
	for prefix := ref; ; {
		dot := strings.LastIndexByte(prefix, '.')
		if dot < 0 {
			break
		}
		prefix = prefix[:dot]
		if isDeclared(prefix) {
			return makeInterfaceRefSplit(prefix, ref[len(prefix)+1:], true)
		}
	}
	// Step 4: legacy Cut of the legacy canon.
	base, unitTok, hasUnit := strings.Cut(canon, ".")
	return makeInterfaceRefSplit(base, unitTok, hasUnit)
}

// makeInterfaceRefSplit builds the result tuple plus the canonical Literal
// for one (base, suffix, hasUnit) triple. hasUnit=false yields the bare
// form regardless of the suffix value.
func makeInterfaceRefSplit(base, unitTok string, hasUnit bool) InterfaceRefSplit {
	if !hasUnit {
		return InterfaceRefSplit{Base: base, Literal: base}
	}
	if _, canon, err := CanonicalLogicalUnit(unitTok); err == nil {
		return InterfaceRefSplit{Base: base, UnitTok: unitTok, HasUnit: true, Literal: base + "." + canon}
	}
	return InterfaceRefSplit{Base: base, UnitTok: unitTok, HasUnit: true, Literal: base + "." + unitTok}
}

// ValidateLogicalUnit is the ONE canonical numeric-identity validator for a
// logical `unit <n>` slot (#5829). A `unit <identity>` slot has no positional
// key validation, so a non-numeric identity such as `unit tenant` passed
// schema + commit and the compiler then SILENTLY DISCARDED the whole unit on
// strconv failure — dropping the unit's addresses, firewall filters, sampling,
// DHCP/DDNS and tunnel state with no diagnostic (a security fail-open: a
// unit-level firewall filter commits with no enforcement). Reject the malformed
// identity at commit instead: non-numeric, negative, integer overflow, and
// out-of-range [0..MaxLogicalUnit] all fail here. Reuse this on every slot that
// names an interface unit so the grammar stays consistent across subsystems.
//
// It now delegates the validation half to CanonicalLogicalUnit (#5878) — the
// shared normalizer — so validation and canonicalization can never diverge.
func ValidateLogicalUnit(raw string, cfg *Config) error {
	_, _, err := CanonicalLogicalUnit(raw)
	return err
}

// validatePercent returns a closure that accepts a real number in
// [min, max] inclusive. The input must parse as a float.
func ValidatePercent(min, max float64) LeafValidator {
	return func(raw string, _ *Config) error {
		if strings.TrimSpace(raw) == "" {
			return fmt.Errorf("missing value (expected percent %.0f..%.0f)", min, max)
		}
		v, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return fmt.Errorf("not a number: %q", raw)
		}
		// NaN/Inf sail past the `<`/`>` range comparisons below (both
		// comparisons are false for NaN), so a schema-accepted NaN/Inf
		// reaches the snapshot and blows up at userspace publish where
		// json.Marshal rejects non-finite floats (#4877). Reject them at
		// commit-check so the operator gets an actionable leaf error.
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return fmt.Errorf("percent must be a finite number (got %s)", raw)
		}
		if v < min || v > max {
			return fmt.Errorf("percent out of range [%.2f..%.2f] (got %s)", min, max, raw)
		}
		return nil
	}
}

// MaxDurationMillis is the largest millisecond count that survives the
// runtime's `time.Duration(ms) * time.Millisecond` conversion without
// int64 overflow (math.MaxInt64 / 1e6 = 9223372036854). Above this, a
// configured millisecond knob converts to a negative Duration — e.g. the
// cluster heartbeat sender ticker panics on a non-positive interval. Used
// as the honest runtime-derived upper bound for millisecond typed leaves
// whose runtime otherwise accepts any positive value (#1319 PR 2; Codex
// review on PR #1845: no schema-only caps).
const MaxDurationMillis = int64(math.MaxInt64) / int64(time.Millisecond)

// MaxDNSTTLSeconds is the largest TTL a DNS record can carry: the RR header's
// TTL is a 32-bit unsigned wire field (RFC 1035 §3.2.1), so a larger value does
// not fail — it WRAPS. 2^32 becomes 0, and a zero TTL tells every resolver not
// to cache the record at all, which is a materially different answer from the
// one the operator configured.
//
// #6773: the DDNS ttl leaf was min-only, and pkg/ddns's rfc2136 backend carried
// `uint32(rec.TTL) //nolint:gosec // TTL is a small positive config value` — a
// comment asserting a property nothing enforced, suppressing exactly the
// warning that would have caught it. Same shape as MaxDurationSeconds below:
// bound the typed leaf at the domain its runtime actually has.
const MaxDNSTTLSeconds = int64(math.MaxUint32)

// MaxDurationSeconds is the seconds analogue of MaxDurationMillis: the
// largest second count that survives `time.Duration(n) * time.Second`
// without int64 overflow (math.MaxInt64 / 1e9 = 9223372036). Used for
// second-denominated typed leaves whose runtime otherwise accepts any
// non-negative value (e.g. services ip-monitoring hold-down,
// pkg/ipmon/ipmon.go:480 — an overflowed negative hold would silently
// invert the damping behaviour).
const MaxDurationSeconds = int64(math.MaxInt64) / int64(time.Second)

// MaxDurationMinutes is the minutes analogue of MaxDurationSeconds: the
// largest minute count that survives `time.Duration(n) * time.Minute`
// without int64 overflow (math.MaxInt64 / 6e10 = 153722867). Above this,
// a configured minute knob converts to a non-positive Duration — e.g. the
// `system archival transfer-interval` timer's time.NewTicker panics on a
// non-positive interval (#5784, the minutes straggler of the #5705/#5723
// config-interval × time.Unit overflow class). Used to clamp minute-
// denominated runtime intervals whose commit-time schema bound the lenient
// Store.Load / peer-sync ingress can bypass.
const MaxDurationMinutes = int64(math.MaxInt64) / int64(time.Minute)

// maxWireU16 / maxWireU32 are the inclusive ceilings for typed leaves
// whose value lands in a Rust u16 / u32 wire field. #1979 Layer B uses
// these so the commit-time range gate agrees EXACTLY with the build-time
// coercion in pkg/dataplane/userspace/flow.go (Layer A, #1977): a value
// Layer B accepts is one Layer A leaves unchanged, and a value Layer B
// rejects is one Layer A would have coerced. (math.MaxUint16 /
// math.MaxUint32 are untyped constants; naming them keeps the schema
// aspect files import-free and the bound self-documenting.)
const (
	maxWireU16 = int64(math.MaxUint16)
	maxWireU32 = int64(math.MaxUint32)
	// maxWireI32 is the inclusive ceiling for a typed leaf whose value lands
	// in a Rust i32 wire field (e.g. RouteSnapshot.preference, #3771). Junos
	// route preference is a non-negative admin distance whose documented range
	// runs to 2^32-1, but the snapshot serializes it as i32, so the
	// wire-representable non-negative ceiling is math.MaxInt32 — a value above
	// it would overflow the Rust i32 decode (failing the whole snapshot). The
	// Rust helper backstops the lower bound too (RoutePreferenceOutOfRange).
	maxWireI32 = int64(math.MaxInt32)
)

// maxLoginUsernameLen caps a `system login user <name>` identity token. The
// classic Linux useradd/UT_NAMESIZE practical limit is 32; keeping the cap
// there also bounds the derived /etc/sudoers.d/xpf-<name> filename and the
// grant line the daemon writes.
const maxLoginUsernameLen = 32

// loginUsernameRE is the safe POSIX/Linux account-name shape a `system login
// user <name>` identity must match: a lowercase letter or underscore, then
// lowercase letters, digits, underscores, or hyphens. It deliberately excludes
// whitespace, newlines, `/`, `:`, quotes, and every sudoers metacharacter so a
// crafted username cannot be formatted into an /etc/sudoers.d grant to inject
// additional directives (#4895 — the lexer decodes `\n` inside a quoted string
// into a literal newline, so a name like "x\nnobody ALL=(ALL) NOPASSWD: ALL"
// would otherwise smuggle a second sudoers line past visudo's syntax check).
var loginUsernameRE = regexp.MustCompile(`^[a-z_][a-z0-9_-]*$`)

// ValidateLoginUsername is the commit-check validator for a `system login user
// <name>` identity token (wired as the schema keyValidator on the user
// container in schema_system.go). It rejects any name that is empty, over
// maxLoginUsernameLen, or does not match loginUsernameRE — the defense against
// the #4895 sudoers-injection path where the daemon formats the raw config key
// into /etc/sudoers.d/xpf-<name>. It is strict on the operator commit path and
// downgraded to a warning on the tolerant Load / SyncApply path
// (compileTreeLenient), the same #1960 doctrine as the other typed-leaf gates;
// the daemon's writeSudoersGrant/reconcileSudoers apply the SAME check
// defensively so a leniently-loaded or peer-synced bad name still never reaches
// the sudoers writer. The *Config arg is unused (part of the LeafValidator
// contract); daemon callers pass nil.
func ValidateLoginUsername(raw string, _ *Config) error {
	if raw == "" {
		return fmt.Errorf("login user name must not be empty")
	}
	if len(raw) > maxLoginUsernameLen {
		return fmt.Errorf("login user name %q too long (max %d characters)", raw, maxLoginUsernameLen)
	}
	if !loginUsernameRE.MatchString(raw) {
		return fmt.Errorf("invalid login user name %q (must match %s: a lowercase letter or underscore "+
			"followed by lowercase letters, digits, underscores, or hyphens; no whitespace, newlines, or "+
			"sudoers metacharacters)", raw, loginUsernameRE.String())
	}
	return nil
}

// TunnelModeNames is the set of `interfaces <if> tunnel mode <mode>` values the
// userspace dataplane actually carries traffic for (#6924).
//
// It MIRRORS the dataplane's own predicate, `tunnel_mode_kind` in
// userspace-dp/src/afxdp/forwarding_build/tunnels.rs, which is the SSOT: a mode
// it maps to TunnelKind::Gre or TunnelKind::WireGuard is carried, and everything
// else falls to TunnelKind::Unknown and is dropped. The two lists live in
// different languages so neither can import the other; the agreement is
// asserted by a drift guard that parses the Rust match arms
// (tunnel_mode_allowlist_6924_test.go), the same shape MasterPasswordPRFNames
// uses against configstore.prfHash.
//
// Before this list existed the leaf had NO validator at all, so
// `set interfaces ge-0/0/0 tunnel mode banana` committed green, built a kernel
// GRE device (buildKernelTunnelLink's default arm), and carried no traffic —
// the same "an interface an operator can see that carries nothing" symptom
// #4785 exists to reject, reached by a route #4785's ipip-keyed gate cannot
// see.
//
// `ipip` is deliberately ABSENT. It is a mode the system recognises and the
// dataplane does NOT carry, and #4785 rejects it at commit with a diagnostic
// that names the affected endpoints. Adding it here would accept it at the
// schema layer for #4785 to reject later; leaving it out makes the leaf refuse
// every mode the dataplane cannot carry, which is the general rule #4785's
// ipip case is one instance of.
//
// The leaf validator is STRICT only on the commit/commit-check path
// (compileTreeStrict -> schemaValidateExpandedTreeForNode). Store.Load and
// Store.SyncApply go through compileTreeLenient, which DOES schema-validate and
// then downgrades the violation to a warning (#1319 PR 2, store.go), so a
// config already persisted with an unrecognised mode still BOOTS (#1960
// no-brick doctrine, the same split #4785 half 1 arranged).
//
// This paragraph previously said compileTreeLenient "does not schema-validate
// at all". That was true when written, hollowed by a later change, and nothing
// re-checked it -- and it was then cited as authority by two agents in one day
// to argue that a new gate could not affect the load path. It can: the load
// path validates, and the no-blackout property rests entirely on the downgrade
// continuing to exist, not on the validation being absent. That distinction is
// pinned by TestLoadDowngradesUnknownTopLevelStanza8882 rather than by this
// comment.
var TunnelModeNames = []string{"gre", "ip6gre", "wireguard"}
