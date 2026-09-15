package dataplane

import (
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// #9841 — an interface MTU the apply cannot read or write.
//
// mapZoneInterface's per-phys setup writes each netdev's planned MTU
// (#8119/#8120) and applyVLANSubInterfaceMTU9757 writes each VLAN child's.
// Two failures left the netdev at its old MTU while the apply returned
// success: the link lookup failed (a silent skip — the `nlErr == nil` guard
// has no log line of its own), or LinkSetMTU failed (one journal line,
// warn-and-continue). Nothing retried within the apply, and no commit
// warning or show output reported the unconverged MTU.
//
// Policy (b): keep applying, retry the lookup once without the cache, and
// surface the unconverged MTU in a commit warning and a show field.
// Fail-closed was rejected: the child is written before the parent in the
// same mapZoneInterface call, so on a valid raise-both commit the kernel's
// refusal is a NORMAL transient (it converges on the next commit until
// #9845 lands); rejecting the commit would strand it — a retry fails
// identically, since the in-call order is deterministic — and the lower
// direction mirrors it (a parent lowered below a live child). Exempting
// "order-explainable" refusals would need kernel-admission modeling that
// #9845's constraints reject, and errno alone cannot identify them.
// Severity LOW, nothing bypasses policy.
//
// The explicit policy this file implements: persistent lookup/permission
// failures produce successful-but-warned commits with no guaranteed
// eventual convergence. Warnings are advisory, not enforcement.
//
// NOTE(#9845): successful MTU writes record no #4960 host mutation yet;
// that issue owns the mark. The retry-success writes below are additional
// write sites its fix must cover.

// MTUUnconvergedGrade classifies WHY an MTU is unconverged, so a transient
// the next apply heals (parent-write-pending) does not read like a config
// that can never converge (config-impossible). Grades are stable,
// machine-readable strings; the human specifics ride Detail.
type MTUUnconvergedGrade string

const (
	// MTUGradeLookupFailed: the netdev could not be resolved, even on the
	// uncached retry. Live is unknown.
	MTUGradeLookupFailed MTUUnconvergedGrade = "lookup-failed"
	// MTUGradeWriteFailed: the resolved netdev refused LinkSetMTU and the
	// failure grades as neither ordering nor config (the want fits the
	// parent's live MTU, or the parent could not be read to grade it).
	MTUGradeWriteFailed MTUUnconvergedGrade = "write-failed"
	// MTUGradeParentWritePending: a child want above the parent's LIVE mtu
	// but within the parent's PLAN — the #9845 in-call order transient.
	// Factual relation only: it asserts nothing about whether the parent
	// write already ran (the parent's own record, when its write failed,
	// says that part).
	MTUGradeParentWritePending MTUUnconvergedGrade = "parent-write-pending"
	// MTUGradeConfigImpossible: a child want above the parent's plan (or
	// above the parent's live MTU with no parent plan at all). No sequence
	// of xpf applies converges it; the config has to change.
	MTUGradeConfigImpossible MTUUnconvergedGrade = "config-impossible"
	// MTUGradeResetTargetUnresolved: a unit with no MTU statement whose
	// #9757 reset target (the parent's live MTU) could not be read. Want
	// is unknown; the device keeps whatever it had.
	MTUGradeResetTargetUnresolved MTUUnconvergedGrade = "reset-target-unresolved"
	// MTUGradeBlockedByChildLive: a parent lower refused while a live VLAN
	// child sits above the want. Pure live observation (no plan modeling):
	// it states the temporal correlation, not causation, and stays true on
	// kernels that propagate parent lowers (there the write succeeds and
	// no record exists at all).
	MTUGradeBlockedByChildLive MTUUnconvergedGrade = "blocked-by-child-live"
)

// mtuUnknown9841 is the MTUUnconverged sentinel for an unknowable value:
// LiveMTU when no link could be resolved, WantMTU when the reset target
// could not be read. It must NEVER render; formatters map it to "unknown".
const mtuUnknown9841 = -1

// MTUUnconverged records one configured MTU this apply left unrealized
// (#9841). It is a HOST-convergence record (netdev state vs config), NOT
// an arm-coverage record: it never feeds WouldGate, disarm, or any
// predicate the arm proof reasons about, and a successful apply carrying
// these records is still a fully armed one. The arm proof ignores this
// field by construction (pinned by TestArmProofIgnoresMTUUnconverged9841).
//
// Records are per-apply (one CompileResult per apply) and truthful at
// publication: a record exists only when a fresh uncached observation
// could not confirm live==want, and a LinkSetMTU success clears any
// pending record for the name (a later zone reference retrying the same
// child, or #9845's future post-parent retry landing inside the attempt,
// cannot leave a stale warning behind). A failed syscall whose end state
// IS converged records nothing — the journal keeps the error; the commit
// warning stays silent because there is no divergence to report.
//
// Every write-success path MUST clear, and every record site MUST
// fresh-verify first; those two rules are what keep cross-zone and
// cross-retry sequences from double-reporting or going stale.
type MTUUnconverged struct {
	// Name is the kernel netdev ("ge-0-0-2", "ge-0-0-2.80").
	Name string
	// ConfigRef is the authored reference ("ge-0/0/2", "reth0.80") — the
	// form zone bindings use, so show rows match without re-resolving.
	ConfigRef string
	// WantMTU is the configured value, or mtuUnknown9841 when the reset
	// target could not be read.
	WantMTU int
	// LiveMTU is the fresh-observed value at record time, or
	// mtuUnknown9841 when the device could not be read.
	LiveMTU int
	// Grade classifies the failure; Detail carries the human specifics
	// (errno, parent/child numbers). Neither ever contains "-1".
	Grade  MTUUnconvergedGrade
	Detail string
	// ExpectIfindex is the ifindex the device must carry at show time for
	// a live==want observation to suppress this record. A same-named
	// foreign device with a coinciding MTU must not clear it.
	ExpectIfindex int
	// ExpectParentIfindex is the required IFLA_LINK for VLAN children, or
	// 0 for physical netdevs (no parent check).
	ExpectParentIfindex int
}

// Key is the record identity: (Name, ConfigRef). Two references can share
// one kernel child (a member zoned directly alongside its reth unit) with
// different wants; keying by Name alone would let the second attempt drop
// the first.
func (u MTUUnconverged) Key() string {
	return u.Name + "\x00" + u.ConfigRef
}

// IdentityMatches reports whether link is plausibly the device this record
// was taken against: same ifindex, and for VLAN children the same parent
// and 802.1Q kind. Show-time suppression requires this AND live==want; a
// squatter that happens to sit at the wanted MTU still flags.
func (u MTUUnconverged) IdentityMatches(link netlink.Link) bool {
	if link == nil || u.ExpectIfindex == 0 {
		return false
	}
	attrs := link.Attrs()
	if attrs == nil || attrs.Index != u.ExpectIfindex {
		return false
	}
	if u.ExpectParentIfindex == 0 {
		return true
	}
	if attrs.ParentIndex != u.ExpectParentIfindex {
		return false
	}
	_, ok := link.(*netlink.Vlan)
	return ok
}

// recordMTUUnconverged upserts one unconverged MTU, keyed by
// (Name, ConfigRef). A second failed attempt for the same key replaces the
// first — the later observation (fresher live value, possibly different
// want after a mid-apply parent change) supersedes it.
func (r *CompileResult) recordMTUUnconverged(u MTUUnconverged) {
	if r == nil {
		return
	}
	for i := range r.mtuUnconverged {
		if r.mtuUnconverged[i].Key() == u.Key() {
			r.mtuUnconverged[i] = u
			return
		}
	}
	r.mtuUnconverged = append(r.mtuUnconverged, u)
}

// clearMTUUnconverged drops any pending record for the name: the write
// succeeded, so the device accepted the value and any earlier failure for
// it in this apply is superseded. Called ONLY on LinkSetMTU-nil — a
// cached-equality skip must never clear, because under the #8119 property
// (LinkSetMTU never refreshes the caller's Link) a cached match can
// predate a write this same apply already failed. The residual TOCTOU —
// an external actor reverting the MTU between our write and this clear —
// is uncloseable without read-back loops and is documented, not denied.
func (r *CompileResult) clearMTUUnconverged(name, configRef string) {
	if r == nil {
		return
	}
	key := name + "\x00" + configRef
	r.mtuUnconverged = slices.DeleteFunc(r.mtuUnconverged, func(u MTUUnconverged) bool {
		return u.Key() == key
	})
}

// sortedMTUUnconverged returns the records in deterministic (Name,
// ConfigRef) order. Zone iteration is Go-map-randomized, so publication
// order would otherwise vary run to run — and commit warnings must not.
// This is the single publication choke: ApplyResultFromCompileResult and
// every formatter read through it.
func (r *CompileResult) sortedMTUUnconverged() []MTUUnconverged {
	if r == nil {
		return nil
	}
	out := slices.Clone(r.mtuUnconverged)
	slices.SortFunc(out, func(a, b MTUUnconverged) int {
		if a.Name != b.Name {
			return strings.Compare(a.Name, b.Name)
		}
		return strings.Compare(a.ConfigRef, b.ConfigRef)
	})
	return out
}

// mtuUnconvergedWarningPrefix is the stable, namespaced strip marker for
// SyncMTUUnconvergedWarnings: a prefix match, not whole-line equality, so
// future detail-text edits cannot orphan stale lines — and no foreign
// advisory shares the prefix.
const mtuUnconvergedWarningPrefix = "interface MTU not realized"

// Warning renders the commit-warning line. It names the authored
// reference first (what the operator configured) and the kernel netdev
// when it differs (what `ip link` shows), the want/live pair with unknowns
// spelled out, the machine grade in brackets for greppability, and the
// human detail.
func (u MTUUnconverged) Warning() string {
	var b strings.Builder
	b.WriteString(mtuUnconvergedWarningPrefix)
	b.WriteString(": ")
	b.WriteString(u.ConfigRef)
	if u.Name != "" && u.Name != u.ConfigRef {
		b.WriteString(" (netdev ")
		b.WriteString(u.Name)
		b.WriteString(")")
	}
	b.WriteString(" want ")
	writeMTUValue9841(&b, u.WantMTU)
	b.WriteString(" live ")
	writeMTUValue9841(&b, u.LiveMTU)
	b.WriteString(" [")
	b.WriteString(string(u.Grade))
	b.WriteString("]")
	if u.Detail != "" {
		b.WriteString(": ")
		b.WriteString(u.Detail)
	}
	b.WriteString(" (#9841)")
	return b.String()
}

func writeMTUValue9841(b *strings.Builder, mtu int) {
	if mtu == mtuUnknown9841 {
		b.WriteString("unknown")
		return
	}
	fmt.Fprintf(b, "%d", mtu)
}

// ShowAnnotation renders the show-interfaces annotation for a record the
// row matched, given one fresh observation (liveMTU/found) plus its
// identity verdict. It returns "" — suppress — ONLY on a fully verified
// convergence: found, identity-matched, want known, live==want. Every
// other outcome annotates: a show-time lookup failure renders
// live=unknown rather than hiding a known-unconverged interface, and an
// identity mismatch stays flagged as unverified even when the numbers
// coincide (a same-named squatter at the wanted MTU is not convergence).
func (u MTUUnconverged) ShowAnnotation(liveMTU int, found, identityOK bool) string {
	if found && identityOK && u.WantMTU != mtuUnknown9841 && liveMTU == u.WantMTU {
		return ""
	}
	var b strings.Builder
	b.WriteString("MTU unconverged: want ")
	writeMTUValue9841(&b, u.WantMTU)
	b.WriteString(", live ")
	if !found {
		b.WriteString("unknown")
	} else {
		fmt.Fprintf(&b, "%d", liveMTU)
	}
	b.WriteString(" [")
	b.WriteString(string(u.Grade))
	b.WriteString("]")
	if found && !identityOK {
		b.WriteString(" (unverified: device identity changed since apply)")
	}
	if u.Detail != "" {
		b.WriteString(": ")
		b.WriteString(u.Detail)
	}
	return b.String()
}

// MatchMTUUnconvergedRow partitions records against one rendered show row,
// identified by its authored reference and kernel netdev name. Exact
// ConfigRef matches win exclusively; the kernel-name fallback applies only
// when the row matched nothing exactly (a netdev shared under two refs —
// the fallback row annotates with the same true numbers, not a foreign
// ref's). Both renderers (local CLI, remote text twin) MUST call this so
// their matching cannot drift.
func MatchMTUUnconvergedRow(recs []MTUUnconverged, configRef, kernelName string) []MTUUnconverged {
	var exact, fallback []MTUUnconverged
	for _, r := range recs {
		if configRef != "" && r.ConfigRef == configRef {
			exact = append(exact, r)
		} else if kernelName != "" && r.Name == kernelName {
			fallback = append(fallback, r)
		}
	}
	if len(exact) > 0 {
		return exact
	}
	return fallback
}

// VisibleUnderFilter reports whether a leftover (rowless) record shows
// under a `show interfaces <filter>` selection. It mirrors the row
// selector's prefix looseness on BOTH identities — ConfigRef in authored
// form, Name against the kernel-normalized filter — so a member-filtered
// query still surfaces its aggregate's records. Deliberately as loose as
// row selection (reth1 matches reth10 rows and leftovers alike); tightening
// either alone would be the inconsistency.
func (u MTUUnconverged) VisibleUnderFilter(filter string) bool {
	if filter == "" {
		return true
	}
	if strings.HasPrefix(u.ConfigRef, filter) {
		return true
	}
	return strings.HasPrefix(u.Name, config.LinuxIfName(filter))
}

// SyncMTUUnconvergedWarnings strips this issue's lines from cfg.Warnings
// and appends the current records' lines, sorted. Strip-then-append (not
// append-only) keeps a re-sync idempotent; the strip predicate is the
// namespaced prefix, never whole-line equality.
//
// Callers MUST pass a response-local object (see
// WithMTUWarningsForResponse9841), NEVER the applied/retained config: the
// dataplane snapshot keeps the applied pointer (userspace builder
// Config: cfg) and status/control readers observe it under the userspace
// mutex, so mutating its Warnings post-apply races readers the applier
// holds no lock against. Pinned by
// TestMTUWarningsAliasedSerializationRace9841 (daemon).
//
// The strip MUST allocate fresh storage (it does: kept starts nil). The
// input slice header is shared with the applied original (the response
// copy is shallow); compacting in place (`w[:0]` filtering) would corrupt
// that original's view. Pinned by
// TestSyncMTUWarningsStripAllocatesFresh9841.
func SyncMTUUnconvergedWarnings(cfg *config.Config, recs []MTUUnconverged) {
	if cfg == nil {
		return
	}
	kept := make([]string, 0, len(cfg.Warnings))
	for _, w := range cfg.Warnings {
		if !strings.HasPrefix(w, mtuUnconvergedWarningPrefix) {
			kept = append(kept, w)
		}
	}
	sorted := slices.Clone(recs)
	slices.SortFunc(sorted, func(a, b MTUUnconverged) int {
		if a.Name != b.Name {
			return strings.Compare(a.Name, b.Name)
		}
		return strings.Compare(a.ConfigRef, b.ConfigRef)
	})
	for _, r := range sorted {
		kept = append(kept, r.Warning())
	}
	cfg.Warnings = kept
}

// WithMTUWarningsForResponse9841 returns the config object a commit
// response projects: cfg itself when recs is empty (pointer identity
// preserved for the record-less majority), else a shallow copy carrying
// the synced lines. The copy shares every sub-object — read-only
// post-commit — but owns its Warnings storage, so the sync can neither
// mutate the applied original the snapshot retains nor race the
// status/control readers observing it. Every commit surface (gRPC, REST,
// local CLI) projects the returned object, never store-active, so the
// lines reach exactly the response of the attempt that produced them.
func WithMTUWarningsForResponse9841(cfg *config.Config, recs []MTUUnconverged) *config.Config {
	if cfg == nil || len(recs) == 0 {
		return cfg
	}
	out := *cfg
	SyncMTUUnconvergedWarnings(&out, recs)
	return &out
}

// retryLinkByIndex9841 is the #9841 uncached retry for an ifindex lookup
// the cache path failed: one fresh RTM_GETLINK through the shared fetch
// (which memoizes on success, exactly as a first-attempt success would — a
// failure never cached anything, so the memoize cannot overwrite), with
// the hit validated against the expected kernel identity. An index reuse
// that now names a different device fails here rather than feeding a
// stranger's attributes to the caller, and the stranger is evicted again
// so no later phase trusts it.
func (r *CompileResult) retryLinkByIndex9841(idx int, expectName string) (netlink.Link, error) {
	link, err := r.fetchLinkByIndex(idx)
	if err != nil {
		return nil, err
	}
	attrs := link.Attrs()
	if attrs == nil || attrs.Index != idx || attrs.Name != expectName {
		got := "<nil>"
		if attrs != nil {
			got = fmt.Sprintf("index %d name %q", attrs.Index, attrs.Name)
			// Evict exactly what the fetch populated: the requested
			// index plus the returned name. linkIdxMap[attrs.Index]
			// is NOT evicted when it differs from idx — that key
			// holds another index's entry, not this fetch's.
			delete(r.linkIdxMap, idx)
			if attrs.Name != "" {
				delete(r.linkCache, attrs.Name)
			}
		}
		return nil, fmt.Errorf("retry resolved ifindex %d to %s, want name %q (index reuse?)",
			idx, got, expectName)
	}
	return link, nil
}

// retryLinkByName9841 is the #9841 uncached retry for a by-name lookup the
// cache path failed, with the hit validated against the expected identity.
// expectIndex is always required; expectParent (0 skips) and expectVLAN
// pin a VLAN child to its adoption: the first lookup trusts ensure's #6916
// proof, but a failure evidences change, so the retry re-proves rather
// than writing an MTU to whatever now owns the name. A mismatch fails
// WITHOUT memoizing the stranger — fetch memoizes before this returns, so
// evict exactly the keys it populated: linkCache under the REQUESTED name
// plus linkIdxMap under the returned index. (fetchLinkByName keys by the
// requested name, not attrs.Name: evicting the returned name leaves a
// wrong-named stranger cached under the requested key, where the next
// cached lookup returns it with no validation at all.)
func (r *CompileResult) retryLinkByName9841(name string, expectIndex, expectParent int, expectVLAN bool) (netlink.Link, error) {
	link, err := r.fetchLinkByName(name)
	if err != nil {
		return nil, err
	}
	if why := misidentifiedLink9841(link, name, expectIndex, expectParent, expectVLAN); why != "" {
		// Do not let a stranger pollute the caches a later phase trusts.
		delete(r.linkCache, name)
		if attrs := link.Attrs(); attrs != nil {
			delete(r.linkIdxMap, attrs.Index)
		}
		return nil, fmt.Errorf("retry resolved %q to an incompatible device (%s); refusing to use it", name, why)
	}
	return link, nil
}

func misidentifiedLink9841(link netlink.Link, name string, expectIndex, expectParent int, expectVLAN bool) string {
	attrs := link.Attrs()
	if attrs == nil {
		return "nil attributes"
	}
	if attrs.Index != expectIndex {
		return fmt.Sprintf("ifindex %d, want %d", attrs.Index, expectIndex)
	}
	if attrs.Name != name {
		return fmt.Sprintf("name %q, want %q", attrs.Name, name)
	}
	if expectParent != 0 && attrs.ParentIndex != expectParent {
		return fmt.Sprintf("parent ifindex %d, want %d", attrs.ParentIndex, expectParent)
	}
	if expectVLAN {
		if _, ok := link.(*netlink.Vlan); !ok {
			return fmt.Sprintf("kind %q, want vlan", link.Type())
		}
	}
	return ""
}

// physMTUAttempt9841 carries one planned physical-netdev MTU write: the
// lookup outcome (post-retry — the caller retries at the lookup site so
// the MTU, tune, UP/DOWN and framing consumers share one truth) plus the
// identities fresh-verification needs.
type physMTUAttempt9841 struct {
	physName  string
	configRef string
	ifindex   int
	want      int
	link      netlink.Link // nil when lookupErr != nil
	lookupErr error
}

// attemptPhysMTU9841 performs the ONE planned MTU write for a netdev,
// recording an MTUUnconverged iff a fresh observation cannot confirm
// convergence. Lookup failure (after the caller's retry), refused write
// with still-divergent live MTU, and refused lower with a live child above
// the want all record; converged-already, write-success, and
// failed-syscall-with-converged-end-state record nothing. slog lines keep
// their historical text.
func attemptPhysMTU9841(result *CompileResult, a physMTUAttempt9841) {
	if a.want <= 0 {
		return
	}
	if a.lookupErr != nil {
		slog.Warn("failed to resolve interface for MTU; leaving MTU unconverged",
			"name", a.physName, "mtu", a.want, "err", a.lookupErr)
		result.recordMTUUnconverged(MTUUnconverged{
			Name: a.physName, ConfigRef: a.configRef,
			WantMTU: a.want, LiveMTU: mtuUnknown9841,
			Grade:         MTUGradeLookupFailed,
			Detail:        fmt.Sprintf("link lookup failed after one retry: %v", a.lookupErr),
			ExpectIfindex: a.ifindex,
		})
		return
	}
	if a.link == nil || a.link.Attrs() == nil {
		// Defensive: a nil link with a nil lookup error. Production
		// lookups error instead of returning nil; a nil must record
		// rather than panic or skip silently.
		slog.Warn("failed to resolve interface for MTU; leaving MTU unconverged",
			"name", a.physName, "mtu", a.want, "err", "resolved to nil link")
		result.recordMTUUnconverged(MTUUnconverged{
			Name: a.physName, ConfigRef: a.configRef,
			WantMTU: a.want, LiveMTU: mtuUnknown9841,
			Grade:         MTUGradeLookupFailed,
			Detail:        "link lookup resolved to a nil link",
			ExpectIfindex: a.ifindex,
		})
		return
	}
	if a.link.Attrs().MTU == a.want {
		return
	}
	if err := linkSetMTUSeam(a.link, a.want); err != nil {
		slog.Warn("failed to set MTU",
			"name", a.physName, "mtu", a.want, "err", err)
		recordPhysMTUWriteFailure9841(result, a, err)
		return
	}
	slog.Info("set interface MTU", "name", a.physName, "mtu", a.want)
	// No clearMTUUnconverged: the per-phys block runs once per netdev per
	// apply (st.attached), so no pending record for this key can exist.
	// If a future retry adds a second attempt, it must clear on success —
	// see the MTUUnconverged contract.
}

// recordPhysMTUWriteFailure9841 records a refused physical MTU write after
// fresh-verifying the live value: a failed syscall whose end state is
// converged (a concurrent writer won) is journal-only, not a warning.
func recordPhysMTUWriteFailure9841(result *CompileResult, a physMTUAttempt9841, writeErr error) {
	live := mtuUnknown9841
	if fresh, err := result.retryLinkByIndex9841(a.ifindex, a.physName); err == nil {
		live = fresh.Attrs().MTU
		if live == a.want {
			// A concurrent writer converged the device under our failed
			// syscall: journal-only, AND clear any pending record for
			// this key — an earlier attempt in this same apply may have
			// recorded it divergent, and that record is now stale. (The
			// cached-equality skip in the caller deliberately does NOT
			// clear: an unverified cache hit is not fresh proof.)
			result.clearMTUUnconverged(a.physName, a.configRef)
			return
		}
	}
	grade := MTUGradeWriteFailed
	detail := fmt.Sprintf("LinkSetMTU refused: %v", writeErr)
	if live != mtuUnknown9841 && a.want < live {
		if child, childMTU, count := childBlockingPhysLower9841(a.physName, a.ifindex, a.want); count > 0 {
			grade = MTUGradeBlockedByChildLive
			detail = fmt.Sprintf("lower to %d refused with %d child device(s) above it (max %d on %s): %v",
				a.want, count, childMTU, child, writeErr)
		}
	}
	result.recordMTUUnconverged(MTUUnconverged{
		Name: a.physName, ConfigRef: a.configRef,
		WantMTU: a.want, LiveMTU: live,
		Grade: grade, Detail: detail,
		ExpectIfindex: a.ifindex,
	})
}

// childBlockingPhysLower9841 finds the live VLAN child above a refused
// lower, for grading only. Candidates must agree three ways — 802.1Q
// kind, IFLA_LINK to this parent, and the "<parent>.<vid>" name form —
// because ParentIndex alone is untrustworthy on unproven devices (#6917)
// and this text must not misattribute. A list failure degrades to
// ungraded (write-failed), never to a guessed attribution.
func childBlockingPhysLower9841(physName string, ifindex, want int) (child string, childMTU, above int) {
	links, err := linkLister()
	if err != nil {
		return "", 0, 0
	}
	prefix := physName + "."
	for _, l := range links {
		attrs := l.Attrs()
		if attrs == nil || attrs.ParentIndex != ifindex || attrs.MTU <= want {
			continue
		}
		if _, ok := l.(*netlink.Vlan); !ok {
			continue
		}
		if !strings.HasPrefix(attrs.Name, prefix) || !isVLANChildSuffix9841(strings.TrimPrefix(attrs.Name, prefix)) {
			continue
		}
		above++
		if attrs.MTU > childMTU {
			child, childMTU = attrs.Name, attrs.MTU
		}
	}
	return child, childMTU, above
}

func isVLANChildSuffix9841(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// vlanMTUContext9841 carries what the VLAN-child attempt needs beyond the
// names: the parent's plan (for grading, read from the SAME pass's
// physDesired — never recomputed) and the two ifindexes ensure already
// proved (for retry identity).
type vlanMTUContext9841 struct {
	parentWant    int
	parentIfindex int
	subIfindex    int
}

// gradeChildMTUFailure9841 grades a refused child write from live
// observations plus the same-pass plan. Pure, so the boundary table is
// pinned directly. Precedence: config-impossible (no plan sequence
// converges it) over parent-write-pending (the #9845 order transient)
// over write-failed (fits but refused, or ungradable). It models nothing
// about kernel admission — every input is observed or planned, never
// inferred.
//
// Known-plan impossibility judges FIRST, before any live comparison: a
// child want above the parent's plan can never converge however the
// parent reads live right now — the plan holds (or lowers) the parent
// below the child, and the kernel refuses children above their parent.
// Judging live-fit first misgraded that refusal as a bare write failure.
func gradeChildMTUFailure9841(childWant, parentLive, parentWant int, parentLiveOK bool) MTUUnconvergedGrade {
	if parentWant > 0 && childWant > parentWant {
		return MTUGradeConfigImpossible
	}
	if !parentLiveOK {
		return MTUGradeWriteFailed
	}
	if childWant <= parentLive {
		return MTUGradeWriteFailed
	}
	if parentWant > 0 && childWant <= parentWant {
		return MTUGradeParentWritePending
	}
	return MTUGradeConfigImpossible
}

// recordChildMTUWriteFailure9841 records a refused child write after
// fresh-verifying the live value: a failed syscall whose end state is
// converged (a concurrent writer won) is journal-only, not a warning.
// Grading reads the parent's live MTU fresh — lazily, on this rare path
// only, so the success path for an explicit unit MTU keeps making zero
// parent reads exactly as before.
func recordChildMTUWriteFailure9841(result *CompileResult, subName, configRef, physName string, want int, mtuCtx vlanMTUContext9841, writeErr error) {
	live := mtuUnknown9841
	if fresh, err := result.retryLinkByName9841(subName, mtuCtx.subIfindex, mtuCtx.parentIfindex, true); err == nil {
		live = fresh.Attrs().MTU
		if live == want {
			// A concurrent writer converged the device under our failed
			// syscall: journal-only, AND clear any pending record for
			// this key — an earlier zone reference in this same apply
			// may have recorded it divergent, and that record is now
			// stale. (The cached-equality skip in the caller deliberately
			// does NOT clear: an unverified cache hit is not fresh proof.)
			result.clearMTUUnconverged(subName, configRef)
			return
		}
	}
	parentLive, parentLiveOK := mtuUnknown9841, false
	if plink, err := result.retryLinkByName9841(physName, mtuCtx.parentIfindex, 0, false); err == nil {
		parentLive, parentLiveOK = plink.Attrs().MTU, true
	}
	grade := gradeChildMTUFailure9841(want, parentLive, mtuCtx.parentWant, parentLiveOK)
	result.recordMTUUnconverged(MTUUnconverged{
		Name: subName, ConfigRef: configRef,
		WantMTU: want, LiveMTU: live,
		Grade:         grade,
		Detail:        childMTUFailureDetail9841(grade, want, parentLive, mtuCtx.parentWant, writeErr),
		ExpectIfindex: mtuCtx.subIfindex, ExpectParentIfindex: mtuCtx.parentIfindex,
	})
}

// childMTUFailureDetail9841 composes the human specifics for a graded child
// failure. Factual relations only — no predictions about what a later
// apply will do.
func childMTUFailureDetail9841(grade MTUUnconvergedGrade, want, parentLive, parentWant int, writeErr error) string {
	switch grade {
	case MTUGradeParentWritePending:
		return fmt.Sprintf("unit MTU %d exceeds parent's live MTU %d (parent plans %d); LinkSetMTU refused: %v",
			want, parentLive, parentWant, writeErr)
	case MTUGradeConfigImpossible:
		if parentWant > 0 {
			return fmt.Sprintf("unit MTU %d exceeds parent's planned MTU %d; LinkSetMTU refused: %v",
				want, parentWant, writeErr)
		}
		return fmt.Sprintf("unit MTU %d exceeds parent's live MTU %d and no parent MTU is planned; LinkSetMTU refused: %v",
			want, parentLive, writeErr)
	default:
		return fmt.Sprintf("LinkSetMTU refused: %v", writeErr)
	}
}

// liveChildMTU9841 best-effort reads a child's live MTU for records taken
// on paths that never resolved the child (reset-target-unresolved): a
// fresh validated read first, else the last cached observation, else
// unknown. A stale-but-observed value beats "unknown" in the warning
// line; it is never used for a convergence DECISION (those always
// fresh-verify).
func liveChildMTU9841(result *CompileResult, subName string, mtuCtx vlanMTUContext9841) int {
	if link, err := result.retryLinkByName9841(subName, mtuCtx.subIfindex, mtuCtx.parentIfindex, true); err == nil {
		return link.Attrs().MTU
	}
	if link, err := result.cachedLinkByName(subName); err == nil && link != nil && link.Attrs() != nil {
		return link.Attrs().MTU
	}
	return mtuUnknown9841
}

// ObserveLive takes the one fresh observation a show annotation needs:
// the record's kernel netdev re-read plus its identity verdict. Callers
// feed all three into ShowAnnotation, so the displayed live value and the
// suppress/annotate decision always share one observation.
func (u MTUUnconverged) ObserveLive() (live int, found, identityOK bool) {
	link, err := netlink.LinkByName(u.Name)
	if err != nil || link == nil || link.Attrs() == nil {
		return 0, false, false
	}
	return link.Attrs().MTU, true, u.IdentityMatches(link)
}

// AnnotateMTUUnconvergedRow renders a show row's MTU annotations: the
// records matching (configRef, kernelName) via MatchMTUUnconvergedRow,
// each freshly observed and formatted, indented for the row depth. It
// returns the lines plus every matched record's Key — including matches
// that verify converged and render nothing, which still count as consumed
// (a matched row owns its records; only rowless records reach the
// leftover section). Both renderers MUST call this so matching,
// observation and formatting cannot drift between them.
func AnnotateMTUUnconvergedRow(recs []MTUUnconverged, configRef, kernelName, indent string) (lines, matched []string) {
	for _, r := range MatchMTUUnconvergedRow(recs, configRef, kernelName) {
		matched = append(matched, r.Key())
		live, found, identityOK := r.ObserveLive()
		if line := r.ShowAnnotation(live, found, identityOK); line != "" {
			lines = append(lines, indent+line)
		}
	}
	return lines, matched
}

// RenderMTUUnconvergedLeftovers renders records no row consumed (an
// interface absent at show time, renamed since the apply, or otherwise
// unmatched), restricted to the show filter. It returns the complete
// section including its header, or nil when nothing qualifies — so
// callers print it verbatim and record-less output stays byte-identical.
func RenderMTUUnconvergedLeftovers(recs []MTUUnconverged, consumed map[string]bool, filter string) []string {
	var lines []string
	for _, r := range recs {
		if consumed[r.Key()] || !r.VisibleUnderFilter(filter) {
			continue
		}
		live, found, identityOK := r.ObserveLive()
		line := r.ShowAnnotation(live, found, identityOK)
		if line == "" {
			continue
		}
		name := r.ConfigRef
		if r.Name != "" && r.Name != r.ConfigRef {
			name += " (netdev " + r.Name + ")"
		}
		lines = append(lines, "  "+name+": "+line)
	}
	if len(lines) == 0 {
		return nil
	}
	return append([]string{"MTU unconverged (no matching interface row):"}, lines...)
}
