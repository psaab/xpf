// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// nftApplyPayload runs `nft -f -` with the supplied ruleset payload on stdin.
//
// #6387 PR-3: production NO LONGER calls this — the host-inbound / lo0 / fence
// install and teardown go through the netlink nftInstaller seam
// (daemon_nft_netlink.go), dropping the `nft` BINARY dependency. This var and
// the build*Payload text builders are RETAINED as the exec-`nft` ORACLE the T1
// ruleset-parity CI diffs the netlink build against (daemon_nft_netlink_parity_
// test.go), plus the payload-shape tests (TestNftDeleteTable*IdempotentAddDelete).
//
// It is a package var so the retained-idiom tests can exercise it without a real
// nft. The 5s context + WaitDelay mirror the established inline apply sites
// (#1794): an `-f -` payload loads atomically, so on failure the kernel retains
// the PREVIOUS table untouched rather than a half-applied ruleset.
var nftApplyPayload = func(payload string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.WaitDelay = 5 * time.Second
	cmd.Stdin = strings.NewReader(payload)
	return cmd.CombinedOutput()
}

// nftDeleteTable idempotently removes an nft table using only the universally
// available `add` / `delete` verbs (NOT `nft destroy`). `destroy` is a recent
// nftables verb and the project does not pin a minimum nftables version
// (debian/control depends on UNVERSIONED `nftables`, with no preflight), so a
// `destroy` dependency would raise "unknown command" on any non-floor base —
// and, now that teardown failures propagate (#3333), that would fail EVERY
// commit. Instead emit a two-line `nft -f -` payload: `add table` makes the
// table exist (a no-op when it already does), so the following `delete table`
// always has a target whether or not the table pre-existed — idempotent without
// `destroy`. A genuine failure (permissions / kernel) still surfaces on either
// line. This mirrors the established in-tree `delete table` idiom (applyLo0Filter
// below, scripts/migrate-bpfrx-to-xpf.sh) and reuses the atomic nftApplyPayload
// runner. Package var for test failure injection.
var nftDeleteTable = func(family, name string) ([]byte, error) {
	payload := "add table " + family + " " + name + "\n" +
		"delete table " + family + " " + name + "\n"
	return nftApplyPayload(payload)
}

// Base-chain hook-input priorities for the two daemon-generated local-delivery
// nftables tables (#3364). Both register `type filter hook input`, but at
// DISTINCT priorities so their inter-chain evaluation order is a deterministic
// product invariant rather than implementation-defined. With two base chains at
// an IDENTICAL hook/priority, netfilter's order between them is unspecified, so
// which chain's reject/log/counter fires for a packet both would act on could
// vary silently across nft/kernel versions (a `drop` stays terminal regardless,
// so this was never a permit bypass — only an observability/determinism gap).
//
// Ordering: xpf_lo0 evaluates BEFORE xpf_hostinbound (lo0 has the strictly lower
// priority number). The lo0.0 input filter is the operator's explicit, named,
// RE-wide control-plane firewall — the authoritative statement of what is
// permitted to the box, written with explicit accept/reject/discard verdicts.
// The zone host-inbound-traffic admission is the coarser Junos default-deny
// backstop. Running the explicit lo0 filter first lets its operator-authored
// verdicts (and their reject messages / per-term effects) take observable
// precedence, with host-inbound governing whatever lo0 did not already
// terminate — the Junos lo0-filter-then-zone ordering. nftApplyPriorityInvariant
// (nft_chain_priority_test.go) pins nftLo0FilterPriority < nftHostInboundPriority
// so the spread cannot silently regress back to a shared priority.
const (
	// nftLo0FilterPriority is the `hook input` priority of the xpf_lo0 loopback
	// input-filter base chain. 0 is the conventional `filter` priority (the lo0
	// chain IS the operator's firewall filter); it is STRICTLY LESS THAN
	// nftHostInboundPriority so lo0 evaluates first.
	nftLo0FilterPriority = 0
	// nftHostInboundPriority is the `hook input` priority of the xpf_hostinbound
	// base chain. It is STRICTLY GREATER THAN nftLo0FilterPriority so the zone
	// host-inbound default-deny backstop runs AFTER the lo0 input filter, and is
	// kept well below the conventional `security` (50) / `srcnat` (100)
	// priorities so it stays within the input-filter band.
	nftHostInboundPriority = 10
	// nftHostInboundGapPriority is the `hook input` priority of the ADDITIVE
	// xpf_hostinbound_gap fence (#5789). It is STRICTLY GREATER THAN
	// nftHostInboundPriority so it evaluates AFTER the main host-inbound table:
	// the gap only denies destinations the retained main table does NOT cover
	// (they fall through the main chain's `policy accept`), while an address the
	// main table already handles is either service-accepted (non-terminal, reaches
	// the gap but is not in its drop set) or catch-all DROPped (terminal at prio
	// 10, never reaches the gap). Running last makes the gap a pure backstop for
	// newly-appeared addresses without altering the retained table's verdicts —
	// the same three-way distinct-priority discipline as xpf_lo0 (0) <
	// xpf_hostinbound (10) < xpf_hostinbound_gap (11), pinned by
	// nft_chain_priority_test.go. Still well below security (50).
	nftHostInboundGapPriority = 11
)

// applyLo0Filter applies loopback filter rules for host-bound traffic.
// Implements "interfaces lo0 unit 0 family inet filter input <name>" by
// generating nftables rules from the named firewall filter.
//
// Fail-closed (#3392, mirroring the host-inbound #3333 fix): both the apply and
// the teardown surface their failure as a returned error instead of a swallowed
// WARN. applyConfigLocked joins this into the commit result, so a committed lo0
// input filter that did not reach the kernel reports commit FAILURE rather than
// silent success (the lo0 filter is host-protection control-plane enforcement,
// the same class of fail-open #3333 closed for host-inbound). The retained
// kernel state is always the more- or equally-restrictive prior state: an `-f -`
// apply loads atomically (the previous table is kept untouched on failure), and
// a failed teardown leaves the existing filter in place — neither relaxes
// enforcement silently. Boot / DHCP re-applies go through applyConfig(), which
// only logs the error, so a transient nft failure cannot brick startup; the next
// clean commit re-renders.
//
// Cold-boot fail-closed fence (#6476, mirroring the host-inbound #5644 fence):
// on COLD BOOT both nft tables are absent — there is no prior lo0 generation to
// retain — so a failed real InstallLo0 would leave the host input path OPEN with
// only a WARN (the boot apply only logs+discards the error), publishing host
// services / VIP / HA-ready over an unenforced RE-protection path. The fence-skip
// gate keys on lo0Enforced — whether a REAL operator filter is currently
// loaded — NOT on "any protecting table exists": a fence is `policy accept` and
// drops only its snapshot's addresses, so a retained FENCE does not cover a
// later-appearing address (#6489). When no real filter is loaded, a failed
// InstallLo0 (re-)installs a fail-closed fence rendered from the CURRENT
// firewall-local snapshot (minus lifelines) — so a fence -> new-address -> real
// install fails sequence re-fences and covers the new address instead of leaving
// it open through the stale fence. Only on a DAY-2 failure with a REAL filter
// loaded (lo0Enforced true) is no fence installed: the atomic replaceTable
// retained the operator's filter, which — unlike the per-destination-address
// host-inbound table — is not per-address scoped and still governs every local
// address (the deliberate divergence from the #5789 gap fence).
func (d *Daemon) applyLo0Filter(cfg *config.Config) error {
	filterV4 := cfg.System.Lo0FilterInputV4
	filterV6 := cfg.System.Lo0FilterInputV6
	if filterV4 == "" && filterV6 == "" {
		// No lo0 filter configured — remove any stale table. DeleteTable is
		// idempotent (absent -> nil, the common no-lo0-filter case), so a non-nil
		// error here is a REAL teardown failure that left a stale lo0 input filter in
		// the kernel: surface it so the commit fails closed rather than reporting that
		// the lo0 filter was removed when it was not (#6387 PR-3: via netlink).
		if err := nftInstaller.DeleteTable(xnft.Lo0TableName); err != nil {
			// Teardown FAILED: a stale xpf_lo0 table (real filter OR a prior fence)
			// may still be installed. Surface the failure (fail closed) and do NOT
			// clear lo0Enforced — if a real filter was the live table it may
			// still be there, so keep the flag (mirrors the host-inbound #5790
			// teardown semantics).
			err = tagNftInstallErr(err)
			slog.Warn("failed to delete stale lo0 filter table", "err", err)
			return fmt.Errorf("delete stale lo0 nftables table: %w", err)
		}
		// Teardown SUCCEEDED: no xpf_lo0 table is installed now, so no real filter is
		// loaded. Clear the gate so a later generation whose first real load fails
		// takes the cold-boot fence path rather than assuming a retained table
		// (#5790 parity).
		d.lo0Enforced.Store(false)
		return nil
	}

	// #6387 PR-3: install via netlink (the google/nftables Installer) instead of
	// exec-`nft`. toNftLo0Spec re-derives the SAME per-term inputs buildLo0Filter
	// Payload feeds the oracle; the netlink build is parity-proven equivalent (T1
	// CI). An unrepresentable port/DSCP token fails the build CLOSED (the installer
	// returns an error and installs nothing), mirroring the oracle's nft rejection.
	spec := toNftLo0Spec(cfg, filterV4, filterV6)
	rules, err := nftInstaller.InstallLo0(spec)
	if err != nil {
		err = tagNftInstallErr(err)
		slog.Warn("failed to apply lo0 filter", "err", err)
		// #6476 cold-boot fail-closed fence. Install (or re-install) a fence UNLESS a
		// REAL operator filter is currently loaded. Keying on lo0Enforced (not
		// "any protecting table") is the #6489 fix: a retained FENCE is `policy accept`
		// and covers only its own snapshot, so if the live table is a fence a failed
		// real install must RE-FENCE from the CURRENT snapshot to cover any address
		// that appeared since — otherwise the new address falls through the stale
		// fence's policy-accept (fail-open). Only a retained REAL filter is trusted to
		// govern every local address (unlike the address-scoped host-inbound table), so
		// with lo0Enforced true no fence is installed.
		if !d.lo0Enforced.Load() {
			// #6492: the fence's drop scope is NOT the real ruleset's scope. It
			// withholds any address shared with a lifeline interface (the fence has
			// no per-service accepts to let management back in) and it covers every
			// firewall-local address, including on a router that declares no
			// security zone at all — where the zone-model builders return nothing
			// and the fence would otherwise be an empty `policy accept` shell.
			sets := dpuserspace.BuildFenceAddrSets(cfg, dpuserspace.BuildZoneHostInboundViews(cfg))
			wgListenPorts := cfg.WireGuardListenPorts()
			if fenceErr := d.installLo0ColdBootFence(sets, wgListenPorts); fenceErr != nil {
				return errors.Join(fmt.Errorf("apply lo0 nftables filter: %w", err), fenceErr)
			}
		}
		return fmt.Errorf("apply lo0 nftables filter: %w", err)
	}
	if rules == 0 {
		// #6529: the install SUCCEEDED but rendered NOTHING — the live xpf_lo0
		// table is an empty `policy accept` shell that enforces nothing. Recording
		// that as "a real operator filter is loaded" is what defeated the #6476
		// fence: with the flag true every later failed install skips the fence and
		// the host input path stays open. A vacated filter is exactly as
		// unprotecting as no filter, so clear the gate — do NOT merely leave it
		// alone, because a peer-sync that atomically replaces a REAL filter with a
		// vacated one would otherwise keep the stale true.
		//
		// Zero rules is reachable through several doors and they are not
		// distinguishable from a boolean: a filter NAME that resolves to no filter
		// (toNftLo0Spec's map lookup silently yields no terms), a filter with no
		// terms, and a filter whose every term lowers to zero rules — a Junos
		// match-nothing scope, e.g. an unresolved `from source-prefix-list`. All
		// three arrive here through opts.lenientFirewallRefs on Store.Load at boot
		// or Store.SyncApply on HA peer-sync, which downgrades the dangling-
		// firewall-ref reject to a warning.
		//
		// This does NOT install a fence: fencing on a SUCCESSFUL install would deny
		// host-bound traffic on a clean commit. The gate being false is what
		// matters — the next failed install fences from the current snapshot.
		d.lo0Enforced.Store(false)
		slog.Warn("lo0 input filter installed but renders NO rules; the xpf_lo0 table is an empty "+
			"policy-accept shell that enforces nothing, so it is NOT recorded as a real filter and a "+
			"later failed install will install the cold-boot fail-closed fence",
			"v4", filterV4, "v6", filterV6,
			"v4_defined", lo0FilterDefined(cfg, filterV4, false),
			"v6_defined", lo0FilterDefined(cfg, filterV6, true))
		return nil
	}
	// A real lo0 filter is now the live table. Record it so a later failed install
	// retains this generation and skips the fence (the intended day-2 divergence).
	d.lo0Enforced.Store(true)
	slog.Info("lo0 filter applied", "v4", filterV4, "v6", filterV6, "rules", rules)
	return nil
}

// logFenceWithheld reports the firewall-local addresses the #6492 Finding-A
// lifeline guard removed from a cold-boot fence's drop set: an address that is
// ALSO configured on a lifeline interface (fxp0 / em0 / fab* / the configured
// control+fabric links). The fence is the real table with every per-service
// ACCEPT stripped and its drop rule carries no `iifname`, so fencing such an
// address renders a bare `ip daddr <mgmt-ip> drop` that kills every NEW
// management connection to it for the whole fence window. Withholding it trades
// fence coverage for the lifeline, which is the standing #1960 / #3277 order of
// priorities — but it is a real coverage hole while the fence is up, so it is
// logged at WARN rather than silently applied. Silent when nothing was withheld
// (the overwhelmingly common case: no address is shared with a lifeline).
func logFenceWithheld(table string, sets dpuserspace.FenceAddrSets) {
	if len(sets.WithheldV4) == 0 && len(sets.WithheldV6) == 0 {
		return
	}
	slog.Warn("cold-boot fence withheld firewall-local addresses that are also configured on a lifeline interface; "+
		"the fence has no per-service accepts and its drop carries no iifname, so fencing them would drop new management connections. "+
		"They stay unfenced until a real ruleset loads",
		"table", table, "withheld_v4", sets.WithheldV4, "withheld_v6", sets.WithheldV6)
}

// lo0FilterDefined reports whether the named lo0 input filter exists in cfg, for
// the #6529 vacated-install diagnostic. A configured name that resolves to no
// filter is the headline door into the zero-rule install: toNftLo0Spec's map
// lookup yields no terms and the resulting empty table installs cleanly. An
// empty name is "not configured", reported as defined so it does not read as the
// cause.
func lo0FilterDefined(cfg *config.Config, name string, v6 bool) bool {
	if name == "" {
		return true
	}
	filters := cfg.Firewall.FiltersInet
	if v6 {
		filters = cfg.Firewall.FiltersInet6
	}
	_, ok := filters[name]
	return ok
}

// installLo0ColdBootFence installs the #6476 lo0 cold-boot fail-closed fence: a
// minimal xpf_lo0 table that DENIES host-bound traffic to every firewall-local
// address in its rendered snapshot (views + the addressed-but-unzoned set),
// admitting only the mandatory L3 / return traffic (established/related, raw
// ESP+AH, IPv6 ND, v4/v6 PMTUD+error, and the configured WireGuard listen
// port(s)). It is the lo0-table analogue of installHostInboundColdBootFence and
// shares the SAME FenceSpec + fence builder, differing only in the target table
// (xpf_lo0 at lo0FilterPriority). It is attempted whenever a real lo0 install
// failed and no real filter is currently loaded (lo0Enforced false).
//
// Scope: the fence drops to the SAME dpuserspace.BuildFenceAddrSets scope the
// host-inbound fence uses (#6492) — lifeline INTERFACES excluded, addresses
// shared with a lifeline interface WITHHELD (the fence strips every per-service
// accept, so an unqualified `ip daddr <mgmt-ip> drop` would kill new management
// connections to a shared address), and every firewall-local address covered
// including on a zone-less router.
//
// State that guarantee exactly, because it is narrower than "management is
// safe": no address configured on — or shared with — a lifeline interface is
// ever dropped here. It is NOT a claim that no management traffic is affected.
// An operator who reaches the box on a non-lifeline address that is not also on
// a lifeline has that address fenced like any other for the fence window; the
// mandatory ct established,related admit keeps an already-open session up, and
// the drop is destination-address-only with no iifname (#3718), so the ingress
// path cannot exempt it. See docs/host-inbound-service-matrix.md,
// "Lifeline exclusion is by address VALUE, in the fence and the real table". It carries no named counters
// (a fence is transient).
//
// A fence deliberately does NOT set lo0Enforced — that flag is set true ONLY by a
// successful real InstallLo0, so it means exactly "a real operator lo0 filter is
// loaded". A fence is NOT a real filter (its chain is `policy accept` and drops
// only THIS snapshot's addresses). lo0Enforced is already false whenever this runs
// (we only reach here when the day-2 gate `!lo0Enforced` passed), so it stays
// false and a subsequent failed real install RE-RENDERS the whole-table fence from
// the then-current snapshot — covering any address that appeared after this fence
// — rather than trusting the stale fence (#6489). This subsumes the zero-drop
// case: an addressless snapshot yields a policy-accept shell, still not a real
// filter, so a later failure re-fences from a possibly-now-addressed snapshot. On
// failure (nft itself is broken) the error is returned and joined into the commit
// result; the daemon has done all it can.
func (d *Daemon) installLo0ColdBootFence(sets dpuserspace.FenceAddrSets, wgListenPorts []uint16) error {
	views, unzonedV4, unzonedV6 := sets.Views, sets.UnzonedV4, sets.UnzonedV6
	fenceHasScopedDrop := hostInboundHasEnforceableView(views) || len(unzonedV4) > 0 || len(unzonedV6) > 0
	logFenceWithheld(xnft.Lo0TableName, sets)
	spec := xnft.FenceSpec{Views: toNftViews(views), UnzonedV4: unzonedV4, UnzonedV6: unzonedV6, WGListenPorts: wgListenPorts}
	if err := nftInstaller.InstallLo0ColdBootFence(spec); err != nil {
		err = tagNftInstallErr(err)
		slog.Error("COLD-BOOT FAIL-OPEN GUARD: lo0 install failed AND the fail-closed "+
			"fence could not be installed; host-bound services may be reachable without "+
			"the lo0 RE-protection filter until the next successful commit re-renders it",
			"err", err)
		return fmt.Errorf("install lo0 cold-boot fail-closed fence: %w", err)
	}
	// lo0Enforced is intentionally NOT set here (a fence is not a real filter).
	if fenceHasScopedDrop {
		slog.Warn("lo0 real install failed; installed an address-scoped fail-closed fence for the current snapshot (re-rendered on each later failure until a real filter loads)",
			"fenced_zones", len(views), "fenced_unzoned_v4", len(unzonedV4),
			"fenced_unzoned_v6", len(unzonedV6))
	} else {
		slog.Warn("lo0 real install failed; installed a zero-drop fence shell (no firewall-local addresses in this snapshot); re-rendered on each later failure until a real filter loads",
			"fenced_zones", len(views), "fenced_unzoned_v4", len(unzonedV4),
			"fenced_unzoned_v6", len(unzonedV6))
	}
	return nil
}

// buildLo0FilterPayload assembles the exact nft ruleset payload that
// applyLo0Filter feeds to `nft -f -`. It is split out as a pure function so
// tests can capture and parse-check the full payload (#2069) without invoking
// nft or the daemon apply path. Callers pass the already-resolved v4/v6 filter
// names so the payload reflects exactly what applyLo0Filter would send.
//
// The leading two lines are the atomic delete+recreate idiom shared with the
// host-inbound table: `add table` makes the table exist (idempotent), so the
// following `delete table` always has a target whether or not it pre-existed,
// removing the old chain AND its named counter OBJECTS; then a fresh
// `table { ... }` body redeclares everything. This REPLACES the pre-#3445
// create/`flush table`/redefine idiom because `flush table` empties rules but
// does NOT delete named counter objects (#3445 attaches a named counter per
// `then count`), so redeclaring them on the next commit would collide
// ("File exists"); delete+recreate guarantees each counter is declared exactly
// once and leaves no stale counter for a removed term. A consequence is that the
// lo0 counters reset to zero on every rebuild (every commit / DHCP re-render);
// since #4422 they are scraped as xpf_lo0_counter_hits_total (pkg/nftables
// ReadLo0Counters → pkg/api collectLo0Counters), and Prometheus rate() handles
// the reset the same way it does for the host-inbound deny counters. nft parses an `-f -`
// payload atomically, so a syntax error on any line rejects the ENTIRE payload.
// (The pre-#2069 `flush ruleset inet xpf_lo0` was NOT valid nft and made the
// filter fail OPEN; the delete+recreate idiom is unconditionally valid.)
func buildLo0FilterPayload(cfg *config.Config, filterV4, filterV6 string) string {
	prefixLists := cfg.PolicyOptions.PrefixLists

	// Render the per-term rules first so the pre-pass can collect the named
	// counter objects every `then count` rule references. nft requires each
	// counter to be DECLARED in the table body before the chain references it, so
	// the declarations are emitted ahead of the chain (mirroring the host-inbound
	// table's pre-pass). Dedup on the object name so a counter shared by several
	// terms (or by both the v4 and v6 lo0 filters, which land in the same inet
	// table) is declared exactly once.
	var ruleLines []string
	var counters []string
	seenCounter := map[string]bool{}
	emit := func(f *config.FirewallFilter, family string) {
		for _, term := range f.Terms {
			for _, r := range nftRulesFromTerm(term, family, prefixLists) {
				if r != "" {
					ruleLines = append(ruleLines, "    "+r)
				}
			}
			if term != nil && term.Count != "" {
				cn := xnft.Lo0CounterName(term.Count)
				if !seenCounter[cn] {
					seenCounter[cn] = true
					counters = append(counters, cn)
				}
			}
		}
	}
	if filterV4 != "" {
		if f, ok := cfg.Firewall.FiltersInet[filterV4]; ok {
			emit(f, "ip")
		}
	}
	if filterV6 != "" {
		if f, ok := cfg.Firewall.FiltersInet6[filterV6]; ok {
			emit(f, "ip6")
		}
	}

	var rules []string
	rules = append(rules, "add table inet xpf_lo0")
	rules = append(rules, "delete table inet xpf_lo0")
	rules = append(rules, "table inet xpf_lo0 {")
	for _, cn := range counters {
		// The DECLARATION must be UNQUOTED (#3578): nft v1.1.6 rejects a quoted
		// name in a counter declaration. Lo0CounterName returns a bare-safe nft
		// identifier, so the unquoted declaration parses and matches the (quoted)
		// reference object name byte-for-byte.
		rules = append(rules, "  counter "+cn+" {")
		rules = append(rules, "  }")
	}
	rules = append(rules, "  chain input {")
	// #3364: explicit distinct priority so lo0 evaluates BEFORE xpf_hostinbound.
	rules = append(rules, fmt.Sprintf("    type filter hook input priority %d; policy accept;", nftLo0FilterPriority))
	rules = append(rules, ruleLines...)
	rules = append(rules, "  }")
	rules = append(rules, "}")

	return strings.Join(rules, "\n") + "\n"
}

// applyHostInboundFilter is the KERNEL-nftables PRIMARY enforcement of
// `security zones <z> host-inbound-traffic` (#3070). Ordinary host-bound
// traffic to a firewall interface IP / VRRP VIP (SSH, ping, OSPF/BGP to the
// box — exactly what host-inbound-traffic governs) is shunted to the Linux
// kernel by the XDP shim before it reaches userspace-dp, so the userspace
// LocalDelivery check (forwarding/host_inbound.rs) only catches the narrow
// subset that actually reaches the XSK. This kernel chain enforces the
// host-inbound set for the rest, mirroring the lo0-filter precedent.
//
// Safety: #3405 — EVERY configured security zone gets a rule (Junos default-deny
// parity). A zone with no `host-inbound-traffic` stanza is treated as an empty
// stanza: its firewall-local addresses get a catch-all DROP, denying every
// host-bound service/protocol not explicitly permitted. Management /
// cluster-control lifeline interfaces (fxp0 / em0 / fab*) are excluded from the
// address sets by BuildZoneHostInboundViews.
//
// That exclusion is by INTERFACE, not by address VALUE, so it does NOT
// guarantee management survives (#7284). An address that is ALSO configured on
// a zoned interface still enters the drop set through that interface, and the
// deny carries no `iifname` — so a management IP shared onto a no-stanza zone
// is denied by this table on an ordinary healthy commit, and the #5566
// reconcile records it with an empty admit set and flushes its established
// entries. Established sessions and IPv6 ND / PMTUD control messages are
// accepted before any deny, which protects a live session only where the zone
// admits the service at all.
//
// Fail-closed (#3333): both the apply and the teardown surface their failure as
// a returned error instead of a swallowed WARN. applyConfigLocked joins this
// into the commit result, so a committed host-inbound deny that did not reach
// the kernel reports commit FAILURE rather than silent success. A failed `-f -`
// apply retains only the exact prior kernel generation, if one exists; its rules
// cover only the destinations represented in that generation (#5789). A failed
// teardown likewise leaves the existing generation in place. Boot / DHCP full
// applies use applyConfig(), which only logs the error, and get a host-inbound
// retry opportunity only when they reach this function. hostInboundEnforced is
// a historical fallback gate, not proof of current table presence or current-
// address coverage (#5789, #5790).
func (d *Daemon) applyHostInboundFilter(cfg *config.Config) error {
	views := dpuserspace.BuildZoneHostInboundViews(cfg)
	// #4420 HI-2: firewall-local addresses on interfaces assigned to NO security
	// zone. xpfd applies an interface's address regardless of zone membership,
	// but the per-zone views above scope the default-deny to ZONED addresses
	// only, so host-bound traffic to an addressed-but-unzoned interface would
	// fall through the chain's `policy accept` and reach the host stack with no
	// host-inbound admission (fail-open; Junos passes no traffic on an unzoned
	// interface). These get their own catch-all DROP below. The builder excludes
	// lifeline INTERFACES and subtracts zoned addresses, so this never conflicts with
	// a zone rule — and since #7284 it also subtracts lifeline address VALUES. A
	// management address additionally configured on an UNZONED interface used to
	// land here with an EMPTY admit set, so the real table dropped new management
	// connections to it and the #5566 reconcile — fed from this same set — flushed
	// the established ones. See docs/host-inbound-service-matrix.md,
	// "Lifeline exclusion is by address VALUE, in the fence and the real table".
	unzonedV4, unzonedV6 := dpuserspace.BuildUnzonedHostInboundAddrs(cfg)
	// #3698: surface the transient fail-open admit window. A configured
	// host-inbound-enforcing zone whose non-lifeline interfaces have no
	// resolvable address yet (DHCP WAN before its first lease, backup node before
	// VIP install, or an unaddressed interface) contributes nothing to the deny
	// scoping below, so host-bound traffic to a freshly-usable address can reach
	// the kernel input path without the zone default-deny. Address appearance is
	// available to a later snapshot, but enforcement changes only when a later
	// applicable apply reaches this function and its nft transaction succeeds.
	// These transition logs describe the pre-publication address snapshot, not nft
	// installation success. Log only state TRANSITIONS (a zone entering/leaving
	// the window) so repeated commits / DHCP renewals do not flood.
	d.logHostInboundAddresslessTransitions(cfg)
	// #3710: the zone-level signal above collapses a MIXED zone (some interfaces
	// addressed, some not; or one family up before the other) to "scoped" the
	// moment ANY interface resolves ANY address, hiding the per-interface /
	// per-family fail-open windows that enforcement (per-daddr, per-family) can
	// still leave open. Log those at unit+family granularity so the operator sees
	// WHICH interface/family is in the window, not just that a whole zone is.
	d.logHostInboundAddresslessIfaceTransitions(cfg)
	// #3718 (Option B): a firewall-local address reachable from >1 zone with
	// DIFFERING host-inbound sets makes the kernel destination-address-only
	// verdict order-dependent (and can disagree with the ingress-scoped
	// userspace-dp path). The strict commit gate rejects this, but a tolerant /
	// peer-synced load can slip one through, and it is NOT self-healing — so log
	// the state transition and export it as xpf_host_inbound_ambiguous_addresses.
	d.logHostInboundAmbiguousTransitions(cfg)
	// #4146: the effective `to-zone junos-host` DENY programs, projected per
	// ingress zone and scoped by kernel iifname. This is the fine-grained
	// per-source / per-application host-inbound DENY the coarse per-zone
	// permit-by-service gate below cannot express — enforced on the DIRECT
	// host-bound path (the kernel delivers those packets; userspace-dp never sees
	// them). Only representable programs that resolve to >=1 non-lifeline netdev
	// are returned; the un-representable remainder keeps the #4168 commit warning.
	programs := dpuserspace.BuildJunosHostPrograms(cfg)
	if !hostInboundHasEnforceableView(views) && len(unzonedV4) == 0 && len(unzonedV6) == 0 && len(programs) == 0 {
		// No host-inbound-configured zone with a resolvable address, no
		// addressed-but-unzoned interface (#4420 HI-2), AND no junos-host DENY
		// program (#4146) — nothing to enforce. Remove any stale table.
		// DeleteTable is idempotent (absent -> nil, the common case), so a non-nil
		// error here is a REAL teardown failure that left a stale deny in the kernel:
		// surface it so the commit fails closed rather than reporting that
		// host-inbound was relaxed when it was not (#6387 PR-3: via netlink).
		if err := nftInstaller.DeleteTable(xnft.HostInboundTableName); err != nil {
			// Teardown FAILED: a stale xpf_hostinbound table may still be installed
			// in the kernel. Surface the failure (fail closed) and — critically — do
			// NOT clear hostInboundEnforced: the flag's meaning ("a real load or
			// address-scoped fallback established a protecting table") may still hold
			// for the table this delete could not remove, so a later failed install
			// must keep retaining it rather than fencing over a live table (#5790).
			err = tagNftInstallErr(err)
			slog.Warn("failed to delete stale host-inbound filter table", "err", err)
			return fmt.Errorf("delete stale host-inbound nftables table: %w", err)
		}
		// #5789: also remove any additive gap fence. With the main table gone there
		// is nothing for the gap to backstop, and a lingering gap deny would fence
		// an address that is no longer enforced. A failed gap delete is treated like
		// the main teardown failure above: a table the delete could not remove may
		// still be installed, so KEEP the coverage/enforced state and surface the
		// error (fail closed) rather than clearing state over a live gap table.
		if err := nftInstaller.DeleteTable(xnft.HostInboundGapTableName); err != nil {
			err = tagNftInstallErr(err)
			slog.Warn("failed to delete stale host-inbound gap fence table", "err", err)
			return fmt.Errorf("delete stale host-inbound gap fence nftables table: %w", err)
		}
		// Teardown SUCCEEDED: no xpf_hostinbound (or gap) table is installed now.
		// Clear the historical gate (#5790) AND the coverage set (#5789): with no
		// table installed nothing is covered. Leaving hostInboundEnforced sticky-true
		// is FAIL-OPEN: if a later generation becomes enforceable and its FIRST real
		// load fails, the stale true would take the day-2 retention branch — which
		// assumes a retained table still protects the addresses — and SKIP the
		// cold-boot/fresh-install fence, leaving newly reachable local addresses
		// unprotected. Clearing the coverage set keeps the two in agreement (a stale
		// covered set would falsely report the torn-down addresses as still covered).
		// Serialized under applySem with the Store(true) sites and every later apply,
		// so this cannot race a subsequent install.
		d.hostInboundEnforced.Store(false)
		// #7181: both tables are gone, so no gap fence stands and the last
		// attempt succeeded. Leaving the staleness flag set here would render a
		// deliberate teardown as a failed render.
		d.hostInboundGapFenceActive.Store(false)
		d.hostInboundLastApplyFailed.Store(false)
		d.hostInboundLastFailureUnixNano.Store(0)
		d.hostInboundCoveredAddrs = nil
		return nil
	}
	// #5582: the configured WireGuard listen port(s). The XDP shim steers
	// local-destination UDP on the WG listen port to the kernel WG socket, so the
	// host-inbound filter must admit that port or a fresh passive handshake to a
	// restricted zoned address is dropped by the per-zone catch-all. Empty (nil)
	// when no WG tunnel is configured — buildHostInboundFilterPayload then emits
	// no WG accept, so the restricted-default posture is unchanged.
	wgListenPorts := cfg.WireGuardListenPorts()
	// #5789: the exact firewall-local destination set this generation wants a
	// catch-all DROP for. Compared on failure against the retained generation's
	// covered set to detect addresses that appeared after that generation loaded.
	desiredDrop := hostInboundDesiredDropAddrs(views, unzonedV4, unzonedV6)
	// #6387 PR-3: install via netlink. toNftHostInboundSpec re-derives the SAME
	// inputs buildHostInboundFilterPayload feeds the oracle; the netlink build is
	// parity-proven equivalent (T1 CI). A failed install still fails the commit
	// closed below (invariant H7) and, at cold boot, drives the fail-closed fence.
	spec := toNftHostInboundSpec(views, unzonedV4, unzonedV6, programs, wgListenPorts)
	if err := nftInstaller.InstallHostInbound(spec); err != nil {
		err = tagNftInstallErr(err)
		slog.Warn("failed to apply host-inbound filter", "err", err)
		// #5644 (M37) cold-boot fail-closed fence. The atomic `-f -` load leaves
		// the exact PREVIOUS table untouched on failure, so day-2 its existing
		// rules and destinations remain in the kernel. But on COLD BOOT both tables
		// are absent — there is no prior
		// generation to retain — so a failed install here would leave the host
		// input path OPEN: host-bound services to firewall-local addresses become
		// reachable with NO host-inbound default-deny (fail-open), and the boot
		// apply only logs+discards this error (applyConfig), so the daemon proceeds
		// to publish host service / VIP / HA-ready over an unenforced input path.
		// A false hostInboundEnforced means no successful real load or fallback with
		// an address-scoped DROP has been published; it can coexist with a loaded
		// zero-drop table shell. Gate the fallback on that historical state and
		// render it from this invocation's exact address snapshot. When that snapshot
		// has destinations, the fallback denies every non-lifeline firewall-local
		// address while admitting only mandatory L3 / return traffic. The requested
		// real apply still fails (we return its error). Another opportunity requires
		// a later failed real invocation that reaches this function while state is
		// still false.
		if !d.hostInboundEnforced.Load() {
			// #6492: fence-only scope — lifeline-shared addresses withheld (the
			// fence strips every per-service ACCEPT, so a bare `daddr <mgmt-ip>
			// drop` would lock out management), and every firewall-local address
			// covered rather than only the zone-model ones.
			sets := dpuserspace.BuildFenceAddrSets(cfg, views)
			if fenceErr := d.installHostInboundColdBootFence(sets, wgListenPorts); fenceErr != nil {
				return errors.Join(fmt.Errorf("apply host-inbound nftables filter: %w", err), fenceErr)
			}
		} else {
			// #5789 day-2 COVERAGE gap. hostInboundEnforced is true, so the cold-boot
			// fence is skipped on the premise that the retained (atomic-untouched)
			// generation still protects the addresses. But that generation only covers
			// the destinations PRESENT when it loaded — a static/DHCP/SLAAC address (or
			// the first address on a program-only generation) that appeared afterward
			// has NO deny in the retained table, so this failed rerender leaves it
			// fail-open. Compare the desired drop set against what the retained
			// generation covers and, for any UNCOVERED destination, install an ADDITIVE
			// gap fence (a separate xpf_hostinbound_gap table at a later hook priority)
			// that denies only those addresses WITHOUT disturbing the retained table's
			// valid accepts/denies. hostInboundCoveredAddrs is unchanged (the retained
			// real table's coverage still stands); the gap is torn down by the next
			// successful real install. A gap install failure joins the commit error so
			// the newly reachable address is never silently left fail-open.
			uncoveredV4, uncoveredV6 := hostInboundUncoveredDropAddrs(views, unzonedV4, unzonedV6, d.hostInboundCoveredAddrs)
			if len(uncoveredV4) > 0 || len(uncoveredV6) > 0 {
				if gapErr := d.installHostInboundGapFence(uncoveredV4, uncoveredV6, wgListenPorts); gapErr != nil {
					// #7181: the apply failed AND the gap could not be installed.
					// Record the staleness before returning -- this is the worst
					// applied state and the one an operator most needs surfaced.
					d.noteHostInboundApplyFailed(time.Now())
					return errors.Join(fmt.Errorf("apply host-inbound nftables filter: %w", err), gapErr)
				}
				// #7181: a gap fence is now standing beside the retained real
				// table. Part of the applied truth -- this box enforces through
				// TWO tables until the next successful real install.
				d.hostInboundGapFenceActive.Store(true)
			}
		}
		// #7181: the retained generation is unchanged and may still be
		// protecting, so this marks the applied state STALE rather than
		// clearing Established -- exactly the distinction a sticky bool cannot
		// express.
		d.noteHostInboundApplyFailed(time.Now())
		return fmt.Errorf("apply host-inbound nftables filter: %w", err)
	}
	// A real host-inbound table is now installed. Record the historical success;
	// a later failed install retains that exact generation and therefore skips the
	// cold-boot fallback. This does not prove current table presence (#5790).
	d.hostInboundEnforced.Store(true)
	// #7181: advance the applied generation and clear the staleness flag and any
	// gap-fence marker -- the real table now covers the desired set on its own.
	d.noteHostInboundApplySucceeded()
	// #5789: the retained generation now covers EXACTLY this desired drop set.
	// Record it so a later failed rerender can tell which destinations a
	// subsequently-appeared address left uncovered.
	d.hostInboundCoveredAddrs = desiredDrop
	// The real table now covers every desired destination, so any additive gap
	// fence from a prior failed rerender is obsolete — a lingering gap would keep
	// denying an address the real table now serves. Best effort: nftDeleteTable is
	// idempotent (a no-op when absent, the common case), so a delete error here is
	// a rare real kernel fault; log it but do NOT fail the successful commit (the
	// enforcement is correct and the next apply retries the delete — a lingering
	// gap fences only, never opens).
	if err := nftInstaller.DeleteTable(xnft.HostInboundGapTableName); err != nil {
		slog.Warn("failed to delete obsolete host-inbound gap fence after successful real install",
			"err", err)
	}
	// #5566: reconcile Linux netfilter conntrack against the just-applied
	// host-inbound set. The chain's leading `ct state established,related accept`
	// precedes the per-zone coarse drops and table replacement does not flush
	// conntrack, so an EXISTING direct-kernel connection admitted under a looser
	// prior config would keep that authorization after a service is removed. Flush
	// the now-denied host-directed entries so the next original-direction packet is
	// re-evaluated against the current rules — mirroring the Rust userspace
	// local-delivery per-hit re-eval/teardown. Best effort (see the function doc):
	// enforcement for NEW connections is already in place, so a flush failure never
	// fails the commit.
	// #6802: record the outcome as retry DEBT. Still not a commit failure — the
	// rationale above holds — but before #6802 a failure left no return value, no
	// dirty flag, no counter and no retry owner, so a now-denied host-inbound
	// flow kept its old authorization until it closed or timed out, with nothing
	// to notice or re-drive it.
	ctReq := hostInboundConntrackFlushRequest{
		views:         views,
		unzonedV4:     unzonedV4,
		unzonedV6:     unzonedV6,
		wgListenPorts: wgListenPorts,
	}
	d.noteHostInboundConntrackFlush(ctReq,
		d.flushDeniedHostInboundConntrack(views, unzonedV4, unzonedV6, wgListenPorts))
	slog.Info("host-inbound filter applied", "zones", len(views),
		"unzoned_deny_v4", len(unzonedV4), "unzoned_deny_v6", len(unzonedV6),
		"junos_host_deny_programs", len(programs))
	return nil
}

// installHostInboundGapFence installs the #5789 ADDITIVE gap fence for the
// supplied uncovered firewall-local addresses via nftApplyPayload. It is a
// SEPARATE xpf_hostinbound_gap table (a distinct input-hook base chain at
// nftHostInboundGapPriority, strictly after the main xpf_hostinbound table), so
// it denies only the newly-appeared destinations the retained generation does not
// cover WITHOUT replacing that generation — the retained table's per-service
// accepts for already-covered addresses stay intact. It is attempted on a failed
// day-2 rerender when hostInboundCoveredAddrs is missing >=1 desired destination.
// A load failure returns the error (joined into the commit result by the caller)
// so a newly reachable local address is never silently left without a host-inbound
// deny. Caller guarantees >=1 uncovered address (the payload has >=1 DROP).
func (d *Daemon) installHostInboundGapFence(uncoveredV4, uncoveredV6 []string, wgListenPorts []uint16) error {
	// #6387 PR-3: install via netlink (parity-proven equivalent to the exec-`nft`
	// buildHostInboundGapFencePayload oracle).
	spec := xnft.GapFenceSpec{UncoveredV4: uncoveredV4, UncoveredV6: uncoveredV6, WGListenPorts: wgListenPorts}
	if err := nftInstaller.InstallGapFence(spec); err != nil {
		err = tagNftInstallErr(err)
		slog.Error("COVERAGE-GAP FAIL-OPEN GUARD: host-inbound real install failed AND the additive "+
			"gap fence for newly-appeared local addresses could not be installed; those addresses "+
			"may be reachable without host-inbound enforcement until the next successful commit",
			"err", err,
			"uncovered_v4", len(uncoveredV4), "uncovered_v6", len(uncoveredV6))
		return fmt.Errorf("install host-inbound coverage-gap fence: %w", err)
	}
	slog.Warn("host-inbound real install failed; retained generation does not cover newly-appeared "+
		"local addresses — installed an additive gap fence denying them (retained accepts preserved)",
		"gap_v4", len(uncoveredV4), "gap_v6", len(uncoveredV6))
	return nil
}

// installHostInboundColdBootFence installs the #5644 (M37) cold-boot
// fail-closed host-inbound fence: a minimal xpf_hostinbound table that DENIES
// every host-bound service to firewall-local addresses in its rendered
// snapshot, admitting only the mandatory L3 / return traffic
// (established/related, raw ESP+AH for
// host-terminated IPsec, IPv6 ND, v4/v6 PMTUD+error, and the configured
// WireGuard listen port(s)). It is attempted only when the real host-inbound
// ruleset failed to load and hostInboundEnforced is false. False can coexist
// with a successfully loaded zero-drop table shell; it does not prove table
// absence.
//
// WHY THE FENCE SURFACE IS NOT A SEPARATE FILE (#7714 Seam A, measured and
// declined). The fence functions look like a cluster — 9 of them, 333 lines,
// in 4 runs — and their scope difference below reads like a seam. It is not one,
// because the file boundary would not carry the property:
//
//   - the scope is CHOSEN BY THE CALLERS, not by the fences.
//     `dpuserspace.BuildFenceAddrSets` is invoked inside `applyLo0Filter` and
//     `applyHostInboundFilter` — the REAL-ruleset functions — and the result is
//     passed in as `sets dpuserspace.FenceAddrSets`. The divergence is visible
//     precisely because the choice sits next to the scope it diverges from.
//   - the two surfaces SHARE their address-set helpers.
//     `hostInboundDesiredDropAddrs` is called by both `applyHostInboundFilter`
//     and `installHostInboundColdBootFence`; `hostInboundDropAddrKey` and
//     `hostInboundUncoveredDropAddrs` likewise straddle them.
//
// So moving the fences out would separate the receivers from the choosers and
// from the helpers they share with the real path — making the relationship this
// comment exists to explain HARDER to see, not easier. The property is stated
// here instead, which is where a reader asking the question already is.
//
// Scope: the fence is the real table with every service ACCEPT removed, so its
// drop scope is NOT the real ruleset's scope — dpuserspace.BuildFenceAddrSets
// (#6492) derives it. Lifeline INTERFACES are excluded by the view builders as
// before, and any address that is ALSO configured on a lifeline interface is
// additionally WITHHELD: without the per-service accepts the fence's unqualified
// `ip daddr <addr> drop` would kill new management connections to a shared
// management IP. Conversely the fence covers every firewall-local address, not
// only the zone-model ones, so a zone-less router is fenced instead of getting an
// empty `policy accept` shell.
//
// The guarantee is narrower than "management is safe": no address configured on
// — or shared with — a lifeline interface is ever dropped here. A non-lifeline
// address the operator happens to manage the box on IS fenced for the fence
// window, with only the mandatory ct established,related admit keeping an open
// session up. See docs/host-inbound-service-matrix.md,
// "Lifeline exclusion is by address VALUE, in the fence and the real table". It carries no named counters (a fence is
// transient) so
// it has fewer moving parts than the real payload and is more likely to load when
// the real one hit a payload-specific nft error. After successful nft completion,
// hostInboundEnforced is set true only when this exact payload contains an
// address-scoped DROP. A successful zero-drop shell leaves false so a later
// failed real invocation reaching this function can try again with its snapshot.
// On failure (nft itself is broken) the error is returned and joined into the
// commit result; the caller logs it and the daemon has done all it can short of
// holding forwarding.
//
// On a successful address-scoped fence the whole-table fence IS the retained
// enforcement, so ITS OWN drop set — derived from sets, not from the real
// ruleset's desiredDrop, which #6492 made a different set in both directions —
// becomes hostInboundCoveredAddrs, letting a later failed rerender detect a
// subsequently-appeared uncovered address.
func (d *Daemon) installHostInboundColdBootFence(sets dpuserspace.FenceAddrSets, wgListenPorts []uint16) error {
	views, unzonedV4, unzonedV6 := sets.Views, sets.UnzonedV4, sets.UnzonedV6
	fenceHasScopedDrop := hostInboundHasEnforceableView(views) || len(unzonedV4) > 0 || len(unzonedV6) > 0
	logFenceWithheld(xnft.HostInboundTableName, sets)
	// #6492: the fence's own coverage, not the real ruleset's desired-drop set.
	// The two now differ in BOTH directions (lifeline-shared addresses withheld,
	// zone-less / unzoned-VIP addresses added), and hostInboundCoveredAddrs must
	// describe what the RETAINED enforcement — this fence — actually drops.
	fenceCovered := hostInboundDesiredDropAddrs(views, unzonedV4, unzonedV6)
	// #6387 PR-3: install via netlink (parity-proven equivalent to the exec-`nft`
	// buildHostInboundFencePayload oracle).
	spec := xnft.FenceSpec{Views: toNftViews(views), UnzonedV4: unzonedV4, UnzonedV6: unzonedV6, WGListenPorts: wgListenPorts}
	if err := nftInstaller.InstallColdBootFence(spec); err != nil {
		err = tagNftInstallErr(err)
		slog.Error("COLD-BOOT FAIL-OPEN GUARD: host-inbound install failed AND the fail-closed "+
			"fence could not be installed; host-bound services may be reachable without "+
			"host-inbound enforcement until the next successful commit re-renders the ruleset",
			"err", err)
		return fmt.Errorf("install host-inbound cold-boot fail-closed fence: %w", err)
	}
	if fenceHasScopedDrop {
		d.hostInboundEnforced.Store(true)
		// #5789: the address-scoped fence is now the retained enforcement; record
		// exactly which destinations it covers so the day-2 coverage check works.
		d.hostInboundCoveredAddrs = fenceCovered
		slog.Warn("host-inbound real install failed; fallback succeeded with address-scoped DROPs for its rendered snapshot",
			"fenced_zones", len(views), "fenced_unzoned_v4", len(unzonedV4),
			"fenced_unzoned_v6", len(unzonedV6))
	} else {
		slog.Warn("host-inbound real install failed; fallback succeeded with zero address-scoped DROPs; hostInboundEnforced remains false and another fallback requires a later failed real invocation reaching host-inbound while false",
			"fenced_zones", len(views), "fenced_unzoned_v4", len(unzonedV4),
			"fenced_unzoned_v6", len(unzonedV6))
	}
	return nil
}

// buildHostInboundFencePayload assembles the #5644 cold-boot fail-closed fence
// payload (see installHostInboundColdBootFence). It is the atomic-replace
// xpf_hostinbound table reduced to: the global mandatory accepts, then a
// catch-all DROP for every firewall-local address represented by the supplied
// snapshot — NO per-service accepts, NO named counters. Empty address inputs
// intentionally produce a zero-drop table shell. Split out as a pure function
// so tests can parse-check the full payload without invoking nft. A syntax error
// on any line rejects the WHOLE payload (atomic load), retaining only the exact
// prior generation, if one exists — exactly like the real builder.
func buildHostInboundFencePayload(views []dpuserspace.ZoneHostInboundView, unzonedV4, unzonedV6 []string, wgListenPorts []uint16) string {
	// Same hook/priority as the real host-inbound chain so the fence occupies the
	// same evaluation slot (#3364).
	return buildFenceTablePayload(xnft.HostInboundTableName, nftHostInboundPriority, views, unzonedV4, unzonedV6, wgListenPorts)
}

// buildLo0FencePayload assembles the #6476 lo0 cold-boot fail-closed fence
// payload (see installLo0ColdBootFence). It is the SAME fence body as
// buildHostInboundFencePayload — mandatory admits then a catch-all DROP for every
// firewall-local address the real ruleset would scope, NO per-service accepts, NO
// named counters — but rendered into the xpf_lo0 table at the lo0 filter priority
// (0), the same slot the real lo0 RE-protection filter occupies, so a later
// successful InstallLo0 atomically replaces it. It shares buildFenceTablePayload
// with the host-inbound fence so the two fence oracles can never drift. Used by
// the T1 parity gate to prove the netlink InstallLo0ColdBootFence is
// bit-equivalent. Empty address inputs intentionally produce a zero-drop shell.
func buildLo0FencePayload(views []dpuserspace.ZoneHostInboundView, unzonedV4, unzonedV6 []string, wgListenPorts []uint16) string {
	return buildFenceTablePayload(xnft.Lo0TableName, nftLo0FilterPriority, views, unzonedV4, unzonedV6, wgListenPorts)
}

// buildFenceTablePayload renders a fail-closed cold-boot fence into the named
// inet table at the given hook-input priority: the shared mandatory admits
// (hostInboundFenceMandatoryAdmits) then a catch-all DROP for every firewall-local
// address the real ruleset would scope — per host-inbound-configured zone
// (default-deny parity, #3405) and the addressed-but-unzoned set (#4420 HI-2).
// These sets exclude lifeline INTERFACES, not lifeline address VALUES: a
// management address shared onto a non-lifeline interface is denied here like any
// other, and the drop carries no iifname (#6492 Finding A). During the fence
// window even a `system-services all` zone is denied (maximally fail-closed); the
// next clean commit restores the real
// accepts. It is the single body shared by the host-inbound fence
// (xpf_hostinbound, priority 10, #5644) and the lo0 fence (xpf_lo0, priority 0,
// #6476) so their admit/deny posture can never diverge. Empty address inputs
// intentionally produce a zero-drop table shell.
func buildFenceTablePayload(tableName string, priority int, views []dpuserspace.ZoneHostInboundView, unzonedV4, unzonedV6 []string, wgListenPorts []uint16) string {
	var rules []string
	rules = append(rules, "add table inet "+tableName)
	rules = append(rules, "delete table inet "+tableName)
	rules = append(rules, "table inet "+tableName+" {")
	rules = append(rules, "  chain input {")
	rules = append(rules, fmt.Sprintf("    type filter hook input priority %d; policy accept;", priority))
	rules = append(rules, hostInboundFenceMandatoryAdmits(wgListenPorts)...)
	for _, v := range views {
		if len(v.V4Addrs) > 0 {
			rules = append(rules, "    ip daddr "+nftAddrSet(v.V4Addrs)+" drop")
		}
		if len(v.V6Addrs) > 0 {
			rules = append(rules, "    ip6 daddr "+nftAddrSet(v.V6Addrs)+" drop")
		}
	}
	if len(unzonedV4) > 0 {
		rules = append(rules, "    ip daddr "+nftAddrSet(unzonedV4)+" drop")
	}
	if len(unzonedV6) > 0 {
		rules = append(rules, "    ip6 daddr "+nftAddrSet(unzonedV6)+" drop")
	}
	rules = append(rules, "  }")
	rules = append(rules, "}")
	return strings.Join(rules, "\n") + "\n"
}

// hostInboundFenceMandatoryAdmits returns the fence chain's mandatory-admit lines
// — return traffic and core L3 control, NOT a service exposure (mirrors the real
// chain's global accepts, counters omitted). Shared by the whole-table cold-boot
// fence (buildHostInboundFencePayload) and the additive gap fence
// (buildHostInboundGapFencePayload, #5789) so their admit posture can never drift
// apart: both must let established/related, host-terminated IPsec (ESP/AH), IPv6
// ND, v4/v6 PMTUD+error, and the configured WireGuard listen port through while
// dropping host-bound services to the fenced addresses.
func hostInboundFenceMandatoryAdmits(wgListenPorts []uint16) []string {
	admits := []string{
		"    ct state established,related accept",
		// Raw ESP (50) / AH (51) so the kernel XFRM stack can decrypt
		// host-terminated IPsec (mirrors the real chain and userspace passthrough).
		"    meta l4proto { 50, 51 } accept",
		// IPv6 ND + v4/v6 PMTUD/error control messages — mandatory link operation.
		"    icmpv6 type { 1, 2, 3, 4 } accept",
		"    icmpv6 type { 133, 134, 135, 136, 137 } accept",
		"    icmp type { destination-unreachable, time-exceeded, parameter-problem } accept",
	}
	// The XDP shim steers local-destination UDP on the WG listen port to the
	// kernel WG socket; admit it so a responder-only tunnel is not black-holed by
	// the fence (mirrors emitHostInboundWireGuardAccept). No-op when WG is unset.
	if len(wgListenPorts) > 0 {
		admits = append(admits, "    udp dport "+renderWireGuardPortSpec(wgListenPorts)+" accept")
	}
	return admits
}

// hostInboundDropAddrKey canonicalizes a firewall-local destination address into
// the coverage-set key "<fam>|<addr>" (fam '4' or '6', #5789). The address text
// is used verbatim (the builders already emit bare host addresses).
func hostInboundDropAddrKey(fam byte, addr string) string {
	return string(fam) + "|" + addr
}

// hostInboundDesiredDropAddrs returns the set of firewall-local DESTINATION
// addresses the REAL host-inbound payload would install a catch-all DROP for in
// THIS snapshot (#5789): the union of every zone view's V4/V6 addresses and the
// addressed-but-unzoned sets, keyed by hostInboundDropAddrKey. This is the exact
// destination-coverage set compared against the retained generation's covered set
// to find an address that appeared AFTER the retained table was installed.
// junos-host PROGRAM (iifname) scopes are deliberately excluded: a program is
// address-independent, so a new ADDRESS on a program-covered interface surfaces
// here as a new destination key — precisely the #5789 path-2 gap.
func hostInboundDesiredDropAddrs(views []dpuserspace.ZoneHostInboundView, unzonedV4, unzonedV6 []string) map[string]struct{} {
	set := map[string]struct{}{}
	add := func(fam byte, addrs []string) {
		for _, a := range addrs {
			set[hostInboundDropAddrKey(fam, a)] = struct{}{}
		}
	}
	for _, v := range views {
		add('4', v.V4Addrs)
		add('6', v.V6Addrs)
	}
	add('4', unzonedV4)
	add('6', unzonedV6)
	return set
}

// hostInboundUncoveredDropAddrs returns the desired-drop addresses (v4, v6, bare,
// de-duplicated, sorted) that are NOT in `covered` — the destinations the
// retained generation has no deny for (#5789). Empty covered (cold boot) makes
// every desired address uncovered. The returned lists feed
// buildHostInboundGapFencePayload.
func hostInboundUncoveredDropAddrs(views []dpuserspace.ZoneHostInboundView, unzonedV4, unzonedV6 []string, covered map[string]struct{}) (v4, v6 []string) {
	seen4, seen6 := map[string]struct{}{}, map[string]struct{}{}
	consider := func(fam byte, addrs []string, seen map[string]struct{}, out *[]string) {
		for _, a := range addrs {
			if _, dup := seen[a]; dup {
				continue
			}
			if _, ok := covered[hostInboundDropAddrKey(fam, a)]; ok {
				continue
			}
			seen[a] = struct{}{}
			*out = append(*out, a)
		}
	}
	for _, view := range views {
		consider('4', view.V4Addrs, seen4, &v4)
		consider('6', view.V6Addrs, seen6, &v6)
	}
	consider('4', unzonedV4, seen4, &v4)
	consider('6', unzonedV6, seen6, &v6)
	sort.Strings(v4)
	sort.Strings(v6)
	return v4, v6
}

// buildHostInboundGapFencePayload assembles the #5789 ADDITIVE gap fence: a
// SEPARATE inet xpf_hostinbound_gap table at nftHostInboundGapPriority (strictly
// AFTER the main xpf_hostinbound table) that denies ONLY the supplied uncovered
// firewall-local addresses, admitting the same mandatory L3 / return traffic as
// the cold-boot fence. Unlike the whole-table cold-boot fence it does NOT replace
// xpf_hostinbound, so the retained generation's per-service ACCEPTS for
// already-covered addresses stay intact (the issue's "do not weaken retained
// valid rules"): a covered address is service-accepted or catch-all-dropped by
// the main table (prio 10) and either way its verdict is unchanged, while a
// newly-appeared uncovered address falls through the main chain's policy-accept
// and is dropped here. The uncovered lists inherit the same lifeline treatment as
// the views/unzoned sets they derive from — lifeline INTERFACES excluded, lifeline
// address VALUES not — so a management address shared onto a non-lifeline
// interface can be fenced here too, with no iifname to distinguish the ingress
// path (#6492 Finding A applies to this fence as well). Callers must only invoke this
// with a non-empty uncovered set (an all-empty payload would be a pointless
// zero-drop shell); an empty set instead deletes the table.
func buildHostInboundGapFencePayload(uncoveredV4, uncoveredV6 []string, wgListenPorts []uint16) string {
	var rules []string
	rules = append(rules, "add table inet xpf_hostinbound_gap")
	rules = append(rules, "delete table inet xpf_hostinbound_gap")
	rules = append(rules, "table inet xpf_hostinbound_gap {")
	rules = append(rules, "  chain input {")
	rules = append(rules, fmt.Sprintf("    type filter hook input priority %d; policy accept;", nftHostInboundGapPriority))
	rules = append(rules, hostInboundFenceMandatoryAdmits(wgListenPorts)...)
	if len(uncoveredV4) > 0 {
		rules = append(rules, "    ip daddr "+nftAddrSet(uncoveredV4)+" drop")
	}
	if len(uncoveredV6) > 0 {
		rules = append(rules, "    ip6 daddr "+nftAddrSet(uncoveredV6)+" drop")
	}
	rules = append(rules, "  }")
	rules = append(rules, "}")
	return strings.Join(rules, "\n") + "\n"
}

// hostInboundFailOpenState groups the three previous-apply host-inbound
// fail-open / ambiguity sets used purely for low-noise state-transition
// logging. It is increment 4 of the #4407 Daemon god-struct decomposition —
// the fields moved verbatim from flat Daemon fields (dropping the redundant
// hostInbound prefix), no behavior/locking change. Every access site is bounded
// to this file (the diff/log functions below) plus its 3698/3718 tests, so a
// named sub-field on Daemon (d.hostInboundFailOpen.<field>) is used rather than
// an embed. All three maps are written and read only under applySem via
// applyHostInboundFilter.
type hostInboundFailOpenState struct {
	// addresslessZones is the set of configured host-inbound-enforcing zones
	// observed in the transient fail-open admit window on the PREVIOUS apply
	// (#3698): a zone with a non-lifeline interface but no resolvable address
	// yet, so the daemon emits no host-inbound deny for it.
	addresslessZones map[string]bool

	// addresslessIfaces is the set of {zone, interface-unit, family} host-inbound
	// fail-open windows observed on the PREVIOUS apply (#3710), keyed as
	// "<zone>|<iface>|<family>". This is the per-interface/per-family refinement
	// of addresslessZones: a DHCP/DHCPv6 client on a non-lifeline unit with no
	// resolved address in that family yet, which the zone-level signal hides in a
	// MIXED zone (a DHCP-pending unit beside a statically-addressed sibling, or
	// the v6 side of a dual-stack edge whose v6 lease lands after v4).
	addresslessIfaces map[string]bool

	// ambiguousAddrs is the set of firewall-local addresses observed on the
	// PREVIOUS apply that are host-inbound-reachable from more than one security
	// zone with DIFFERING host-inbound service/protocol sets (#3718 Option B),
	// keyed as "<family>|<addr>". The kernel host-inbound chain matches
	// destination address only, so such an address's admission verdict is decided
	// order-dependently by whichever zone sorts first (and can disagree with the
	// ingress-scoped userspace-dp path). The strict commit gate rejects this; a
	// tolerant / peer-synced load (#1960) can slip one through, and unlike the
	// addressless window it is NOT self-healing.
	ambiguousAddrs map[string]bool
}

// logHostInboundAddresslessTransitions emits a state-transition log whenever a
// configured host-inbound-enforcing zone ENTERS or LEAVES the transient
// fail-open admit window (#3698) — a zone with a non-lifeline interface but no
// resolvable address yet, for which the kernel host-inbound chain emits no deny.
// It compares the current addressless set against the set observed on the
// previous apply (d.hostInboundFailOpen.addresslessZones) so a zone that stays addressless
// across repeated commits / DHCP renewals is logged once (on entry), not every
// apply — the low-noise contract for an address-snapshot transition. Recovery
// is observed before the nft transaction below, so the log is not publication
// proof. Runs under applySem
// (the sole caller, applyHostInboundFilter, is invoked from applyConfigLocked),
// so the map access needs no extra locking. The current window is also exported
// as the xpf_host_inbound_addressless_zones gauge (pkg/api), which is scraped
// from the active config independently of this log.
func (d *Daemon) logHostInboundAddresslessTransitions(cfg *config.Config) {
	current := make(map[string]bool)
	for _, z := range dpuserspace.AddresslessEnforcingZones(cfg) {
		current[z.Zone] = true
		if !d.hostInboundFailOpen.addresslessZones[z.Zone] {
			slog.Warn("host-inbound zone has no address yet — host-inbound default-deny NOT enforced for it until an address appears (transient fail-open admit window)",
				"zone", z.Zone, "interfaces", strings.Join(z.Interfaces, ","))
		}
	}
	for zone := range d.hostInboundFailOpen.addresslessZones {
		if !current[zone] {
			// This reports snapshot recovery before nftApplyPayload runs; installation
			// success is determined later in applyHostInboundFilter.
			slog.Info("host-inbound zone now has an address — host-inbound default-deny enforced (fail-open admit window closed)",
				"zone", zone)
		}
	}
	d.hostInboundFailOpen.addresslessZones = current
}

// logHostInboundAddresslessIfaceTransitions emits a state-transition log whenever
// a {zone, interface-unit, family} ENTERS or LEAVES the transient host-inbound
// fail-open admit window at per-interface/per-family granularity (#3710). The
// zone-level logHostInboundAddresslessTransitions above marks a zone scoped (and
// stays silent) as soon as ANY of its interfaces resolves ANY address in EITHER
// family, so a MIXED zone hides the gap: a DHCP-pending interface beside a
// statically-addressed sibling, or the IPv6 side of a dual-stack edge whose v6
// lease lands after its v4. Enforcement is per-destination-address and per-family
// (the kernel chain emits `<fam> daddr <set> ... drop` separately for inet and
// inet6), so those finer gaps are real fail-open windows the zone-level collapse
// cannot express. It compares the current per-interface set against the set
// observed on the previous apply (d.hostInboundFailOpen.addresslessIfaces) so a unit that
// stays DHCP-pending across repeated commits / renewals is logged once (on
// entry), not every apply. Runs under applySem (via applyHostInboundFilter), so
// the map access needs no extra locking. The current set is also exported as the
// xpf_host_inbound_addressless_interfaces gauge (pkg/api), scraped independently.
func (d *Daemon) logHostInboundAddresslessIfaceTransitions(cfg *config.Config) {
	current := make(map[string]bool)
	for _, i := range dpuserspace.AddresslessEnforcingInterfaces(cfg) {
		key := i.Zone + "|" + i.Interface + "|" + i.Family
		current[key] = true
		if !d.hostInboundFailOpen.addresslessIfaces[key] {
			slog.Warn("host-inbound interface has no address in this family yet — host-inbound default-deny NOT enforced for it until a lease arrives (transient fail-open admit window); the zone-level signal is hidden by an addressed sibling / family",
				"zone", i.Zone, "interface", i.Interface, "family", i.Family, "reason", i.Reason)
		}
	}
	for key := range d.hostInboundFailOpen.addresslessIfaces {
		if !current[key] {
			// This reports snapshot recovery before nftApplyPayload runs; installation
			// success is determined later in applyHostInboundFilter.
			slog.Info("host-inbound interface now has an address in this family — host-inbound default-deny enforced (fail-open admit window closed)",
				"key", key)
		}
	}
	d.hostInboundFailOpen.addresslessIfaces = current
}

// logHostInboundAmbiguousTransitions emits a state-transition log whenever a
// firewall-local address ENTERS or LEAVES the #3718 ambiguity set — an address
// host-inbound-reachable from more than one security zone with DIFFERING
// host-inbound service/protocol sets. The kernel host-inbound chain matches on
// destination address only (no ingress predicate) over a single global input
// chain, so such an address's admission verdict is order-dependent (the
// earlier-sorting zone decides the packet) and can disagree with the
// ingress-scoped userspace-dp path — a zone-isolation failure. The strict commit
// gate (config.validateDuplicateHostLocalAddressStrict) rejects this; a tolerant
// / peer-synced load (#1960) can slip one through, and unlike the addressless
// window it does NOT self-heal, so the warning stands until the operator fixes
// the config. It compares against the set observed on the previous apply
// (d.hostInboundFailOpen.ambiguousAddrs) so a persisting ambiguity is logged once (on
// entry), not every apply. Runs under applySem (via applyHostInboundFilter), so
// the map access needs no extra locking. The current set is also exported as the
// xpf_host_inbound_ambiguous_addresses gauge (pkg/api), scraped independently.
func (d *Daemon) logHostInboundAmbiguousTransitions(cfg *config.Config) {
	current := make(map[string]bool)
	for _, a := range dpuserspace.AmbiguousHostInboundAddresses(cfg) {
		key := a.Family + "|" + a.Address
		current[key] = true
		if !d.hostInboundFailOpen.ambiguousAddrs[key] {
			slog.Warn("host-inbound address is reachable from multiple zones with differing host-inbound sets — the kernel destination-address-only verdict is order-dependent and may disagree with the ingress-scoped userspace path (zone-isolation failure); assign the address to one zone or make the host-inbound sets identical (#3718)",
				"address", a.Address, "family", a.Family, "zones", strings.Join(a.Zones, ","))
		}
	}
	for key := range d.hostInboundFailOpen.ambiguousAddrs {
		if !current[key] {
			slog.Info("host-inbound address ambiguity resolved — the address no longer has an order-dependent host-inbound verdict",
				"address", key)
		}
	}
	d.hostInboundFailOpen.ambiguousAddrs = current
}

// hostInboundHasEnforceableView reports whether at least one view in this
// snapshot carries a resolvable address. It is the view term of the fallback's
// address-scoped-DROP predicate; unzoned v4/v6 slices are separate terms.
// Static, VRRP-VIP and DHCP/DHCPv6-learned addresses all
// count: the live interface snapshot enumerates every kernel address via
// AddrList(FAMILY_ALL), so a DHCP-only interface with a live lease IS scoped
// (#3224 — see BuildZoneHostInboundViews). The only no-address case left is a
// configured zone whose interfaces have no static address AND no live address
// yet (e.g. a DHCP WAN before its first lease). That zone produces nothing for
// this snapshot. A later address can contribute only when an applicable apply
// reaches applyHostInboundFilter; nft success then determines kernel state.
func hostInboundHasEnforceableView(views []dpuserspace.ZoneHostInboundView) bool {
	for _, v := range views {
		if len(v.V4Addrs) > 0 || len(v.V6Addrs) > 0 {
			return true
		}
	}
	return false
}

// buildHostInboundFilterPayload assembles the exact `nft -f -` payload for the
// host-inbound kernel chain. Split out as a pure function so tests can
// parse-check the full payload without invoking nft. A syntax error on any line
// rejects the WHOLE payload (atomic load), so the chain fails closed-as-absent
// rather than half-applied.
//
// Atomic replace idiom: `add table` (create if absent), `delete table` (now
// always has a target -> removes the old chain AND its stateful objects), then a
// fresh `table { ... }` body. This replaces the plain create/flush/redefine used
// by lo0: `flush table` empties rules but does NOT delete named counter objects,
// so redeclaring the per-zone DROP counters (below) on the next commit would
// collide ("File exists"). delete+recreate guarantees the named counters are
// declared exactly once and never leaves a stale counter for a removed zone.
// (A consequence: the host-inbound deny counters reset to zero on every
// rebuild — every commit and every DHCP/DHCPv6 address change that re-renders
// the table. Prometheus rate() handles the reset; documented on the metric.)
//
// Layout of `chain input` (type filter hook input priority 10; policy accept —
// distinct from the xpf_lo0 chain's priority 0 so this host-inbound backstop
// evaluates AFTER the lo0 input filter, #3364):
//  1. ct state established,related accept   — return/ongoing host traffic.
//  2. meta l4proto { 50, 51 } accept — raw ESP/AH exemption for host-terminated
//     IPsec (mirrors the userspace stage_ipsec_passthrough_check); the kernel
//     XFRM stack decrypts before any host-inbound deny can apply.
//  3. icmpv6 ND + error/PMTUD accept, icmp error/PMTUD accept — IPv6 Neighbor
//     Discovery and v4/v6 PMTUD/error control messages (dest-unreachable,
//     packet-too-big, time-exceeded, parameter-problem) are mandatory link
//     operation, never a "service" exposure; accepted globally so a host-inbound
//     set omitting `ping` does not black-hole PMTUD/ND/error delivery. This set
//     is mirrored by the userspace host-inbound exemption (#3171) so kernel and
//     XSK LocalDelivery agree. Echo-request stays gated on the `ping` service.
//     3b. #5582: when WireGuard is configured, a coarse
//     `udp dport <configured-wg-listen-port(s)> accept` (emitHostInbound
//     WireGuardAccept). The shim steers local-destination UDP on the WG listen
//     port to the kernel WG socket, so the host-inbound filter must admit it or a
//     fresh passive handshake to a restricted zoned address is dropped by the
//     per-zone catch-all. A single global input-hook rule (input = host-destined
//     only), so it mirrors the shim's local-destination scope without touching
//     transit UDP; only the WG port is opened, so the restricted default holds.
//  4. Per host-inbound-configured zone, per family with addresses:
//     - if `any-service`: <fam> daddr <addrs> accept (and no deny — the
//     operator opened the zone to all services). NOT `all`: #3226 narrowed
//     `all` to the named union, so it flows through the per-match path below.
//     - else: one accept per listed service/protocol scoped to the zone addrs
//     (`protocols all` expands to the routing-protocol set — #3199, NOT a
//     blanket accept), then a catch-all
//     `<fam> daddr <addrs> counter name "<n>" drop` (Junos default-deny to the
//     host is a silent drop). The named counter `<n>` is declared at the top of
//     the table body and scraped per zone/family into the
//     xpf_host_inbound_kernel_denies_total metric (#3361) — distinct from the
//     userspace-dp xpf_host_inbound_denies_total path (#3326).
func buildHostInboundFilterPayload(views []dpuserspace.ZoneHostInboundView, unzonedV4, unzonedV6 []string, programs []dpuserspace.JunosHostProgram, wgListenPorts []uint16) string {
	// Pre-pass: collect the named DROP counters the chain will reference, so they
	// can be declared at the top of the table body BEFORE the chain. A counter is
	// emitted exactly when emitHostInboundZone emits a catch-all drop
	// (hostInboundEmitsDrop) — the two MUST agree on that condition or nft rejects
	// the load (reference to an undeclared counter / declared-but-unused is fine,
	// but an undeclared reference is a hard error).
	//
	// The counter name is keyed only on (zone, family) — and so is the DROP rule
	// that references it (emitHostInboundZone). With per-interface host-inbound
	// overrides (#3362) a single zone can yield MULTIPLE views sharing the same
	// v.Zone (an override view plus the zone-default view), each emitting its own
	// catch-all DROP that references the same "<zone>_<fam>" counter. That is the
	// intended aggregation (one per-zone/family kernel-deny counter the #3361
	// scraper reads back via ParseHostInboundDenyCounterName), but the declaration
	// must be emitted EXACTLY ONCE: nft rejects `counter <name> {}` declared
	// twice in the same table body ("File exists"). Dedup the declarations on the
	// counter NAME so each is declared once no matter how many views share a zone;
	// the per-view DROP rules below still all reference it.
	var counters []string
	seenCounter := map[string]bool{}
	addCounter := func(name string) {
		if seenCounter[name] {
			return
		}
		seenCounter[name] = true
		counters = append(counters, name)
	}
	// #4759: the GLOBAL ICMP-error / ND accept rules emitted below carry named
	// nft counters so the host-inbound admit path is observable per type-class
	// (ICMPv6 ND, ICMPv6 error/PMTUD, ICMPv4 error/PMTUD). Those accept rules are
	// UNCONDITIONAL (they precede every per-zone rule and are always present), so
	// declare all three counter objects up front — declaration and reference
	// always agree, no matter how many zones exist. The counters are AGGREGATE
	// (the accept rules are global, not per-zone).
	for _, typ := range xnft.HostInboundAcceptCounterTypes {
		addCounter(xnft.HostInboundAcceptCounterName(typ))
	}
	// #9637: a view's ingress-zone rules reference the same per-zone/family
	// counter, possibly in a family where the view has no address of its own, so
	// the declaration covers them too.
	ingressV4, ingressV6 := hostInboundIngressDestinations(views, unzonedV4, unzonedV6)
	for _, v := range views {
		if hostInboundEmitsDrop(v, v.V4Addrs) || hostInboundEmitsIngressDrop(v, ingressV4) {
			addCounter(xnft.HostInboundDenyCounterName(v.Zone, "ip"))
		}
		if hostInboundEmitsDrop(v, v.V6Addrs) || hostInboundEmitsIngressDrop(v, ingressV6) {
			addCounter(xnft.HostInboundDenyCounterName(v.Zone, "ip6"))
		}
	}
	// #4420 HI-2: the addressed-but-unzoned catch-all DROP references its own
	// named counter under the reserved junos-host sentinel label (declared here
	// exactly once, matching the per-zone declaration contract above).
	if len(unzonedV4) > 0 {
		addCounter(xnft.HostInboundDenyCounterName(dpuserspace.UnzonedHostInboundZoneLabel, "ip"))
	}
	if len(unzonedV6) > 0 {
		addCounter(xnft.HostInboundDenyCounterName(dpuserspace.UnzonedHostInboundZoneLabel, "ip6"))
	}
	// #4146: pre-declare the junos-host DENY counters. A distinct-prefix counter
	// (xnft.HostInboundJunosHostDenyCounterName) is referenced once per family
	// that a program renders a drop rule for; multiple drop rules of the same
	// (zone, family) share the ONE declaration (matching the multi-reference
	// contract above), so declare each unique name exactly once.
	for _, p := range programs {
		if len(p.RulesV4) > 0 {
			addCounter(xnft.HostInboundJunosHostDenyCounterName(p.Zone, "ip"))
		}
		if len(p.RulesV6) > 0 {
			addCounter(xnft.HostInboundJunosHostDenyCounterName(p.Zone, "ip6"))
		}
	}

	var rules []string
	rules = append(rules, "add table inet xpf_hostinbound")
	rules = append(rules, "delete table inet xpf_hostinbound")
	rules = append(rules, "table inet xpf_hostinbound {")
	for _, cn := range counters {
		// The DECLARATION must be UNQUOTED (#3578): nft v1.1.6 rejects a quoted
		// name in a counter declaration (`counter "<n>" {}` -> "syntax error,
		// unexpected quoted string"), even though it accepts a quoted name in the
		// REFERENCE below. cn is sanitized to a bare-safe nft identifier by
		// HostInboundDenyCounterName, so the unquoted declaration always parses and
		// matches the (quoted) reference object name byte-for-byte.
		rules = append(rules, "  counter "+cn+" {")
		rules = append(rules, "  }")
	}
	rules = append(rules, "  chain input {")
	// #3364: explicit distinct priority so host-inbound evaluates AFTER xpf_lo0.
	rules = append(rules, fmt.Sprintf("    type filter hook input priority %d; policy accept;", nftHostInboundPriority))
	// #4146: when a `to-zone junos-host` DENY program is enforced, the chain is
	// restructured into Rust's coarse-then-fine order — the fine DROP must run
	// AFTER the genuinely pre-fine-exempt accepts (ESP/AH + firewall-originated
	// reply-direction established) but BEFORE the ND/PMTUD accepts and the
	// residual full established accept, because Rust runs the fine junos-host
	// policy after coarse ND/PMTUD admission (a denied source's ND/PMTUD/original-
	// direction-established inbound MUST also be dropped, mirroring the per-hit
	// re-eval/teardown at poll_descriptor/mod.rs:1291). With no junos-host program
	// the chain is byte-identical to the pre-#4146 order.
	if len(programs) > 0 {
		// (1) Raw ESP (50) / AH (51) — GENUINELY fine-exempt: the userspace IPsec
		// passthrough stage returns before the fine junos-host policy, and the
		// kernel XFRM stack decrypts host-terminated IPsec before any deny.
		rules = append(rules, "    meta l4proto { 50, 51 } accept")
		// (2) Firewall-ORIGINATED reply traffic (host-OUTBOUND flow return).
		// junos-host governs host-INBOUND original-direction only, so only the
		// reply direction is admitted ahead of the fine DROP; the denied source's
		// original-direction established inbound falls through to the DROP below.
		rules = append(rules, "    ct state established,related ct direction reply accept")
		// (3) Fine junos-host programs: per ingress zone, the exemption shields
		// and an iifname-scoped jump to the zone's first-match subchain (#9504).
		// Placed before the ND/PMTUD accepts (§6.4).
		for i, p := range programs {
			emitJunosHostProgramJump(&rules, i, p)
		}
		// (4) ND/PMTUD/ICMP-error accepts for NON-denied sources.
		emitHostInboundICMPAccepts(&rules)
		// (4b) #5582: coarse WireGuard listen-port admission. Placed AFTER the
		// fine junos-host DROP subchain so an explicit operator `to-zone
		// junos-host` deny of a WG source still wins; it is a coarse admit like
		// the ND/PMTUD accepts.
		emitHostInboundWireGuardAccept(&rules, wgListenPorts)
		// (5) Residual full established accept (non-denied established inbound).
		rules = append(rules, "    ct state established,related accept")
	} else {
		rules = append(rules, "    ct state established,related accept")
		// Raw ESP (50) / AH (51) are exempt from host-inbound enforcement so the
		// kernel XFRM stack can decrypt host-terminated IPsec — mirroring the
		// userspace stage_ipsec_passthrough_check, which runs BEFORE
		// host_inbound_admits (poll_descriptor mod.rs). Standard vSRX configures
		// the IPsec external zone with host-inbound `system-services { ike; }`
		// (IKE alone; ESP implicitly permitted): the `ike` token already accepts
		// udp 500/4500 (so IKE and NAT-T survive), and this exempts the raw ESP/AH
		// data plane (typical site-to-site). Without it a scoped `daddr <wan-ip>
		// drop` would black-hole the tunnel AFTER IKE succeeds — a silent upgrade
		// regression once #3070 turns a previously-no-op `ike` stanza into real
		// enforcement.
		rules = append(rules, "    meta l4proto { 50, 51 } accept")
		emitHostInboundICMPAccepts(&rules)
		// #5582: coarse WireGuard listen-port admission (see
		// emitHostInboundWireGuardAccept). A single global accept on the input
		// hook, so the shim-steered outer transport reaches the userspace WG
		// socket regardless of which zone's address it is destined to.
		emitHostInboundWireGuardAccept(&rules, wgListenPorts)
	}

	// #9637: the ingress-zone rules come first. A packet that arrives on a
	// view's own netdev is judged by that view's zone, whichever judged address
	// it names, and ends here: a listed service accepts it, or the drop does. A
	// packet on any other netdev matches none of these rules and meets the
	// destination-address rules below, which are unchanged. A netdev the scope
	// leaves out is judged exactly as before, and no packet reaches the accept
	// policy that did not before, because both rule sets judge the same
	// destination addresses.
	for _, v := range views {
		emitHostInboundZoneIngress(&rules, v, "ip", ingressV4)
		emitHostInboundZoneIngress(&rules, v, "ip6", ingressV6)
	}
	for _, v := range views {
		emitHostInboundZone(&rules, v, "ip", v.V4Addrs)
		emitHostInboundZone(&rules, v, "ip6", v.V6Addrs)
	}
	// #4420 HI-2: catch-all DROP for firewall-local addresses on interfaces in NO
	// security zone. Emitted AFTER the per-zone rules and the global
	// established / ESP-AH / ND / PMTUD accepts, so those still admit their
	// traffic on an unzoned interface (a decrypted host-terminated tunnel, ND,
	// PMTUD) while every other host-bound service/protocol is denied — the Junos
	// fail-closed posture for an interface with no zone. The address set is
	// already zone-subtracted by BuildUnzonedHostInboundAddrs and excludes lifeline
	// INTERFACES — but not lifeline address VALUES, so a management address on an
	// unzoned interface is denied here with no service accept in front of it.
	emitUnzonedHostInboundDeny(&rules, "ip", unzonedV4)
	emitUnzonedHostInboundDeny(&rules, "ip6", unzonedV6)
	rules = append(rules, "  }")
	// #9504: the junos-host subchains the input chain jumps to.
	for i, p := range programs {
		emitJunosHostProgramChain(&rules, i, p)
	}
	rules = append(rules, "}")
	return strings.Join(rules, "\n") + "\n"
}

// emitHostInboundICMPAccepts appends the GLOBAL IPv6 ND + v4/v6 PMTUD/error
// control-message accepts — admitted regardless of the host-inbound set so
// enforcement never breaks core L3 operation. The ICMP error subtypes accepted
// here MUST stay in lock-step with the userspace host-inbound exemption
// (`is_icmp_host_inbound_global_accept` in
// userspace-dp/.../forwarding/host_inbound.rs, #3171) so the kernel chain and
// the XSK LocalDelivery classifier agree on a configured ping-less zone. icmpv6
// type 1 (destination-unreachable), 2 (packet-too-big, PMTUD), 3 (time-exceeded),
// 4 (parameter-problem); 133-137 are Neighbor Discovery. ICMPv4
// destination-unreachable (3, PMTUD frag-needed code 4), time-exceeded (11) and
// parameter-problem (12). Echo-request is NOT here — it stays gated on the
// per-zone `ping` system-service. #4759: each accept carries a named AGGREGATE
// counter (global rules, not per-zone). Factored out (#4146) so the payload
// builder can place it either before the per-zone rules (no junos-host program)
// or AFTER the fine junos-host DROP (coarse-then-fine order).
func emitHostInboundICMPAccepts(rules *[]string) {
	*rules = append(*rules, "    icmpv6 type { 1, 2, 3, 4 } counter name \""+xnft.HostInboundAcceptCounterName(xnft.HostInboundAcceptICMP6Error)+"\" accept")
	*rules = append(*rules, "    icmpv6 type { 133, 134, 135, 136, 137 } counter name \""+xnft.HostInboundAcceptCounterName(xnft.HostInboundAcceptICMP6ND)+"\" accept")
	*rules = append(*rules, "    icmp type { destination-unreachable, time-exceeded, parameter-problem } counter name \""+xnft.HostInboundAcceptCounterName(xnft.HostInboundAcceptICMP4Error)+"\" accept")
}

// emitHostInboundWireGuardAccept appends the #5582 dynamic WireGuard listen-port
// admission: a single coarse `udp dport <configured-wg-port(s)> accept` on the
// host-inbound input hook.
//
// The XDP shim deliberately steers local-destination UDP on the configured WG
// listen port to the kernel (userspace-xdp wg_steer_to_kernel) so the userspace
// WireGuard control socket receives the outer transport. Without this accept a
// FRESH passive (responder-only) handshake — conntrack NEW, so the leading
// `ct state established,related accept` does not cover it — misses the per-zone
// service accepts and is dropped by the host-inbound catch-all (or the #4420
// addressed-but-unzoned catch-all), so a supported responder-only WireGuard
// listener can never come up on a restricted zoned address.
//
// The rule is emitted ONCE, not per zone. The nft input hook only ever sees
// host-destined packets, so a bare `udp dport <port>` admits the WG port to
// EVERY firewall-local address — exactly the shim's `is_local_destination`
// steering scope — while transit/forward UDP (which traverses the forward hook,
// never this input chain) is untouched, so transit/DNAT UDP on the WG port is
// never shunted around policy. Only the configured WG port(s) are opened; every
// other host-bound service stays governed by the per-zone default-deny, so the
// restricted-default posture is preserved.
//
// The port set is the compile-time SSOT config.WireGuardListenPorts() (all
// configured WG tunnels). The shim's single-port WG-RX steering (S2a) only
// steers the FIRST configured listen port today.
//
// #9016: this comment previously called the second port's rule "a no-op at the
// kernel (nothing steers that port up)". It is NOT a no-op. The rule is what
// ADMITS that port's traffic to the host, where the second tunnel's own bound
// socket (the helper spawns a control thread per wireguard endpoint) receives
// it. Unsteered means "not on the AF_XDP fast path", not "inert".
//
// #9521: what that socket does with it changed. Handshake and cookie records
// are processed as before, so admitting every configured port is still
// load-bearing — without it an unsteered tunnel could not complete even a
// passive handshake to a restricted zone. A TRANSPORT record that reaches an
// unsteered port's socket is now dropped by the helper instead of being
// decrypted onto the wgN TUN for the kernel to forward with no zone policy.
// This filter is deliberately NOT where that is enforced: an input-hook admit
// list cannot refuse `ct established` traffic answering a handshake xpf itself
// initiated (the chain accepts established traffic ahead of this rule), a zone
// that admits every host-inbound service accepts the port regardless, and no
// table is installed at all when nothing needs one. The helper's socket is the
// one place every such record converges. No-op when WG is not configured.
func emitHostInboundWireGuardAccept(rules *[]string, wgListenPorts []uint16) {
	if len(wgListenPorts) == 0 {
		return
	}
	*rules = append(*rules, "    udp dport "+renderWireGuardPortSpec(wgListenPorts)+" accept")
}

// renderWireGuardPortSpec renders the WireGuard listen-port set as an nft
// destination-port value: a single port ("51820") or an anonymous set
// ("{ 51820, 51821 }"). Ports arrive sorted+deduped from
// config.WireGuardListenPorts().
func renderWireGuardPortSpec(ports []uint16) string {
	if len(ports) == 1 {
		return strconv.Itoa(int(ports[0]))
	}
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(int(p))
	}
	return "{ " + strings.Join(parts, ", ") + " }"
}

// emitJunosHostProgramJump appends one ingress zone's entry into its fine
// `to-zone junos-host` program (#4146): the fine-eligible-L4 exemption shields
// (ahead of an `application any` deny-class rule), then an iifname-scoped jump
// to the zone's subchain. The subchain holds the first-match rules and a permit
// RETURNS from it (#9504), so no fine accept is ever emitted and the coarse
// host-inbound gate below stays the sole admit authority (Rust
// poll_descriptor/mod.rs:138).
func emitJunosHostProgramJump(rules *[]string, index int, p dpuserspace.JunosHostProgram) {
	if p.HasApplicationAnyDeny {
		if p.CoarseAdmitsIKE {
			// The coarse gate admits IKE (udp 500/4500) from any source, and the
			// userspace IPsec passthrough reinjects it before the fine policy, so
			// the fine drop must not swallow it. #5565: scope the shield to the
			// SPECIFIC netdevs whose effective per-interface host-inbound set admits
			// IKE (IKEExemptNetdevs), NOT the whole zone iifname set — a per-
			// interface `ike` override must not leak to a sibling interface. A
			// zone-level `ike` yields the full IngressIfnames set (zone-wide).
			ikeIif := nftIifnameSet(p.IKEExemptNetdevs)
			*rules = append(*rules, "    iifname "+ikeIif+" udp dport { 500, 4500 } accept")
		}
		if p.CoarseIdentResets {
			// The effective coarse verdict for TCP/113 is a RST (ident-reset set AND
			// not all/any-service); preserve it ahead of the silent drop. #5565:
			// scope to IdentResetNetdevs (the interfaces that configured
			// ident-reset), never the whole zone.
			identIif := nftIifnameSet(p.IdentResetNetdevs)
			*rules = append(*rules, "    iifname "+identIif+" tcp dport 113 reject with tcp reset")
		}
	}
	*rules = append(*rules, "    iifname "+nftIifnameSet(p.IngressIfnames)+" jump "+xnft.HostInboundJunosHostChainName(index, p.Zone))
}

// emitJunosHostProgramChain appends a zone's subchain (#9504): every projected
// rule in first-match order, IPv4 then IPv6. Each rule carries its family, so an
// IPv6 packet never meets an IPv4 rule of a later term. The chain's end returns,
// as the runtime delivers a host-bound packet no junos-host policy matches.
func emitJunosHostProgramChain(rules *[]string, index int, p dpuserspace.JunosHostProgram) {
	*rules = append(*rules, "  chain "+xnft.HostInboundJunosHostChainName(index, p.Zone)+" {")
	for _, r := range p.RulesV4 {
		emitJunosHostRule(rules, p.Zone, r)
	}
	for _, r := range p.RulesV6 {
		emitJunosHostRule(rules, p.Zone, r)
	}
	*rules = append(*rules, "  }")
}

// emitJunosHostRule renders one projected rule: one nft rule per L4 fragment, or
// one for `application any`. A verdict that answers TCP with a RST (a reject, or
// a deny on a tcp-rst zone) renders an `application any` rule as two, the TCP
// rule first. A return carries no counter: the counter counts denies.
func emitJunosHostRule(rules *[]string, zone string, r config.JunosHostDenyRule) {
	head := "    meta nfproto " + junosHostNfproto(r.Family)
	preds := junosHostSrcPredicate(r) + junosHostDstPredicate(r)
	cn := xnft.HostInboundJunosHostDenyCounterName(zone, r.Family)
	if len(r.L4) == 0 {
		if r.Verdict.SplitsTCP() {
			*rules = append(*rules, head+" meta l4proto tcp"+preds+junosHostVerdictText(r.Verdict, cn, true))
		}
		*rules = append(*rules, head+preds+junosHostVerdictText(r.Verdict, cn, false))
		return
	}
	for _, f := range r.L4 {
		line := head
		if l4 := renderJunosHostL4(f, r.Family); l4 != "" {
			line += " " + l4
		}
		*rules = append(*rules, line+preds+junosHostVerdictText(r.Verdict, cn, f.Proto == config.HostInboundProtoTCP))
	}
}

// junosHostVerdictText renders a rule's counter and verdict. tcp says the rule
// matches only TCP, which selects the RST for a verdict that answers TCP with
// one.
func junosHostVerdictText(v config.JunosHostVerdict, counter string, tcp bool) string {
	c := " counter name \"" + counter + "\""
	switch {
	case v == config.JunosHostReturn:
		return " return"
	case v.SplitsTCP() && tcp:
		return c + " reject with tcp reset"
	case v == config.JunosHostReject:
		return c + " reject with icmpx type admin-prohibited"
	default:
		return c + " drop"
	}
}

// junosHostNfproto is the `meta nfproto` value for a rule family.
func junosHostNfproto(family string) string {
	if family == "ip6" {
		return "ipv6"
	}
	return "ipv4"
}

// junosHostSrcPredicate builds the leading-space source predicate for a
// junos-host rule: the positive/excluded/any source match. Returns "" for an
// unconstrained source (the rule matches every source of its family).
func junosHostSrcPredicate(r config.JunosHostDenyRule) string {
	var b strings.Builder
	switch {
	case r.SrcExcluded && len(r.Src) > 0:
		b.WriteString(" " + r.Family + " saddr != " + nftAddrSet(r.Src))
	case r.SrcAny || (r.SrcExcluded && len(r.Src) == 0):
		// match every source (no positive saddr predicate)
	default:
		if len(r.Src) > 0 {
			b.WriteString(" " + r.Family + " saddr " + nftAddrSet(r.Src))
		}
	}
	return b.String()
}

// junosHostDstPredicate builds the leading-space destination predicate for a
// DROP rule from an explicit `match destination-address` (#4146 destination
// slice). Returns "" for `destination-address any` — the case every pre-slice
// program rendered — so an unscoped deny is byte-identical to before.
//
// The chain hooks the INPUT path, so every packet it evaluates is already
// host-destined; a `daddr` predicate here narrows the deny to the firewall
// address(es) the operator authored. It is NEVER the zone scope — that stays
// `iifname` (a daddr-only scope both under- and over-denies across zones, plan
// §3.2).
func junosHostDstPredicate(r config.JunosHostDenyRule) string {
	switch {
	case r.DstExcluded && len(r.Dst) > 0:
		return " " + r.Family + " daddr != " + nftAddrSet(r.Dst)
	case r.DstAny || (r.DstExcluded && len(r.Dst) == 0):
		// match every destination (no daddr predicate)
		return ""
	default:
		if len(r.Dst) > 0 {
			return " " + r.Family + " daddr " + nftAddrSet(r.Dst)
		}
	}
	return ""
}

// renderJunosHostL4 renders one L4 match fragment for a family. Returns "" only
// for a degenerate fragment (should not occur for a representable deny).
func renderJunosHostL4(f config.JunosHostDenyL4, family string) string {
	switch f.Proto {
	case config.HostInboundProtoTCP, config.HostInboundProtoUDP:
		kw := "tcp"
		if f.Proto == config.HostInboundProtoUDP {
			kw = "udp"
		}
		var parts []string
		if len(f.Ports) > 0 {
			parts = append(parts, kw+" dport "+renderHostInboundPortSpec(f.Ports))
		}
		if len(f.SourcePorts) > 0 {
			parts = append(parts, kw+" sport "+renderHostInboundPortSpec(f.SourcePorts))
		}
		if len(parts) == 0 {
			return "meta l4proto " + strconv.Itoa(int(f.Proto))
		}
		return strings.Join(parts, " ")
	case config.HostInboundProtoICMP, config.HostInboundProtoICMPv6:
		kw := "icmp"
		if f.Proto == config.HostInboundProtoICMPv6 {
			kw = "icmpv6"
		}
		if f.ICMPType == nil {
			return "meta l4proto " + strconv.Itoa(int(f.Proto))
		}
		s := kw + " type " + strconv.Itoa(int(*f.ICMPType))
		if f.ICMPCode != nil {
			s += " " + kw + " code " + strconv.Itoa(int(*f.ICMPCode))
		}
		return s
	default:
		return "meta l4proto " + strconv.Itoa(int(f.Proto))
	}
}

// nftIifnameSet renders an iifname predicate value: a single quoted name or an
// nft anonymous set of quoted names. Interface names carry '.' (VLAN units), so
// each name is quoted for the nft parser.
func nftIifnameSet(names []string) string {
	if len(names) == 1 {
		return "\"" + names[0] + "\""
	}
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = "\"" + n + "\""
	}
	return "{ " + strings.Join(quoted, ", ") + " }"
}

// emitUnzonedHostInboundDeny appends the #4420 HI-2 catch-all DROP for the given
// family's addressed-but-unzoned firewall-local addresses. It is a pure
// destination-scoped silent drop (Junos default-deny to the host) counted under
// the reserved junos-host sentinel label, so the #3361 kernel-deny scraper picks
// it up as zone="junos-host". No-op when the family has no unzoned address.
func emitUnzonedHostInboundDeny(rules *[]string, family string, addrs []string) {
	if len(addrs) == 0 {
		return
	}
	cn := xnft.HostInboundDenyCounterName(dpuserspace.UnzonedHostInboundZoneLabel, family)
	*rules = append(*rules, "    "+family+" daddr "+nftAddrSet(addrs)+" counter name \""+cn+"\" drop")
}

// hostInboundEmitsDrop reports whether emitHostInboundZone will emit a catch-all
// DROP (and therefore a named DROP counter) for this zone/family. A drop is
// emitted whenever the family has at least one address AND the zone is not opened
// to all services (`any-service`; NOT `system-services all`, narrowed to the
// named union by #3226). buildHostInboundFilterPayload
// uses this to pre-declare the matching counter objects, so the two sites cannot
// diverge on which (zone, family) pairs get a counter.
func hostInboundEmitsDrop(v dpuserspace.ZoneHostInboundView, addrs []string) bool {
	return len(addrs) > 0 && !hostInboundAllowsAll(v)
}

// emitHostInboundZone appends the accept(+drop) rules for one zone/family to
// rules. No-op when the zone has no address in this family.
func emitHostInboundZone(rules *[]string, v dpuserspace.ZoneHostInboundView, family string, addrs []string) {
	if len(addrs) == 0 {
		return
	}
	daddr := family + " daddr " + nftAddrSet(addrs)
	// Only `any-service` fully opens the zone: accept everything to its
	// addresses, emit no deny. `system-services all` does NOT — #3226 scoped it
	// to the named service union, so it takes the per-match path. `protocols all` is scoped to
	// the routing-protocol set (#3199) and flows through the per-match path
	// below, so it still gets a catch-all drop for non-routing traffic.
	if hostInboundAllowsAll(v) {
		*rules = append(*rules, "    "+daddr+" accept")
		return
	}
	rulesSet := hostInboundMatchSet(v, family)
	// Zero recognized service/protocol matches for this configured zone — a zone
	// with NO `host-inbound-traffic` stanza (#3405 default-deny parity), an empty
	// `host-inbound-traffic { }` stanza (#3200), or (on the tolerant load path) a
	// zone whose every token was an unrecognized typo that commit-time validation
	// downgraded to a warning rather than rejected. Fall through to emit ONLY the
	// catch-all drop below: the operator opened nothing, so Junos denies all
	// host-bound traffic to the zone, and the Rust AF_XDP classifier already fails
	// CLOSED for the same case (host_inbound_admits returns deny when the zone is
	// configured but matches nothing). Emitting nothing here would fail OPEN and leave the
	// kernel and Rust paths in disagreement — the #3200 split-brain. Management
	// / cluster-control lifeline interfaces are excluded from v.V4Addrs /
	// v.V6Addrs by BuildZoneHostInboundViews, and the established / ESP-AH / ND
	// / PMTUD accepts precede this drop, so a zero-match zone cannot strand
	// management or break HA. The strict commit path rejects unknown tokens
	// outright (validateHostInboundTokensStrict), so this zero-match branch is
	// normally reachable only for a genuinely empty stanza.
	// Each recognized service/protocol match is emitted with its per-token
	// nft verdict. Almost every host-inbound token is a plain `accept`;
	// `system-services ident-reset` is the lone exception (#3310): Junos
	// ident-reset actively RESETS inbound ident (auth/TCP-113) probes rather
	// than admitting them, so its rule carries `reject with tcp reset`. The
	// reject rule is emitted here, BEFORE the catch-all drop below, so a fresh
	// ident SYN (no `established` state) hits it; the leading
	// `ct state established,related accept` and the global ND/ESP/ICMP accepts
	// still precede it (a fresh probe is a SYN, so this is fine).
	for _, m := range rulesSet {
		*rules = append(*rules, "    "+daddr+" "+m.match+" "+m.action)
	}
	// Catch-all deny for anything else destined to this zone's addresses
	// (Junos default-deny to the host is a silent drop). Attach a named counter
	// (declared at the top of the table body by buildHostInboundFilterPayload) so
	// the kernel host-inbound drops are scrapeable per zone/family (#3361) — the
	// drop was previously uncounted and invisible to operators.
	cn := xnft.HostInboundDenyCounterName(v.Zone, family)
	*rules = append(*rules, "    "+daddr+" counter name \""+cn+"\" drop")
}

// hostInboundAllowsAll reports whether the zone's system-services contains
// `any-service` (full admit). Despite the name it does NOT match
// `system-services all` — #3226 narrowed that to the named union; the
// predicate is config.HostInboundFullAdmitService. `protocols all` is deliberately NOT a
// full admit (#3199): in Junos it means all ROUTING protocols, not all
// system-services and not a blanket accept. `protocols all` is expanded to the
// concrete routing-protocol match set by hostInboundProtocolMatches instead, so
// it never opens SSH/HTTPS/SNMP/NETCONF on the box.
func hostInboundAllowsAll(v dpuserspace.ZoneHostInboundView) bool {
	for _, s := range v.SystemServices {
		if config.HostInboundFullAdmitService(s) {
			return true
		}
	}
	return false
}

// hostInboundReject is the nft verdict for `system-services ident-reset`: a
// TCP reset (RST) for inbound ident (auth/TCP-113) probes, not an admit (#3310).
// nftables synthesizes an RFC-correct RST (RST|ACK with seq/ack reflecting the
// inbound SYN) for the matched TCP packet, exactly Junos ident-reset semantics.
// This is the only host-inbound token that emits a `reject` rather than
// `accept`. Validated to parse on the appliance nft (v1.1.x) in an `inet`
// filter input chain by TestHostInboundFilterIdentResetPayloadParses.
const hostInboundReject = "reject with tcp reset"

// hostInboundAccept is the default host-inbound verdict (admit the service to
// the host stack). Every recognized system-service / protocol uses it except
// ident-reset (see hostInboundServiceAction).
const hostInboundAccept = "accept"

// hostInboundRule pairs an nft match fragment (WITHOUT the leading daddr) with
// the nft verdict to apply to it. Almost every host-inbound token is an
// `accept`; ident-reset resets TCP/113 (#3310), so the verdict must travel with
// the match rather than being a uniform trailing `accept`.
type hostInboundRule struct {
	match  string // nft match fragment, e.g. "tcp dport 22"
	action string // nft verdict, e.g. "accept" or "reject with tcp reset"
}

// hostInboundServiceAction returns the nft verdict for a `system-services`
// token. Junos `ident-reset` actively RESETS inbound ident (TCP/113) probes
// rather than permitting the service (#3310), so it maps to
// `reject with tcp reset`; every other recognized service is a plain admit.
// Protocols (routing) are always admits, so they do not consult this.
func hostInboundServiceAction(token string) string {
	if token == "ident-reset" {
		return hostInboundReject
	}
	return hostInboundAccept
}

// hostInboundMatchSet returns the de-duplicated nft match fragments — each
// paired with its nft verdict (hostInboundRule) — admitted (or, for
// ident-reset, reset) by the zone's system-services + protocols for the given
// family ("ip" / "ip6"). The match clause carries NO leading daddr or trailing
// verdict; emitHostInboundZone prepends the daddr and appends rule.action.
//
// This is the Go/nftables MIRROR of the Rust classifier in
// userspace-dp/src/afxdp/forwarding/host_inbound.rs — keep the two token sets
// in sync (the recognized-token SSOT is config.KnownHostInboundSystemServices /
// config.KnownHostInboundProtocols; TestHostInboundNftMatchesKnownTokens
// asserts this matcher's domain equals that SSOT). An unrecognised token
// contributes nothing here; if it leaves the zone with zero recognized matches,
// emitHostInboundZone emits a catch-all drop (fail CLOSED, matching the Rust
// classifier). Strict commit-time rejection of unknown tokens lands in
// validateHostInboundTokensStrict (#3200), so a zero-match zone normally only
// arises from a genuinely empty `host-inbound-traffic { }` stanza.
//
// #3310 note: ident-reset carries the `reject with tcp reset` verdict on the
// kernel (primary) path. The Rust AF_XDP secondary path does NOT admit TCP/113
// (host_inbound.rs ident-reset arm is a no-op for the admit set), so the rare
// AF_XDP-reached ident packet is dropped there rather than reset — a documented
// divergence (the AF_XDP path is reached only by DNAT/static-NAT-to-113, an
// edge of an edge; the kernel chain carries ~100% of real ident probes). Both
// layers stop the prior plain-admit of 113.
func hostInboundMatchSet(v dpuserspace.ZoneHostInboundView, family string) []hostInboundRule {
	var out []hostInboundRule
	seen := map[string]bool{}
	add := func(m, action string) {
		if m == "" {
			return
		}
		// Dedup on the match fragment: no two host-inbound tokens map to the
		// same match with different verdicts (ident-reset's `tcp dport 113` is
		// unique — pgm's proto-113 is `meta l4proto 113`, a different match), so
		// match-keyed dedup cannot drop or shadow a reject rule.
		if seen[m] {
			return
		}
		seen[m] = true
		out = append(out, hostInboundRule{match: m, action: action})
	}
	// #3226: expand each authored token to the concrete services it stands for
	// (`all` → the named-service union; everything else → itself) and take the
	// verdict from the CONCRETE token. The verdict must not be keyed on the
	// AUTHORED token: `all` expands to a set that includes `ident-reset`, whose
	// rule is `reject with tcp reset`, and hostInboundServiceAction("all") is a
	// plain accept — so keying on the authored token would render
	// `tcp dport 113 accept` and ADMIT ident probes that the per-token form
	// resets. Expanding here makes `system-services all` render byte-identically
	// to the operator having listed the expansion explicitly.
	for _, s := range v.SystemServices {
		for _, sub := range config.HostInboundServiceTokenExpansion(s) {
			action := hostInboundServiceAction(sub)
			for _, m := range hostInboundServiceMatches(sub, family) {
				add(m, action)
			}
		}
	}
	for _, p := range v.Protocols {
		for _, m := range hostInboundProtocolMatches(p, family) {
			add(m, hostInboundAccept)
		}
	}
	return out
}

// hostInboundServiceMatches maps a Junos `system-services` token to nft match
// fragments for the given family. Returns nil for `any-service` (handled by
// hostInboundAllowsAll) and for unrecognised tokens (fail-closed). NOT for
// `system-services all`: #3226 narrowed that to the named union, so it is
// expanded token-by-token through this function like any other list.
//
// #3627 B1a: the token->tuple truth now lives in the structured SSOT
// config.HostInboundServiceMatch (shared with the match-policies host-inbound
// classifier); this function RENDERS those tuples to nft match fragments. The
// render is byte-identical to the pre-#3627 hand-written switch — proven by
// TestHostInboundNftRenderGoldenByteIdentical — so the nft kernel mirror is
// unchanged. The family gate (dhcp=v4, dhcpv6=v6, ...) is applied inside
// HostInboundServiceMatch via config.HostInboundServiceFamily.
func hostInboundServiceMatches(token, family string) []string {
	return renderHostInboundMatches(config.HostInboundServiceMatch(token, family), family)
}

// hostInboundProtocolMatches maps a Junos `protocols` (routing-protocol) token
// to nft match fragments. `all` expands to the full routing-protocol set
// (#3199) — NOT a blanket accept (that would open every system-service). Returns
// nil for unrecognised tokens (fail-closed).
//
// #3627 B1a: renders the structured SSOT config.HostInboundProtocolMatch (which
// owns the `all` expansion, the #3225 family gating, and the #3311 L2 no-op) to
// byte-identical nft fragments.
func hostInboundProtocolMatches(token, family string) []string {
	return renderHostInboundMatches(config.HostInboundProtocolMatch(token, family), family)
}

// renderHostInboundMatches renders a slice of structured host-inbound L4 match
// tuples (config.L4Match, the #3627 B1a SSOT) into nft match fragments,
// preserving the authored per-token order. The render is byte-identical to the
// pre-#3627 hand-written strings (guarded by
// TestHostInboundNftRenderGoldenByteIdentical):
//
//   - TCP/UDP -> "tcp dport <spec>" / "udp dport <spec>" (renderHostInboundPortSpec)
//   - ICMP/ICMPv6 -> "icmp type <spec>" / "icmpv6 type <spec>", coalescing
//     consecutive same-proto ICMP tuples into ONE type set so router-discovery
//     stays `icmp type { 9, 10 }` (one rule) rather than two
//   - a bare IP protocol -> "meta l4proto <n>"
//
// The Reject marker (ident-reset) does not affect the match fragment — the nft
// VERDICT is applied separately by hostInboundServiceAction — so this render is
// verdict-agnostic.
func renderHostInboundMatches(ms []config.L4Match, family string) []string {
	var out []string
	for i := 0; i < len(ms); {
		m := ms[i]
		switch m.Proto {
		case config.HostInboundProtoICMP, config.HostInboundProtoICMPv6:
			kw := "icmp"
			if m.Proto == config.HostInboundProtoICMPv6 {
				kw = "icmpv6"
			}
			var types []uint8
			for i < len(ms) && ms[i].Proto == m.Proto && ms[i].ICMPType != nil {
				types = append(types, *ms[i].ICMPType)
				i++
			}
			if len(types) == 0 {
				// Defensive: a degenerate entry (nil ICMPType on the FIRST
				// unconsumed ICMP/ICMPv6 match) advances zero iterations in
				// the loop above. The documented SSOT invariant (nil
				// ICMPType is never emitted for an ICMP proto,
				// config.L4Match doc comment) means every reachable caller
				// avoids this today, but nothing in the type system
				// enforces it — without this guard i never advances and
				// the outer loop spins on the same index forever (#4813).
				// There is no valid ICMP type to render, so skip emitting a
				// match fragment for this entry rather than rendering a
				// malformed empty nft set ("icmp type {  }").
				i++
				continue
			}
			out = append(out, kw+" type "+renderHostInboundICMPSpec(types, m.Proto))
		case config.HostInboundProtoTCP:
			out = append(out, "tcp dport "+renderHostInboundPortSpec(m.Ports))
			i++
		case config.HostInboundProtoUDP:
			out = append(out, "udp dport "+renderHostInboundPortSpec(m.Ports))
			i++
		default:
			out = append(out, "meta l4proto "+strconv.Itoa(int(m.Proto)))
			i++
		}
	}
	return out
}

// renderHostInboundPortSpec renders a TCP/UDP destination-port spec: a single
// port ("22"), a contiguous range ("33434-33523"), or an nft anonymous set of
// multiple ports ("{ 67, 68 }").
func renderHostInboundPortSpec(ports []config.PortRange) string {
	if len(ports) == 1 {
		return renderHostInboundPort(ports[0])
	}
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = renderHostInboundPort(p)
	}
	return "{ " + strings.Join(parts, ", ") + " }"
}

func renderHostInboundPort(p config.PortRange) string {
	if p.Lo == p.Hi {
		return strconv.Itoa(int(p.Lo))
	}
	return strconv.Itoa(int(p.Lo)) + "-" + strconv.Itoa(int(p.Hi))
}

// renderHostInboundICMPSpec renders an ICMP/ICMPv6 type spec. A single
// echo-request type (v4 8 / v6 128) renders as the nft named type
// "echo-request" — the only named ICMP type the per-token host-inbound rules
// use; every other type renders numerically ("{ 9, 10 }" for router-discovery).
func renderHostInboundICMPSpec(types []uint8, proto uint8) string {
	if len(types) == 1 {
		if (proto == config.HostInboundProtoICMP && types[0] == 8) ||
			(proto == config.HostInboundProtoICMPv6 && types[0] == 128) {
			return "echo-request"
		}
		return strconv.Itoa(int(types[0]))
	}
	parts := make([]string, len(types))
	for i, t := range types {
		parts[i] = strconv.Itoa(int(t))
	}
	return "{ " + strings.Join(parts, ", ") + " }"
}

// nftAddrSet renders a single address as a bare token or multiple as an nft
// anonymous set.
func nftAddrSet(addrs []string) string {
	if len(addrs) == 1 {
		return addrs[0]
	}
	return "{ " + strings.Join(addrs, ", ") + " }"
}

// nftFamilyAddrs keeps only the addresses belonging to the chain's family
// ("ip" -> IPv4, "ip6" -> IPv6), dropping the empty / "any" placeholders and the
// wrong-family literals. Dropping a WRONG-FAMILY literal mirrors the userspace
// matcher's per-family vectors (parse_address classifies each entry into
// source_v4 / source_v6, and the inet / inet6 chain only ever consults the
// matching family), so a v4 CIDR carried in an inet6 filter (#3433 H02) leaves
// THIS family's vector empty, which the matcher treats as the empty
// positive/except set. Each kept entry is re-rendered in its canonical form so a
// bare host IP and a CIDR are both valid nft right-hand sides.
//
// #6512: a MALFORMED token is kept VERBATIM instead of being silently dropped.
// The dropped-token behavior installed a NARROWED rule from a partially-
// malformed positive list (a discard/reject term then enforced a smaller address
// set than the operator wrote) and a WIDENED one from an except list — an
// all-malformed except list emptied and nftAddrPredicate's empty-except arm
// dropped the predicate entirely, leaving the direction unconstrained. Emitting
// the raw token makes `nft -f -` REJECT the whole ruleset and retain the prior
// generation, which is exactly the fail-closed posture this oracle already has
// for an unresolvable port / DSCP token (#6405) — and it keeps this oracle in
// agreement with filterFamilyAddrs in pkg/nftables/netlink_lo0.go, the
// production builder, which errors on the same token.
func nftFamilyAddrs(family string, addrs []string) []string {
	wantV6 := family == "ip6"
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if a == "" || a == "any" {
			continue
		}
		if pfx, err := netip.ParsePrefix(a); err == nil {
			if pfx.Addr().Is6() == wantV6 {
				out = append(out, pfx.String())
			}
			continue
		}
		if ip, err := netip.ParseAddr(a); err == nil {
			if ip.Is6() == wantV6 {
				out = append(out, ip.String())
			}
			continue
		}
		out = append(out, a)
	}
	return out
}

// nftAddrPredicate lowers one direction (saddr / daddr) of a firewall-filter
// term's address scope into an nft predicate, mirroring nets_match_v4/v6 in
// userspace-dp filter/engine/matching.rs so the kernel lo0 chain enforces the
// SAME verdict as the userspace matcher (#3433). It returns the predicate string
// (empty == no constraint, i.e. match ALL for this direction) and
// matchesNothing == true when the direction is constrained but resolves to no
// prefix of this family with a POSITIVE (non-except) scope — the Junos
// empty-positive-set semantic (match NOTHING). The caller skips the whole rule in
// that case (a term that matches nothing contributes no enforcement). Semantics,
// per family F:
//   - !constrained                         -> "" (no scope -> match ALL)
//   - constrained, no F-prefix, except     -> "" (match every addr NOT in {} = ALL)
//   - constrained, no F-prefix, positive   -> matchesNothing (match addr in {} = none)
//   - constrained, F-prefixes,  positive   -> "<fam> <field> { prefixes }"
//   - constrained, F-prefixes,  except     -> "<fam> <field> != { prefixes }"
func nftAddrPredicate(field, family string, addrs []string, except, constrained bool) (pred string, matchesNothing bool) {
	if !constrained {
		return "", false
	}
	famAddrs := nftFamilyAddrs(family, addrs)
	if len(famAddrs) == 0 {
		if except {
			// Empty except set -> "match every address NOT in {}" = match ALL ->
			// no predicate. Mirrors nets_match returning `except` for an empty set.
			return "", false
		}
		// Empty positive set -> "match addresses in {}" = match NOTHING. Fail
		// closed: the term matches no packet (the caller skips the rule).
		return "", true
	}
	op := family + " " + field + " "
	if except {
		op = family + " " + field + " != "
	}
	return op + nftAddrSet(famAddrs), false
}

// nftRulesFromTerm converts a firewall filter term to the nftables rule lines
// that mirror it onto the kernel lo0 input chain. It returns a slice because a
// single term can lower to ZERO rules (a match-nothing or a pure fall-through
// with no honored modifier), ONE rule (the common accept/discard/modifier-only
// case), or TWO rules (a faithful `reject` — a TCP RST plus an ICMP/ICMPv6
// admin-prohibited reply, #3445 H10). prefixLists expands source-prefix-list and
// destination-prefix-list references.
//
// #3445 modifier policy: the `then` modifiers nft CAN honor on a `hook input`
// chain are emitted (`then log`/`then syslog` -> nft `log`; `then count <name>`
// -> a named nft `counter`). The modifiers nft CANNOT faithfully honor on the
// host-inbound mirror (policer rate-limit, dscp-rewrite, forwarding-class,
// loss-priority CoS marking) are NOT silently dropped here — a commit-time
// WARNING names each such term+modifier (config.validateLo0FilterKernelMirror
// Warnings for policer/dscp-rewrite/forwarding-class, and the pre-existing #2507
// loss-priority warning), so the operator knows the kernel path will not enforce
// them. See pkg/daemon/README.md "lo0 input filter".
// joinNftFields joins the space-separated fragments of one nft rule (match
// predicates, non-terminating modifier statements, and the trailing verdict),
// skipping the empty fragments so a term with no match / no modifier renders as
// a clean `<verdict>` rather than carrying stray leading spaces.
func joinNftFields(fields ...string) string {
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f != "" {
			out = append(out, f)
		}
	}
	return strings.Join(out, " ")
}

// nftLo0LogPrefix builds the `log prefix` string for a mirrored `then log` /
// `then syslog` modifier (#3445). It carries the term name so an operator can
// correlate a kernel lo0-filter log line with the configured term, stripping the
// quote / backslash bytes that would break the quoted nft string and bounding
// the length to stay within nft's log-prefix limit.
func nftLo0LogPrefix(term string) string {
	const maxLen = 64
	safe := strings.NewReplacer(`"`, "", `\`, "").Replace(term)
	p := "xpf-lo0 " + safe + ": "
	if len(p) > maxLen {
		p = p[:maxLen]
	}
	return p
}

// nftTCPFlagOrder lists the TCP flag bits in canonical low-to-high bit order
// with their nftables symbolic names. The bit values match config.tcpFlagBits
// (the SSOT consumed by ParseTCPFlagsExpression) and userspace-dp/src/tcp_flags.rs.
var nftTCPFlagOrder = []struct {
	bit  uint8
	name string
}{
	{0x01, "fin"},
	{0x02, "syn"},
	{0x04, "rst"},
	{0x08, "psh"},
	{0x10, "ack"},
	{0x20, "urg"},
}

// nftTCPFlagNames renders a TCP-flags bit mask as the nftables symbolic flag
// list joined with " | " (e.g. 0x12 -> "syn | ack"). An empty mask renders as
// the numeric "0x0" so it is a valid right-hand side for the `== 0` (all-clear)
// case.
func nftTCPFlagNames(mask uint8) string {
	var names []string
	for _, f := range nftTCPFlagOrder {
		if mask&f.bit != 0 {
			names = append(names, f.name)
		}
	}
	if len(names) == 0 {
		return "0x0"
	}
	return strings.Join(names, " | ")
}

// nftTCPFlagsMatch renders the canonical nftables masked-equality TCP-flags
// match for a required/forbidden mask pair, the form that expresses the Junos
// AND-conjunction semantics (a segment matches when (flags & required) ==
// required && (flags & forbidden) == 0):
//
//	tcp flags & (<required|forbidden flag names>) == <required flag names>
//
// Both sides are parenthesized when they name more than one flag so nft's `|`
// precedence cannot reassociate the right-hand side across the `==`. A single
// flag, or the all-clear "0x0" right-hand side, needs no parentheses.
func nftTCPFlagsMatch(required, forbidden uint8) string {
	mask := required | forbidden
	maskExpr := nftTCPFlagNames(mask)
	if mask&(mask-1) != 0 { // more than one bit set
		maskExpr = "(" + maskExpr + ")"
	}
	reqExpr := nftTCPFlagNames(required)
	if required&(required-1) != 0 { // more than one bit set
		reqExpr = "(" + reqExpr + ")"
	}
	return "tcp flags & " + maskExpr + " == " + reqExpr
}

// nftDSCPValue converts a Junos DSCP name to the nftables symbolic name.
// nftables accepts: cs0-cs7, af11-af43, ef, or numeric values.
// nftIntSet renders an int slice as a single nft scalar (e.g. "8") or an nft
// anonymous set (e.g. "{ 8, 13 }") for multi-value match criteria (#2545).
func nftIntSet(vals []int) string {
	if len(vals) == 1 {
		return strconv.Itoa(vals[0])
	}
	strs := make([]string, len(vals))
	for i, v := range vals {
		strs[i] = strconv.Itoa(v)
	}
	return "{ " + strings.Join(strs, ", ") + " }"
}

// nftIntSetWithRaw renders the resolved ICMP bytes together with any raw token
// the compiler could NOT resolve (#6806).
//
// The raw token is deliberately emitted verbatim into the nft right-hand side.
// It is not valid nft, and that is the point: `nft -f -` loads the lo0 table
// atomically, so an invalid token REJECTS the whole ruleset and the prior
// generation stays installed — the fail-closed posture this oracle already has
// for an unresolvable port / DSCP token (#6405) and a malformed address
// literal (#6512). Rendering only the resolved bytes would silently widen the
// term instead, which is the #6806 fail-open.
//
// A cold boot has no prior generation to retain, and that case is covered:
// applyLo0Filter installs the #6476 cold-boot fail-closed fence whenever an
// install fails with no real filter enforced (#6489/#6492 keep the fence keyed
// on lo0Enforced and rebuilt from the CURRENT snapshot).
//
// With no unresolved tokens this is exactly nftIntSet, so a term that resolves
// cleanly renders byte-identically to before.
func nftIntSetWithRaw(vals []int, raw []string) string {
	if len(raw) == 0 {
		return nftIntSet(vals)
	}
	strs := make([]string, 0, len(vals)+len(raw))
	for _, v := range vals {
		strs = append(strs, strconv.Itoa(v))
	}
	strs = append(strs, raw...)
	if len(strs) == 1 {
		return strs[0]
	}
	return "{ " + strings.Join(strs, ", ") + " }"
}

// nftDSCPValue converts a firewall-filter DSCP / traffic-class match token to a
// numeric nft dscp token, resolving code-point NAMES through the
// dataplane.DSCPValues SSOT (#3436). The pre-fix pass-through was wrong on two
// counts that nft rejects atomically (failing the whole lo0 load) or that
// silently stop the kernel mirror matching:
//
//   - Case: the commit gate (filterDSCPResolvable) and the userspace matcher
//     (pkg/dataplane/userspace/filters.go, via strings.ToLower) accept names
//     case-insensitively, so `from dscp EF` reaches here as "EF" — but nft's
//     DSCP names are lowercase only, so `ip dscp EF` is a parse error.
//   - Name coverage: xpf accepts `be` (best-effort) as a code point, but nft
//     has NO `be` DSCP name at all — `ip dscp be` is unloadable.
//
// Resolving to the numeric value yields an unconditionally nft-safe token that
// matches the SAME code point as userspace (which resolves the identical table).
// A numeric 0..63 token passes through as-is. An unresolvable token is
// unreachable for a committed config (filterDSCPResolvable gates it); it is
// lower-cased as a best-effort fallback rather than emitted with stray case.
func nftDSCPValue(name string) string {
	if val, ok := dataplane.DSCPValues[strings.ToLower(strings.TrimSpace(name))]; ok {
		return strconv.Itoa(int(val))
	}
	if v, err := strconv.Atoi(strings.TrimSpace(name)); err == nil && v >= 0 && v <= 63 {
		return strconv.Itoa(v)
	}
	return strings.ToLower(strings.TrimSpace(name))
}

// lo0FlexMatchUnrepresentable reports whether a term's flexible-match-range
// cannot be rendered faithfully (#6804): more than one named range (#5823), an
// unparseable numeric token (UnknownFlexMatch), or a load width outside 1..4
// bytes.
//
// The width rule mirrors the userspace snapshot builder exactly: a zero
// bit-length defaults to 4 (32-bit) and an oversized width is NOT capped —
// capping would compare only the truncated window and BROADEN the match, which
// is the #3406 fail-open.
func lo0FlexMatchUnrepresentable(term *config.FirewallFilterTerm) bool {
	if len(term.FlexMatchRangeNames) > 1 || len(term.UnknownFlexMatch) > 0 {
		return true
	}
	if term.FlexMatch == nil {
		return false
	}
	n := nftFlexMatchByteLen(term.FlexMatch.BitLength)
	return n < 1 || n > 4
}

// nftFlexMatchByteLen is the payload load width in bytes for a bit length,
// matching the userspace snapshot builder (0 -> 4, else ceil(bits/8)).
func nftFlexMatchByteLen(bits uint8) int {
	if bits == 0 {
		return 4
	}
	return (int(bits) + 7) / 8
}

// nftFlexMatchExpr renders `@nh,<bitoff>,<bitlen> & <mask> == <value>`.
//
// The load width is whole BYTES (nft loads byte-aligned), so the bit length in
// the expression is the byte width times 8 — the sub-byte narrowing is carried
// by the mask, exactly as the userspace matcher does it. The expected value is
// pre-masked for the same reason the netlink builder pre-masks it: nft compares
// the MASKED load, so a value carrying bits outside the mask would never match,
// and a silent never-match is a different fail direction but just as quiet.
func nftFlexMatchExpr(fm config.FlexMatchConfig) string {
	n := nftFlexMatchByteLen(fm.BitLength)
	mask := fm.Mask
	value := fm.Value & mask
	if n < 4 {
		trunc := uint32(1)<<(uint(n)*8) - 1
		mask &= trunc
		value &= trunc
	}
	return fmt.Sprintf("@nh,%d,%d & 0x%x == 0x%x", int(fm.ByteOffset)*8, n*8, mask, value)
}
