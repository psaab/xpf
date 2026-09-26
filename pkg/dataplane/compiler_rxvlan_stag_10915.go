package dataplane

import (
	"fmt"
	"log/slog"
	"strings"
)

// #10915: the S-tag (802.1ad) RX-strip offload, `rx-vlan-stag-hw-parse`.
//
// The in-frame S-tag drop in userspace-xdp (see #10655) assumes the S-tag is
// visible in-frame — but on iavf VFs advertising
// VIRTCHNL_VLAN_ETHERTYPE_88A8 outer stripping, the NIC can strip 0x88a8 into
// skb->vlan_tci (unreadable to XDP) via this offload. Upstream iavf advertises
// NETIF_F_HW_VLAN_STAG_RX conditional on PF/VF virtchnl support, and ethtool
// maps it to `rx-vlan-stag-hw-parse` (net/ethtool/common.c). A stripped frame
// bypasses the in-frame drop and adjudicates as untagged/unit-0.
//
// This file mirrors the 802.1Q RX-VLAN path (#5268, #9946) for that offload:
// a shared classifier with absent/off/[fixed] handling, a disable path, and a
// fail-closed activation gate. The existing 802.1Q-only `rxvlan` control is
// unchanged; compile setup now checks both independent features, while the
// VLAN-scoped C-tag gate retains its established predicate.

// RxVlanStagHwParseState is what an `ethtool -k <iface>` query says about
// `rx-vlan-stag-hw-parse`, reduced to the three cases a caller acts on. It
// mirrors RxVlanOffloadState (#9946) feature for feature, including the two
// cases that exist to stop a fail-closed gate misfiring:
//
//   - Absent (query succeeded, feature not listed): the NIC has no such
//     offload and never strips an S-tag — probing it with `-K` would fail
//     "not supported", indistinguishable from a real refusal;
//   - Off (reported "off", including "off [fixed]"): no S-tags stripped,
//     and no toggle (a toggle on iavf VFs drives a driver reset that drops
//     in-flight packets).
//
// Anything else — reported "on" (including "on [fixed]", which can never be
// disabled), or a failed query (state UNKNOWN) — is NeedsDisable: attempt the
// disable, and treat a failure as a genuine fail-closed candidate.
type RxVlanStagHwParseState int

const (
	// RxVlanStagHwParseAbsent: the query SUCCEEDED and listed no
	// `rx-vlan-stag-hw-parse` feature at all.
	RxVlanStagHwParseAbsent RxVlanStagHwParseState = iota

	// RxVlanStagHwParseOff: reported "off", including "off [fixed]".
	RxVlanStagHwParseOff

	// RxVlanStagHwParseNeedsDisable: reported "on", OR the query itself
	// failed so the state is UNKNOWN.
	RxVlanStagHwParseNeedsDisable
)

// ClassifyRxVlanStagHwParse reduces an `ethtool -k <iface>` result to the
// state its caller acts on. It shares ClassifyRxVlanOffload's contract: a
// failed query is deliberately NOT Absent — an unreadable NIC is unknown,
// not safe — and only the value after the colon is read (the pre-#5268
// `strings.Contains(line, "off")` trap matches the feature NAME).
//
// Pure function of the query result, placed in pkg/dataplane (not behind the
// compile path) so a post-link-cycle re-disable can share it exactly as
// ClassifyRxVlanOffload is shared with pkg/daemon (#9946).
func ClassifyRxVlanStagHwParse(out []byte, queryErr error) RxVlanStagHwParseState {
	if queryErr != nil {
		return RxVlanStagHwParseNeedsDisable
	}
	for _, line := range strings.Split(string(out), "\n") {
		l := strings.TrimSpace(line)
		if !strings.HasPrefix(l, "rx-vlan-stag-hw-parse:") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(l, "rx-vlan-stag-hw-parse:"))
		if strings.HasPrefix(value, "off") {
			return RxVlanStagHwParseOff
		}
		// Reported "on" (or anything else the tool prints): disable it.
		return RxVlanStagHwParseNeedsDisable
	}
	return RxVlanStagHwParseAbsent
}

// ensureRxVlanParsePreconditions disables, on iface, every NIC RX offload
// that strips VLAN tags out of packet data into skb->vlan_tci (which XDP
// cannot read), so the XDP parser sees tags in-frame:
//
//   - rx-vlan-offload (the 802.1Q C-tag strip, `ethtool -K <if> rxvlan off`);
//   - rx-vlan-stag-hw-parse (the 802.1ad S-tag strip, `ethtool -K <if>
//     rx-vlan-stag-hw-parse off`).
//
// BOTH features are classified from a SINGLE `ethtool -k` query and share
// the one rxTagStripOffCache entry, which now means "XDP tag-parse
// preconditions confirmed for iface" rather than "the 802.1Q knob alone".
// Two queries would be a second subprocess per parent per compile for no
// information gain, and two caches would be an ordering trap: whichever
// ensure ran second would have to consult the first's cache to keep the
// seeded-cache tests honest, and a future reorder would silently skip one
// offload. One query, one cache, two per-feature errors.
//
// Error contract (per feature, mirroring #5268): a non-nil error means the
// offload is ACTIVE and could NOT be turned off (or the state cannot be
// determined and disabling failed). Absent/off/off-[fixed] returns nil for
// that feature without touching `-K`. The two errors are returned
// separately because their gates have DIFFERENT scopes: the 802.1Q failure
// fails closed only on a parent carrying configured VLAN subinterfaces
// (rxVlanOffloadActivationError), while the S-tag failure fails closed on
// EVERY XDP-adjudicated parent (rxVlanStagHwParseActivationError below).
//
// The cache is written only when BOTH features are confirmed: a partial
// failure retries the query next compile (query-first, so an already-off
// knob is never re-toggled into a driver reset).
func (r *CompileResult) ensureRxVlanParsePreconditions(iface string) (rxvlanErr, stagErr error) {
	if r.rxTagStripOffCache[iface] {
		return nil, nil
	}
	// One shared query; each feature is classified independently, so a NIC
	// with only one knob (or with one already off) disables exactly what
	// needs it. See ClassifyRxVlanOffload for why a NIC that lists no such
	// feature must NOT be probed with `-K`, and why a failed query counts
	// as "needs disable" rather than "safe".
	out, queryErr := runEthtool("-k", iface)
	rxvlanState := ClassifyRxVlanOffload(out, queryErr)
	stagState := ClassifyRxVlanStagHwParse(out, queryErr)
	if rxvlanState != RxVlanOffloadNeedsDisable && stagState != RxVlanStagHwParseNeedsDisable {
		// Already off (includes "off [fixed]"), or the NIC has no such
		// offload(s) at all: no tags stripped either way.
		r.rxTagStripOffCache[iface] = true
		return nil, nil
	}
	// Either the offload is ON, or the query failed (state unknown):
	// attempt to disable. Success => off; failure => the caller may fail
	// closed.
	if rxvlanState == RxVlanOffloadNeedsDisable {
		if out, err := runEthtool("-K", iface, "rxvlan", "off"); err != nil {
			slog.Warn("failed to disable rxvlan offload (HW-stripped tags cannot be parsed by XDP)",
				"interface", iface, "err", err, "output", strings.TrimSpace(string(out)))
			rxvlanErr = fmt.Errorf("disable rx-vlan-offload on %s: %w (output: %s)",
				iface, err, strings.TrimSpace(string(out)))
		}
	}
	if stagState == RxVlanStagHwParseNeedsDisable {
		if out, err := runEthtool("-K", iface, "rx-vlan-stag-hw-parse", "off"); err != nil {
			slog.Warn("failed to disable S-tag HW-parse offload (HW-stripped S-tags bypass the XDP in-frame drop)",
				"interface", iface, "err", err, "output", strings.TrimSpace(string(out)))
			stagErr = fmt.Errorf("disable rx-vlan-stag-hw-parse on %s: %w (output: %s)",
				iface, err, strings.TrimSpace(string(out)))
		}
	}
	if rxvlanErr == nil && stagErr == nil {
		r.rxTagStripOffCache[iface] = true
		slog.Info("disabled VLAN RX tag-strip offloads for XDP", "interface", iface)
	}
	return rxvlanErr, stagErr
}

// rxVlanStagHwParseActivationError decides whether a failure to disable the
// S-tag HW-parse offload on physName must FAIL ACTIVATION CLOSED (#10915).
// Like rxVlanOffloadActivationError, it passes nil through and wraps a
// fail-closed error, but its scope is EVERY XDP-adjudicated parent: there is
// deliberately no 802.1Q VLAN-subinterface predicate.
//
// Security rationale: the XDP dataplane's single-S-tag drop
// (USERSPACE_FALLBACK_REASON_STAG_DROP, #10655) reads the 0x88a8 tag
// SOLELY from in-frame packet data. If a NIC's S-tag HW-parse offload
// strips it into skb->vlan_tci (which XDP cannot read) and xpf cannot
// disable it, the stripped frame bypasses the drop and adjudicates as
// untagged/unit-0, falling back to the PHYSICAL parent ifindex — so an
// S-tag-domain frame is classified into the parent's zone on an XDP stack
// with no S-tag identity to steer by (zone confusion; the kernel side is
// 802.1Q-only and #5879 refuses QinQ configs, so there is no S-tag unit
// for it to land on).
//
// Unlike the 802.1Q offload — which only matters where tag-based zone
// classification is configured (hence the VLAN-subinterface predicate) —
// the S-tag drop is load-bearing on EVERY XDP-adjudicated parent: any wire
// can carry a 0x88a8 frame, and the stripping happens below XDP before any
// parent's configuration is consulted. A plain parent (no 802.1Q units)
// with an undisableable S-tag strip is therefore just as exposed as a VLAN
// parent, and its activation fails here too. NICs that legitimately lack
// the knob (absent/off/[fixed]) return nil from the ensure and are
// unaffected — the fail-closed verdict fires only when the offload is
// present and could not be confirmed off.
func rxVlanStagHwParseActivationError(physName string, ensureErr error) error {
	if ensureErr == nil {
		return nil
	}
	return fmt.Errorf(
		"interface %s: S-tag HW-parse offload could not be disabled (%w): XDP drops "+
			"single-S-tagged frames only from in-frame 0x88a8 tags, so a HW-stripped "+
			"S-tag would bypass the drop and adjudicate as untagged/unit-0 into the "+
			"parent's zone on a stack with no S-tag identity (zone confusion) — "+
			"failing activation closed",
		physName, ensureErr)
}
