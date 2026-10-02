package routing

import (
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// errWGIncompatibleLinkRetained is returned by applyWireguardTunLocked
// ONLY when a same-name link of the WRONG type (a non-TUN: GRE/IPIP/TAP/
// dummy) is present and its replacement LinkDel failed — so a stale
// NON-WG kernel link remains under the WG name. Apply uses this sentinel
// (and only this one) to re-retain the name in ownedNames for non-WG
// removal-retry (#1919 r5/r6): every OTHER applyWireguardTunLocked error
// (transient lookup, failed create) either leaves no link or leaves a
// HEALTHY persistent WG link, which must stay untracked (#1432 S2a).
var errWGIncompatibleLinkRetained = errors.New("wireguard tun: stale incompatible link retained for retry")

// WG per-packet outer overhead (must mirror userspace-dp
// afxdp/wg/mod.rs WG_OVERHEAD_V4/V6): outer IP + UDP(8) + WG data
// header(16) + Poly1305 tag(16). Plus up to 15 bytes of §5.4.6 pad.
const (
	wgOverheadV4 = 20 + 8 + 16 + 16 // 60
	wgOverheadV6 = 40 + 8 + 16 + 16 // 80
	wgPadWorst   = 15
)

// wgEngineMaxInnerMTU is the largest INNER IP packet (pre-§5.4.6 padding)
// the WireGuard engine can encrypt in one transport message. It MUST mirror
// userspace-dp afxdp/wg/engine.rs WG_ENGINE_MAX_INNER_MTU
// (= PADDED_PLAINTEXT_MAX = 4096). The engine rejects an inner whose
// 16-byte-padded length exceeds PADDED_PLAINTEXT_MAX; because
// PADDED_PLAINTEXT_MAX is itself a 16-multiple, the largest accepted unpadded
// inner length is exactly 4096.
//
// #2457: the configured / derived wgN inner MTU MUST be clamped to this
// ceiling. Without the clamp, an operator who sets `mtu 9000` on a wgN
// interface (or a jumbo underlay deriving a >4096 inner budget) hands the
// engine plaintext above its encryptable maximum, so every oversized packet
// is silently dropped at the encap `padded_len > PADDED_PLAINTEXT_MAX` guard
// (`encap_mtu_drops`). Clamping makes the advertised/configured inner MTU
// match what the engine actually accepts.
const wgEngineMaxInnerMTU = 4080 + 16 // 4096

// wgDefaultOuterMTU is the assumed underlay (outer-link) MTU used to
// derive the wgN inner MTU when the operator has not set an explicit
// `mtu` on the tunnel (#2300). It mirrors the Rust control-thread
// fallback (coordinator/wg_control.rs WG_DEFAULT_OUTER_MTU) so both
// sides share ONE outer-MTU model. The control thread is additionally
// handed the REAL resolved underlay-egress MTU at spawn, and the
// transit-egress encap reads the real egress MTU per packet, so on a
// non-1500 underlay the Rust guard is authoritative even when this
// Go-side default cannot see the route. An operator who must lower the
// wgN MTU for a sub-1500 underlay (PPPoE 1492, cloud overlays ~1450)
// sets `set interfaces wgN unit U family inet mtu <n>` — that override
// wins (see wgTunMTUForEndpoint).
const wgDefaultOuterMTU = 1500

// wgTunMTUForEndpoint computes the inner (wgN) MTU cap (#1432 S2a, AGY
// Hazard A / H2). The kernel must never hand the WG control thread a
// plaintext packet that, once encapped with the worst-case overhead
// plus §5.4.6 pad, exceeds the outer MTU and forces outer IP
// fragmentation. The overhead depends on the outer IP family (the WG
// peer endpoint address): IPv6-outer is 20 bytes larger.
//
// #2300 MTU model: an operator-set `tc.MTU > 0` is the inner wgN MTU
// directly (the supported sub-1500 / jumbo path — it is the owning
// interface's `mtu` statement, carried by collectAppliedTunnels). With
// no operator MTU the cap derives from `wgDefaultOuterMTU` minus the
// family overhead. The control thread enforces an exact pad-aware guard
// against the REAL underlay-egress MTU (wg_control.rs), so this is the
// first line, not the only one — and on a non-1500 underlay the Rust
// guard catches what this default-derived value over-permits.
func wgTunMTUForEndpoint(tc *config.TunnelConfig) int {
	// Operator override: a configured `mtu` on the tunnel interface is
	// the inner wgN MTU. This is the divergence #2300 closes — the prior
	// code ignored tc.MTU entirely and always derived from 1500, so a
	// lowered-underlay deployment could not set a smaller wgN MTU.
	//
	// #2457: clamp the override to the engine's encryptable ceiling. An
	// operator who sets `mtu 9000` on a jumbo wgN device would otherwise
	// have the kernel hand the WG engine plaintext above
	// wgEngineMaxInnerMTU (4096), which the encap guard silently drops
	// (`encap_mtu_drops`). Clamping keeps the configured device MTU at or
	// below what the engine can actually encrypt.
	if tc.MTU > 0 {
		return min(tc.MTU, wgEngineMaxInnerMTU)
	}
	// A configured v4 endpoint uses the v4 overhead; a v6 endpoint (or a
	// responder-only/roaming endpoint with no configured address, which
	// the Rust control thread may LEARN as v6 — Codex r4 MAJOR) uses the
	// larger v6 overhead so the kernel never hands the control thread an
	// inner packet that the v6-aware encap guard would then drop. With
	// multi-peer (#1434) the outer family is a TUNNEL-level property (one
	// UDP socket); WgOuterFamilyV6 resolves it from the peer(s) that
	// declare an endpoint (validateWireguardPeers rejects mixed-family).
	overhead := wgOverheadV6
	if !tc.WgOuterFamilyV6() && tc.WgHasEndpoint() {
		overhead = wgOverheadV4
	}
	// #2457: the default-derived value also clamps to the engine ceiling
	// so a jumbo wgDefaultOuterMTU (were it ever raised) cannot derive an
	// inner budget the engine cannot encrypt. At the shipped 1500 default
	// this is a no-op.
	return min(wgDefaultOuterMTU-overhead-wgPadWorst, wgEngineMaxInnerMTU)
}

// applyWireguardTunLocked creates (or reuses) the persistent wgN TUN
// netdev for a WireGuard tunnel endpoint and configures its MTU,
// addresses, and VRF binding. The device is intentionally NOT tracked
// in t.tunnels: clearLocked must not delete it on reload (AGY Hazard B
// — flapping wgN destroys its addresses and FRR routes every commit).
//
// On config removal the persistent wgN LINK is intentionally kept (S2a:
// tearing it would flap the device and destroy the live peer/session),
// but the kernel ADDRESSES this manager applied are now pruned away by
// Apply's WG-removal diff (#1919): wgConfigured records the WG names from
// the last Apply, and a name that disappears has pruneAppliedAddrsLocked
// reconcile its addresses to empty while keeping the link. So a removed WG
// tunnel no longer leaks its addresses (or the kernel connected route the
// address auto-installs, removed by the kernel on AddrDel — and hence any
// FRR direct→connected redistribution of it).
//
// On restart the same LinkList sweep handles the removal case too, pruning
// non-link-local addresses without LinkDel'ing the persistent WG TUN.
// Link-local addresses remain protected because an empty applied-address
// set cannot distinguish configured fe80 addresses from kernel autoconf.
//
// VRF membership IS reconciled through the shared appliedRI claim
// machinery (#5120): the reconcile below records an identity-gated claim
// on a successful bind, so removing the `routing-instance` stanza from a
// still-configured tunnel unbinds here, and removing the whole tunnel
// unbinds via the persistent-link prune in Apply (both use
// unbindVRFClaimLocked — the wgN link is kept but never left enslaved to a
// stale VRF).
//
// The Rust control thread (coordinator/wg_control.rs) attaches to this
// persistent device by name.
func (t *tunnelManager) applyWireguardTunLocked(tc *config.TunnelConfig) error {
	mtu := wgTunMTUForEndpoint(tc)
	link, err := t.ops.LinkByName(tc.Name)
	// Copilot C3: only reuse an existing link if it is actually a TUN/TAP.
	// A name collision with some other interface type (e.g. a leftover
	// dummy) must be deleted and recreated, not mutated — otherwise we'd
	// bring up + address + VRF-bind the wrong device, and the Rust side's
	// open_tun on the same name would then fail.
	mustCreate := err != nil
	if err == nil {
		tt, isTuntap := link.(*netlink.Tuntap)
		if !isTuntap || tt.Mode != netlink.TUNTAP_MODE_TUN {
			// Not a TUN (a TAP, or some other type entirely). The Rust
			// side opens it with IFF_TUN, so a TAP would fail there;
			// delete + recreate as a TUN rather than mutate the wrong
			// device (Codex r3 MINOR).
			slog.Info("replacing non-TUN link before wireguard tun create",
				"name", tc.Name, "type", link.Type())
			if delErr := t.ops.LinkDel(link); delErr != nil {
				// A stale NON-WG link remains under this name. Wrap with the
				// sentinel so Apply re-retains ownedNames for non-WG cleanup
				// retry (#1919 r5/r6) — distinct from a create failure that
				// may leave a healthy WG link.
				return fmt.Errorf("replace non-tun wireguard link %s: %w: %w",
					tc.Name, delErr, errWGIncompatibleLinkRetained)
			}
			mustCreate = true
		}
	}
	if mustCreate {
		// Create a persistent TUN. NonPersist:false keeps the netdev
		// alive after the creating fd closes, so a reload that does not
		// touch this device leaves it (and its routes) intact.
		tun := &netlink.Tuntap{
			LinkAttrs:  netlink.LinkAttrs{Name: tc.Name, MTU: mtu},
			Mode:       netlink.TUNTAP_MODE_TUN,
			Flags:      netlink.TUNTAP_NO_PI,
			Queues:     1,
			NonPersist: false,
		}
		if addErr := t.ops.LinkAdd(tun); addErr != nil {
			return fmt.Errorf("create wireguard tun %s: %w", tc.Name, addErr)
		}
		closeTuntapFiles(tun.Fds)
		link = tun
		// vishvananda/netlink creates a TUN via TUNSETIFF and may return
		// before the generic LinkAttrs.MTU is applied, leaving the kernel
		// device at its default MTU on first apply (Codex r4 MAJOR).
		// Set the MTU explicitly after create so the inner cap is live
		// immediately, not only after a later reload.
		if mtuErr := t.ops.LinkSetMTU(link, mtu); mtuErr != nil {
			slog.Warn("failed to set wireguard tun mtu on create",
				"name", tc.Name, "mtu", mtu, "err", mtuErr)
		}
		slog.Info("wireguard tun created", "name", tc.Name, "mtu", mtu)
	} else {
		// Reuse in place; reconcile the MTU if the config changed it
		// (AGY M4 / Copilot C4 — a stale MTU on reuse, including a
		// pre-created device, would otherwise persist).
		if link.Attrs().MTU != mtu {
			if mtuErr := t.ops.LinkSetMTU(link, mtu); mtuErr != nil {
				slog.Warn("failed to update wireguard tun mtu",
					"name", tc.Name, "mtu", mtu, "err", mtuErr)
			} else {
				slog.Info("wireguard tun mtu updated", "name", tc.Name, "mtu", mtu)
			}
		}
		slog.Debug("wireguard tun reused", "name", tc.Name)
	}

	// #5355: a genuine bring-up failure on the persistent wgN device
	// leaves it admin-DOWN, so surface it (fail closed) — but still run
	// the address/VRF reconcile best-effort below and return the error at
	// the tail. A plain LinkSetUp error is NOT the incompatible-link
	// sentinel, so Apply's errWGIncompatibleLinkRetained branch stays a
	// no-op and the healthy persistent link is not re-tracked.
	var upErr error
	if err := t.ops.LinkSetUp(link); err != nil {
		slog.Warn("failed to bring up wireguard tun", "name", tc.Name, "err", err)
		upErr = fmt.Errorf("bring up wireguard tun %s: %w", tc.Name, err)
	}

	// Symmetric address reconciliation (Copilot C5): because the device
	// is persistent and never recreated, addresses removed from the config
	// would otherwise survive every reload and keep being routed. Shared
	// helper (#1884) with the per-link applied-address record (#1905) —
	// the same configured-vs-autoconf link-local split as the GRE/IPIP
	// branch: a CONFIGURED fe80 later removed from config is deleted
	// (this manager applied it), while the kernel's autoconf fe80 — and
	// any fe80 already present before this daemon's first apply
	// (restart adoption pass, applied == nil) — is never touched.
	// On config REMOVAL the wgN link persists (S2a) but its addresses are
	// now pruned by Apply's WG-removal diff (#1919, see the function doc
	// above); the appliedAddrs entry is dropped once the device is proven
	// clean, so a later re-add starts tracking fresh.
	t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
		link, tc.Name, tc.Addresses, t.appliedAddrs[tc.Name], "wireguard tun")

	// VRF binding via the shared identity-gated claim machinery (#5120).
	// Previously WG bound directly with no else/unbind branch, so removing
	// the `routing-instance` stanza from a still-configured tunnel left wgN
	// mastered to the old VRF indefinitely. reconcileVRFClaimLocked records
	// appliedRI on a successful bind and, when the desired RI is now empty,
	// identity-checks the current master and unbinds (unbindVRFClaimLocked).
	// The whole-tunnel-removal case is handled by the persistent-link prune
	// in Apply, which shares unbindVRFClaimLocked. The wgN link is kept
	// (S2a) but is no longer left enslaved to a stale VRF.
	t.reconcileVRFClaimLocked(tc, link)
	return upErr
}

// closeTuntapFiles closes the file descriptors returned by a Tuntap
// LinkAdd so they are not leaked.
func closeTuntapFiles(files []*os.File) {
	for _, file := range files {
		if file != nil {
			_ = file.Close()
		}
	}
}
