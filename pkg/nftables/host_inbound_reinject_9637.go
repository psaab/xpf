package nftables

// host_inbound_reinject_9637.go renders the #9637-residual reinject exemption:
// userspace-adjudicated reinjects arriving on the slow-path TUN are accepted to
// view (zoned) addresses without re-judging them by the address owner.
//
// The direct-path exposure from #9637 is fixed and merged (#9860): the kernel
// chain judges a host-bound packet by its ingress zone. The residual is that
// destinations owned by interface-mode source NAT take the userspace reinject
// path (is_local_destination reports them non-local for the #290 reverse-NAT
// repair) and are over-refused: the kernel sees iifname xpf-usp0, which no view
// claims, and re-judges the SYN by the owner zone.
//
// GUARD-FIRST (operator doctrine: every point in every flow needs its
// explicit allow — no blanket accept): the accept below admits ONLY
// reinjects that passed a userspace host-inbound gate, proven by the
// arrival device. The userspace dataplane reinjects gate-passed
// LocalDelivery frames (session-hit re-eval, session-miss incl. the
// interface-NAT path, flowless — every deny `continue`s before reinject)
// through `xpf-usp0`, and every other reinject class through `xpf-usp1`
// (forced and common-skew NoRoute incl. capped delegates,
// transit-adjudicated MissingNeighbor, ForwardCandidate build-failure
// fallback, unconditionally-exempt IPsec incl. NAT-T — the old D2/D3/D4
// enumeration, now denied at the destination instead of flipped). The
// kernel holds NO accept for `xpf-usp1`, so those frames meet the
// destination-only rules, unzoned catch-all, lifeline subtraction, RETH
// sets and fences exactly as pre-#9637. The outlet IS the authorization
// proof: `reinject_host_authorized` (single site) maps disposition to
// outlet, and unfiltered call sites declare `false` at their site.
//
// The remaining window is snapshot freshness, closed pre-landing by the
// DataplaneFresh gate: the accept renders only on
// publication-acknowledged ApplyConfig success (failures, deferred XSK
// publishes via SnapshotPublishDeferred, and cancellation closeouts all
// render accept-less), so a fresh address the running snapshot never
// authorized meets the destination-only deny. Post-install failure
// removes an installed accept on the next render for the same reason.
//
// Views-scoping is load-bearing: the accept's daddr set is VIEW addresses
// only. Unzoned-interface addresses are excluded so the #4420 catch-all DROP
// keeps judging unzoned-dst reinjects exactly as today; pure-lifeline
// destinations are in neither set and fall through in both designs.

// HostInboundReinjectIfname is the slow-path TUN the userspace dataplane
// reinjects adjudicated host-bound packets through. It MUST stay equal to the
// Rust DEFAULT_SLOW_PATH_TUN (userspace-dp/src/afxdp/mod.rs) — a mismatch
// orphans the accept (dead rule, residual unclosed) or, worse, scopes it to a
// device that never carries reinjects. Pinned by TestHostInboundReinjectTunName.
const HostInboundReinjectIfname = "xpf-usp0"

// HostInboundDelegatedIfname is the slow-path TUN for reinjects that did NOT
// pass a userspace host-inbound gate (#9637 operator narrowing: NoRoute and
// capped delegates, transit-adjudicated MissingNeighbor, ForwardCandidate
// build-failure fallback, unconditionally-exempt IPsec classes). The kernel
// holds NO accept for this device — these frames are judged by the
// destination rules exactly as pre-#9637 — so NO render surface may ever
// reference it (pinned by the no-delegated-reference assertion in the
// reinject tests). It MUST stay equal to the Rust DELEGATED_SLOW_PATH_TUN
// (userspace-dp/src/afxdp/mod.rs); a mismatch strands delegated reinjects
// on a device the kernel never sees (silent host-bound blackhole) or, if
// the name ever equalled a zone netdev, mis-scopes them. Pinned by
// TestHostInboundReinjectTunName.
const HostInboundDelegatedIfname = "xpf-usp1"

// HostInboundAcceptReinject is the accept-counter type-class key for the
// reinject exemption (#4759 pattern). It is deliberately NOT a member of
// HostInboundAcceptCounterTypes: those are UNCONDITIONAL global accepts, while
// this counter is declared exactly when the accept rules render (fresh +
// addressed views), mirroring the deny-counter declaration discipline. The
// scraper (ParseHostInboundAcceptCounterName) and the
// xpf_host_inbound_icmp_nd_accept_total series pick it up by name.
const HostInboundAcceptReinject = "reinject"
