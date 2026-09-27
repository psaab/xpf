//! RFC 2637 PPTP call associations (#7699, stage 1).
//!
//! # Why this table exists
//!
//! A PPTP GRE data packet carries the Call ID **of the peer it is being sent
//! to** (RFC 2637 §4.1), and each side allocates its own during the
//! control-connection exchange. So the two directions of ONE call carry
//! DIFFERENT values, and no transform of a single packet can pair them —
//! `reverse_wire_key` and friends apply a symmetric swap, which is right for a
//! TCP port pair and for an RFC 2890 Key (one value, both directions) and wrong
//! here.
//!
//! That is why [`TunnelDiscriminator::Pptp`] carries a locally-derived **call
//! handle** rather than the value off the packet: both directions of one call
//! resolve through this table to the same handle, which makes the class
//! direction-symmetric like every other and lets a reply match the stored
//! reverse companion. The alternative — a discriminator built from the packet's
//! own call ID — makes the reply match NO session at all, which is strictly
//! worse than the aliasing it would replace (#8382, closed for this reason).
//!
//! # Why the handle is derived, not allocated
//!
//! HA session sync is session-oriented: a flat per-session record with no
//! auxiliary-table mechanism. A standby that receives a PPTP session but not
//! the association holds a session it can never match a packet against, because
//! it cannot compute the handle. So the association must reach the standby
//! under ANY handle scheme.
//!
//! Given that, a handle **derived** from the association is strictly better
//! than a node-local one: both nodes compute the same value from the same
//! association, so there is no import-time translation table to drift. The
//! derivation is written out explicitly rather than delegated to a std hasher,
//! because it must be stable across processes, builds and nodes — a property
//! std's hashers do not promise.

use std::net::IpAddr;

use rustc_hash::FxHashMap;

/// A learned PPTP call: the two peers and the call ID each ALLOCATED.
///
/// Stored canonically (lower IP first) so the two directions of one call
/// produce one association and one handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct PptpCall {
    lo: IpAddr,
    hi: IpAddr,
    /// Call ID allocated BY the peer at `lo` — so it appears in packets sent TO
    /// `lo`, i.e. those whose destination is `lo`.
    lo_call_id: u16,
    /// Call ID allocated BY the peer at `hi`.
    hi_call_id: u16,
}

impl PptpCall {
    /// Build the canonical association from the two `(peer, call-id-it
    /// allocated)` halves, in either argument order.
    pub(crate) fn new(a: IpAddr, a_call_id: u16, b: IpAddr, b_call_id: u16) -> Self {
        if (a, a_call_id) <= (b, b_call_id) {
            Self { lo: a, hi: b, lo_call_id: a_call_id, hi_call_id: b_call_id }
        } else {
            Self { lo: b, hi: a, lo_call_id: b_call_id, hi_call_id: a_call_id }
        }
    }

    /// Encode the call-id pair for the HA sync wire (#7699).
    ///
    /// Never returns [`PPTP_CALL_IDS_ABSENT`], so a receiver can read `0` as
    /// "the peer could not state this" rather than as a call.
    pub(crate) fn to_wire_call_ids(&self) -> u64 {
        PPTP_CALL_IDS_PRESENT | (u64::from(self.lo_call_id) << 16) | u64::from(self.hi_call_id)
    }

    /// Rebuild an association from the wire pair and the two peer addresses.
    ///
    /// `None` means the peer did not carry the field, which is a WITHHOLD on
    /// the import path rather than a default — a session whose handle the
    /// receiver cannot reproduce is one it can never match a packet against.
    /// The addresses come from the session key, and re-canonicalizing through
    /// [`Self::new`] keeps the ordering identical to the sender's.
    pub(crate) fn from_wire_call_ids(wire: u64, a: IpAddr, b: IpAddr) -> Option<Self> {
        if wire & PPTP_CALL_IDS_PRESENT == 0 || wire >> 33 != 0 {
            return None;
        }
        let lo_call_id = ((wire >> 16) & 0xFFFF) as u16;
        let hi_call_id = (wire & 0xFFFF) as u16;
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        Some(Self::new(lo, lo_call_id, hi, hi_call_id))
    }

    /// The deterministic call handle.
    ///
    /// FNV-1a over the canonical association, written out so it is auditable
    /// and provably identical on both nodes. Never returns 0: a zero handle
    /// would encode as the bare PPTP wire tag, and reserving it keeps "handle
    /// zero" from colliding with any future use of a bare tag.
    pub(crate) fn handle(&self) -> u32 {
        const OFFSET: u32 = 0x811c_9dc5;
        const PRIME: u32 = 0x0100_0193;
        let mut h = OFFSET;
        let mut eat = |bytes: &[u8]| {
            for b in bytes {
                h ^= u32::from(*b);
                h = h.wrapping_mul(PRIME);
            }
        };
        match self.lo {
            IpAddr::V4(v4) => { eat(&[4]); eat(&v4.octets()); }
            IpAddr::V6(v6) => { eat(&[6]); eat(&v6.octets()); }
        }
        match self.hi {
            IpAddr::V4(v4) => { eat(&[4]); eat(&v4.octets()); }
            IpAddr::V6(v6) => { eat(&[6]); eat(&v6.octets()); }
        }
        eat(&self.lo_call_id.to_be_bytes());
        eat(&self.hi_call_id.to_be_bytes());
        if h == 0 { 1 } else { h }
    }
}

/// Reserved: the call-id pair was not carried on the HA sync wire.
///
/// Not the encoding of the pair `(0, 0)` — PPTP call id 0 is not obviously
/// illegal, so an older peer's `serde(default)` zero must not be readable as a
/// real call. Same reasoning as `WIRE_ABSENT` in the discriminator codec.
pub(crate) const PPTP_CALL_IDS_ABSENT: u64 = 0;
/// Present-form tag; the pair rides in the low 32 bits as `(lo << 16) | hi`.
pub(crate) const PPTP_CALL_IDS_PRESENT: u64 = 1 << 32;

/// The TCP/1723 control channel an association was learned on (#7699 stage 3).
///
/// Canonical (lower endpoint first) so both directions of the control
/// connection name one channel. An association must not outlive the channel
/// that taught it: when the control session goes away, the calls it set up are
/// gone whether or not their Call-Disconnect-Notify was ever seen.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct ControlChannelId {
    lo: (IpAddr, u16),
    hi: (IpAddr, u16),
}

impl ControlChannelId {
    pub(crate) fn new(a: IpAddr, a_port: u16, b: IpAddr, b_port: u16) -> Self {
        if (a, a_port) <= (b, b_port) {
            Self { lo: (a, a_port), hi: (b, b_port) }
        } else {
            Self { lo: (b, b_port), hi: (a, a_port) }
        }
    }
}

/// A learned association plus the state that bounds its life.
#[derive(Clone, Copy, Debug)]
struct AssociationRecord {
    call: PptpCall,
    /// The channel that taught it. Removing the channel removes the call.
    control: ControlChannelId,
    /// Stable install time, used to keep a delayed close from deleting a call
    /// learned on a reused TCP tuple.
    learned_ns: u64,
    /// Last time a data packet resolved through it, or install time.
    ///
    /// This is what makes the lifetime independent of ever seeing a teardown:
    /// a call whose peer vanished stops refreshing and expires on its own.
    last_seen_ns: u64,
}

/// How long an association survives with no data traffic resolving through it.
///
/// **This is the bound on mis-attribution exposure, not a memory policy.** The
/// hazard is not that a dead association wastes a map entry — it is that PPTP
/// call ids are 16 bits and REUSED, so a stale association pairs a NEW call's
/// packets onto a DEAD call's handle. Traffic for call B resolving to call A's
/// session is a correctness failure with security-adjacent consequences, and
/// this constant is how long that window can stay open when a
/// Call-Disconnect-Notify is never seen.
///
/// Fifteen minutes: long enough that a live call idle between transfers is not
/// torn down under it (data traffic refreshes it, and a call with no data for
/// this long is not carrying anything), short enough to bound the window. It is
/// a ceiling, not a target — the ordinary path is the explicit teardown, and
/// the control-channel binding removes a whole channel's calls at once.
pub(crate) const ASSOCIATION_IDLE_TIMEOUT_NS: u64 = 15 * 60 * 1_000_000_000;

/// Why an association was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PptpInstallError {
    /// A DIFFERENT association already derived this handle.
    ///
    /// Fail closed, matching the posture of every other derived-name collision
    /// in this tree (#5277 composed route-maps, #5116 redistribute aliases,
    /// #7625 the reserved deny name): refuse rather than let two calls share an
    /// identity, which is the exact collapse this class exists to prevent.
    HandleCollision { existing: PptpCall, handle: u32 },
    /// A DIFFERENT call already owns one of this call's `(allocator, call-id)`
    /// aliases (#11053).
    ///
    /// Data resolution is BY ALIAS ([`PptpAssociations::resolve`]), so silently
    /// overwriting the entry would re-point the earlier call's data at the new
    /// handle — the same identity collapse as a handle collision, through the
    /// other index. Refused, with no mutation, for the same reason.
    /// `owner` is the handle that already owns the alias.
    AllocatorCollision { allocator: IpAddr, call_id: u16, owner: u32 },
}

/// The learned associations, indexed for packet resolution.
#[derive(Default)]
pub(crate) struct PptpAssociations {
    /// `(allocator, call-id it allocated) -> handle`.
    ///
    /// A packet is keyed on its DESTINATION, because the Call ID it carries
    /// belongs to the peer it is being sent to. Two entries per call — one per
    /// peer — which is what makes both directions resolve to one handle.
    by_allocator: FxHashMap<(IpAddr, u16), u32>,
    /// `handle -> record`, for teardown, expiry and collision detection.
    by_handle: FxHashMap<u32, AssociationRecord>,
    /// Version-1 packets that resolved to no association.
    ///
    /// **Expected non-zero during startup and after a restart**, and after any
    /// event that loses control-channel state: the association is learned from
    /// the control channel, so data packets legitimately arrive before it. This
    /// counter is a "PPTP is running unattributed" signal, NOT an error rate,
    /// and reading it as one is how a routinely non-zero counter gets ignored.
    unassociated: u64,
}

impl PptpAssociations {
    /// Learn a call. Idempotent for an identical association.
    ///
    /// #11053: the alias check runs BEFORE either insert, so a refusal mutates
    /// nothing — there is no half-installed `by_handle` row to roll back.
    pub(crate) fn install(
        &mut self,
        call: PptpCall,
        control: ControlChannelId,
        now_ns: u64,
    ) -> Result<u32, PptpInstallError> {
        let handle = call.handle();
        match self.by_handle.get(&handle) {
            Some(existing) if existing.call == call => {
                // Idempotent re-learn (a retransmitted reply). Refresh rather
                // than refuse: the call is real and this is evidence of it.
                self.by_handle.entry(handle).and_modify(|r| {
                    r.control = control;
                    r.learned_ns = now_ns;
                    r.last_seen_ns = now_ns;
                });
                return Ok(handle);
            }
            Some(existing) => {
                return Err(PptpInstallError::HandleCollision {
                    existing: existing.call,
                    handle,
                });
            }
            None => {}
        }
        // A new handle, but the aliases it needs may belong to other calls.
        // Each side's `(allocator, call-id it allocated)` must be unowned or
        // owned by THIS handle (the latter is unreachable past the idempotent
        // arm above, but comparing rather than merely probing keeps the refusal
        // exact if this ever runs without it).
        for (allocator, call_id) in [(call.lo, call.lo_call_id), (call.hi, call.hi_call_id)] {
            if let Some(owner) = self.by_allocator.get(&(allocator, call_id))
                && *owner != handle
            {
                return Err(PptpInstallError::AllocatorCollision {
                    allocator,
                    call_id,
                    owner: *owner,
                });
            }
        }
        self.by_handle.insert(
            handle,
            AssociationRecord {
                call,
                control,
                learned_ns: now_ns,
                last_seen_ns: now_ns,
            },
        );
        self.by_allocator.insert((call.lo, call.lo_call_id), handle);
        self.by_allocator.insert((call.hi, call.hi_call_id), handle);
        Ok(handle)
    }

    /// Resolve a data packet to its call handle.
    ///
    /// `dst` is the packet's destination and `call_id` the value in its GRE
    /// header — which the sender set to the value the DESTINATION allocated.
    /// `None` means unassociated; the caller forwards and counts rather than
    /// dropping (see [`Self::note_unassociated`]).
    pub(crate) fn resolve(&self, dst: IpAddr, call_id: u16) -> Option<u32> {
        self.by_allocator.get(&(dst, call_id)).copied()
    }

    /// The data-path form: resolve AND refresh the association's idle clock.
    ///
    /// Refreshing on use is what makes [`ASSOCIATION_IDLE_TIMEOUT_NS`] mean "no
    /// traffic" rather than "old". A long-lived call carrying data is never
    /// expired under it; a call whose peer vanished stops refreshing and ages
    /// out without anyone announcing its death.
    ///
    /// **WIRED as of #7699's data-channel resolve.** This comment previously
    /// said there was no production caller and that the packet-path dispatch had
    /// not changed it — true when written: the dispatch wired the CONTROL
    /// channel, and the DATA channel was a separate join that
    /// `gre_discriminator` refused outright. That join is
    /// `gre_discriminator::pptp_data_session_flow`, called from the descriptor
    /// loop, and it reaches this function for every version-1 GRE packet.
    ///
    /// So the consequence that comment recorded is gone: the idle clock now
    /// advances on DATA, which is what makes the timeout mean "no traffic"
    /// rather than "old". It previously advanced only at install, bounding an
    /// association's life from when it was LEARNED — conservative (it expired
    /// sooner, never later), but wrong, because expiring a live call frees a
    /// 16-bit id that is REUSED.
    pub(crate) fn resolve_and_touch(
        &mut self,
        dst: IpAddr,
        call_id: u16,
        now_ns: u64,
    ) -> Option<u32> {
        let handle = *self.by_allocator.get(&(dst, call_id))?;
        if let Some(rec) = self.by_handle.get_mut(&handle) {
            rec.last_seen_ns = now_ns;
        }
        Some(handle)
    }

    /// Drop every association idle longer than `timeout_ns`. Returns how many.
    ///
    /// The lifetime bound that does NOT depend on a teardown arriving. Without
    /// it, a Call-Disconnect-Notify lost to a dropped packet, a restarted peer
    /// or a control channel torn down mid-call leaves an association that
    /// re-pairs a REUSED 16-bit call id onto a dead handle — a mis-attribution,
    /// not a leak.
    pub(crate) fn expire_idle(&mut self, now_ns: u64, timeout_ns: u64) -> usize {
        let stale: Vec<u32> = self
            .by_handle
            .iter()
            .filter(|(_, rec)| now_ns.saturating_sub(rec.last_seen_ns) > timeout_ns)
            .map(|(handle, _)| *handle)
            .collect();
        for handle in &stale {
            self.remove(*handle);
        }
        stale.len()
    }

    /// Drop every association learned on a control channel. Returns how many.
    ///
    /// An association must not outlive the channel that taught it: once the
    /// control session is gone the calls it set up cannot be renegotiated or
    /// torn down through it, so keeping them serves nothing and risks pairing a
    /// reused call id. Production callers invoke this on FIN/RST or the control
    /// session's own timeout, not waiting for per-call notifies that will never
    /// arrive. The timeout sweep remains the fallback if no close is observed.
    pub(crate) fn forget_control_channel(&mut self, control: ControlChannelId) -> usize {
        let doomed: Vec<u32> = self
            .by_handle
            .iter()
            .filter(|(_, rec)| rec.control == control)
            .map(|(handle, _)| *handle)
            .collect();
        for handle in &doomed {
            self.remove(*handle);
        }
        doomed.len()
    }

    /// Drop associations on this channel learned no later than the close.
    ///
    /// Peer-worker commands can be delayed by a full queue; the stable learn
    /// time keeps an old close from deleting calls on a later reused tuple.
    pub(crate) fn forget_control_channel_learned_by(
        &mut self,
        control: ControlChannelId,
        closed_ns: u64,
    ) -> usize {
        let doomed: Vec<u32> = self
            .by_handle
            .iter()
            .filter(|(_, rec)| rec.control == control && rec.learned_ns <= closed_ns)
            .map(|(handle, _)| *handle)
            .collect();
        for handle in &doomed {
            self.remove(*handle);
        }
        doomed.len()
    }

    /// Forget a call, by handle. Returns whether anything was removed.
    pub(crate) fn remove(&mut self, handle: u32) -> bool {
        let Some(rec) = self.by_handle.remove(&handle) else {
            return false;
        };
        let call = rec.call;
        self.by_allocator.remove(&(call.lo, call.lo_call_id));
        self.by_allocator.remove(&(call.hi, call.hi_call_id));
        true
    }

    /// Count a version-1 packet that resolved to nothing.
    pub(crate) fn note_unassociated(&mut self) {
        self.unassociated = self.unassociated.saturating_add(1);
    }

    pub(crate) fn unassociated_count(&self) -> u64 {
        self.unassociated
    }

    pub(crate) fn len(&self) -> usize {
        self.by_handle.len()
    }

    /// Force an association in at a CHOSEN handle, so the collision arm is
    /// reachable from a test.
    ///
    /// FNV-1a collisions are not constructible by hand, so without this seam
    /// `PptpInstallError::HandleCollision` would be an untested fail-closed
    /// path — the shape that quietly rots into a fail-open one. Test-only.
    #[cfg(test)]
    pub(crate) fn force_handle_for_test(&mut self, call: PptpCall, handle: u32) {
        self.by_handle.insert(
            handle,
            AssociationRecord {
                call,
                control: ControlChannelId::new(call.lo, 1723, call.hi, 1723),
                learned_ns: 0,
                last_seen_ns: 0,
            },
        );
        self.by_allocator.insert((call.lo, call.lo_call_id), handle);
        self.by_allocator.insert((call.hi, call.hi_call_id), handle);
    }
}

#[cfg(test)]
mod tests_7699 {
    use super::*;
    use crate::session::TunnelDiscriminator;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// The control channel a fixture's calls are learned on. Stage-3 cells that
    /// care about the channel build their own.
    fn ctl(a: IpAddr, b: IpAddr) -> ControlChannelId {
        ControlChannelId::new(a, 49152, b, 1723)
    }

    /// THE PROPERTY THE WHOLE DESIGN EXISTS FOR: both directions of one call
    /// resolve to the SAME handle.
    ///
    /// A→B carries the call ID B allocated; B→A carries the one A allocated.
    /// They are different values, and a discriminator built from either would
    /// differ per direction — which is why #8382 was closed. Resolving through
    /// the association makes the class direction-symmetric.
    #[test]
    fn both_directions_of_one_call_resolve_to_one_handle_7699() {
        let (a, b) = (ip("198.51.100.7"), ip("203.0.113.9"));
        let (a_id, b_id) = (0x1111u16, 0x2222u16);
        let mut t = PptpAssociations::default();
        let handle = t.install(PptpCall::new(a, a_id, b, b_id), ctl(a, b), 0).expect("install");

        // A→B carries B's call id, so it is keyed on the destination B.
        assert_eq!(
            t.resolve(b, b_id),
            Some(handle),
            "the A->B direction must resolve to the call handle"
        );
        // B→A carries A's call id, keyed on destination A.
        assert_eq!(
            t.resolve(a, a_id),
            Some(handle),
            "the B->A direction must resolve to the SAME handle; if these two \
             differ, the reply is looked up under a key the forward session's \
             reverse companion does not equal and it matches NO session"
        );
    }

    /// Criterion 2: two simultaneous calls between the SAME endpoints must not
    /// alias. This is the case that motivated the whole issue.
    #[test]
    fn two_calls_between_one_endpoint_pair_get_distinct_handles_7699() {
        let (a, b) = (ip("198.51.100.7"), ip("203.0.113.9"));
        let mut t = PptpAssociations::default();
        let h1 = t.install(PptpCall::new(a, 0x1001, b, 0x2001), ctl(a, b), 0).expect("call 1");
        let h2 = t.install(PptpCall::new(a, 0x1002, b, 0x2002), ctl(a, b), 0).expect("call 2");
        assert_ne!(
            h1, h2,
            "two calls between one endpoint pair shared a handle, so they share \
             a session: one policy decision, one NAT state, one counter set"
        );
        assert_eq!(t.resolve(b, 0x2001), Some(h1));
        assert_eq!(t.resolve(b, 0x2002), Some(h2));
    }

    /// The handle must depend on EVERY component, varied ONE AT A TIME.
    ///
    /// This cell exists because the two-calls cell below could not see it. That
    /// fixture varies both call IDs together, so a handle that ignored one of
    /// them still separated the two calls and the cell stayed green — an
    /// escaped mutation found by dropping `hi_call_id` from the derivation.
    ///
    /// A handle blind to one component collides for every pair of calls that
    /// differ only in it, which is two calls sharing one session: the exact
    /// collapse this class exists to prevent. Varying one axis at a time is the
    /// only shape that catches it.
    #[test]
    fn the_handle_depends_on_every_component_7699() {
        let (a, b) = (ip("198.51.100.7"), ip("203.0.113.9"));
        let base = PptpCall::new(a, 0x1111, b, 0x2222);
        let h = base.handle();

        for (what, other) in [
            ("the call id allocated by A", PptpCall::new(a, 0x9999, b, 0x2222)),
            ("the call id allocated by B", PptpCall::new(a, 0x1111, b, 0x9999)),
            ("peer A's address", PptpCall::new(ip("198.51.100.8"), 0x1111, b, 0x2222)),
            ("peer B's address", PptpCall::new(a, 0x1111, ip("203.0.113.10"), 0x2222)),
        ] {
            assert_ne!(
                h,
                other.handle(),
                "the handle ignores {what}: two calls differing only in it would \
                 share one handle, and therefore one session"
            );
        }
    }

    /// The handle must be a pure function of the association — same value from
    /// either argument order, and from a freshly built table.
    ///
    /// This is what lets both HA nodes compute it without a translation table,
    /// which is the reason it is derived rather than allocated.
    #[test]
    fn the_handle_is_deterministic_and_order_independent_7699() {
        let (a, b) = (ip("198.51.100.7"), ip("203.0.113.9"));
        let forward = PptpCall::new(a, 0x1111, b, 0x2222);
        let reversed = PptpCall::new(b, 0x2222, a, 0x1111);
        assert_eq!(
            forward, reversed,
            "the association must canonicalize, or the two peers store two rows \
             for one call"
        );
        assert_eq!(
            forward.handle(),
            reversed.handle(),
            "the handle must not depend on which peer's half was seen first — \
             the standby derives it from the synced association, not from the \
             order the active happened to learn it in"
        );
    }

    /// FAIL CLOSED on a handle collision, matching #5277 / #5116 / #7625.
    ///
    /// Reached through a test seam because FNV-1a collisions are not
    /// constructible by hand. Without the seam this arm would be untested, and
    /// an untested fail-closed path is the one that quietly becomes fail-open.
    #[test]
    fn a_handle_collision_is_refused_not_merged_7699() {
        let (a, b) = (ip("198.51.100.7"), ip("203.0.113.9"));
        let squatter = PptpCall::new(a, 0x1001, b, 0x2001);
        let victim = PptpCall::new(a, 0x3003, b, 0x4004);
        let handle = victim.handle();

        let mut t = PptpAssociations::default();
        t.force_handle_for_test(squatter, handle);

        match t.install(victim, ctl(a, b), 0) {
            Err(PptpInstallError::HandleCollision { existing, handle: h }) => {
                assert_eq!(existing, squatter);
                assert_eq!(h, handle);
            }
            other => panic!(
                "a colliding association must be REFUSED, not merged; two calls \
                 sharing one handle share one session, which is the collapse \
                 this class exists to prevent. Got {other:?}"
            ),
        }
        // NEGATIVE CONTROL, on a CLEAN table: re-installing the identical
        // association is idempotent, not a collision — otherwise a re-learn on
        // a retransmitted control message would refuse a call that is already
        // correct, and the guard would be indistinguishable from one that
        // refuses everything.
        //
        // It must not reuse the forced table above: `squatter` was planted at
        // VICTIM's handle there, so installing it would go to its own handle
        // and the assertion would be about the seam rather than about
        // idempotence.
        let mut clean = PptpAssociations::default();
        let first = clean.install(squatter, ctl(a, b), 0).expect("first install");
        assert_eq!(
            clean.install(squatter, ctl(a, b), 0),
            Ok(first),
            "re-learning an identical association must be idempotent"
        );
        assert_eq!(clean.len(), 1, "idempotent re-install must not add a row");
    }

    /// A call cannot take over an `(allocator, call-id)` alias from another
    /// handle: data lookup is indexed by this alias, not by the call record.
    #[test]
    fn an_allocator_alias_collision_is_refused_without_repointing_11053() {
        let (a, b, c) = (
            ip("198.51.100.7"),
            ip("203.0.113.9"),
            ip("203.0.113.10"),
        );
        let original = PptpCall::new(a, 0x1111, b, 0x2222);
        let colliding = PptpCall::new(a, 0x1111, c, 0x3333);
        let mut table = PptpAssociations::default();
        let original_handle = table.install(original, ctl(a, b), 10).expect("original");

        assert_eq!(
            table.install(colliding, ctl(a, c), 20),
            Err(PptpInstallError::AllocatorCollision {
                allocator: a,
                call_id: 0x1111,
                owner: original_handle,
            }),
            "a reused allocator alias must refuse the second association"
        );
        assert_eq!(table.resolve(a, 0x1111), Some(original_handle));
        assert_eq!(table.resolve(b, 0x2222), Some(original_handle));
        assert_eq!(table.resolve(c, 0x3333), None);
        assert_eq!(table.len(), 1, "refusal must not leave a second handle");
    }

    /// The unassociated path: resolve to nothing, count, and do NOT drop.
    ///
    /// The counter is expected non-zero at startup and after a restart — data
    /// packets legitimately precede the control channel — so it is a "running
    /// unattributed" signal, not an error rate.
    #[test]
    fn an_unassociated_packet_resolves_to_none_and_is_counted_7699() {
        let mut t = PptpAssociations::default();
        assert_eq!(t.resolve(ip("203.0.113.9"), 0x2222), None);
        assert_eq!(t.unassociated_count(), 0, "resolve must not itself count");
        t.note_unassociated();
        t.note_unassociated();
        assert_eq!(t.unassociated_count(), 2);
    }

    /// Teardown must remove BOTH allocator entries.
    ///
    /// Leaving one behind is the mis-attribution hazard: PPTP call IDs are
    /// 16-bit and REUSED, so a stale half-entry pairs a future call onto a dead
    /// handle. Asserted per direction, because removing only the direction the
    /// teardown arrived on would pass a single-direction check.
    #[test]
    fn removing_a_call_clears_both_directions_7699() {
        let (a, b) = (ip("198.51.100.7"), ip("203.0.113.9"));
        let mut t = PptpAssociations::default();
        let handle = t.install(PptpCall::new(a, 0x1111, b, 0x2222), ctl(a, b), 0).expect("install");
        assert!(t.remove(handle));
        assert_eq!(t.resolve(a, 0x1111), None, "A-side entry survived teardown");
        assert_eq!(t.resolve(b, 0x2222), None, "B-side entry survived teardown");
        assert_eq!(t.len(), 0);
        assert!(!t.remove(handle), "a second remove must report nothing removed");
    }

    /// The end-to-end property: a session keyed on a PPTP handle has a reverse
    /// companion keyed on the SAME handle, so a reply matches it.
    ///
    /// This is the assertion #8382 could not make, and the reason that slice
    /// was closed rather than landed.
    #[test]
    fn a_pptp_session_reverse_companion_keeps_the_handle_7699() {
        let call = PptpCall::new(ip("198.51.100.7"), 0x1111, ip("203.0.113.9"), 0x2222);
        let handle = call.handle();
        let disc = TunnelDiscriminator::Pptp(handle);
        assert_eq!(
            crate::session::key::reverse_direction_discriminator_for_test(disc),
            disc,
            "the reverse companion must carry the same handle; if this ever \
             transforms, a reply is looked up under a key the stored companion \
             does not equal and matches no session at all"
        );
    }
}

#[cfg(test)]
mod expiry_tests_7699 {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    const T0: u64 = 1_000_000_000_000;

    /// THE CELL STAGE 3 EXISTS FOR: a MISSED teardown must not mis-attribute a
    /// later call that reuses the call id.
    ///
    /// The fixture enters the missed-teardown state deliberately. Call A ends
    /// and its Call-Disconnect-Notify is never seen — a lost packet, a
    /// restarted peer, a control channel torn down mid-call. Nothing calls
    /// `remove`. Then a NEW call reuses A's 16-bit id on the same peer, and its
    /// own control channel has not been seen yet.
    ///
    /// **The failure this guards is a mis-attribution, not a leak.** Without
    /// expiry, the new call's data packet resolves to the DEAD call's handle,
    /// so its traffic lands on call A's session — A's policy decision, A's NAT
    /// state, A's counters. A cell that only ever sends a clean teardown passes
    /// under an implementation that never expires anything and would not see
    /// this at all.
    #[test]
    fn a_missed_teardown_does_not_mis_attribute_a_reused_call_id_7699() {
        let (pac, pns) = (ip("198.51.100.7"), ip("203.0.113.9"));
        let ctl = ControlChannelId::new(pac, 49152, pns, 1723);
        let mut t = PptpAssociations::default();

        let dead = t
            .install(PptpCall::new(pac, 0xAAAA, pns, 0xBBBB), ctl, T0)
            .expect("install");

        // The call ends. No notify arrives; nothing calls remove(). Time passes
        // with no data traffic refreshing it.
        let later = T0 + ASSOCIATION_IDLE_TIMEOUT_NS + 1;
        assert_eq!(
            t.expire_idle(later, ASSOCIATION_IDLE_TIMEOUT_NS),
            1,
            "an association idle past the bound must age out without a teardown"
        );

        // A new call reuses 0xBBBB on the PNS; its control channel is not yet
        // seen, so nothing has been learned for it.
        assert_eq!(
            t.resolve(pns, 0xBBBB),
            None,
            "a reused call id resolved to the DEAD call's handle — the new \
             call's traffic would land on the old call's session. This is the \
             mis-attribution the expiry exists to prevent, and it is what a \
             clean-teardown-only fixture cannot see"
        );
        assert_ne!(
            t.resolve(pns, 0xBBBB),
            Some(dead),
            "explicitly: not the dead handle"
        );
    }

    /// ANTI-VACUITY: a call still carrying data is NOT expired.
    ///
    /// Without this, the cell above is satisfied by an implementation that
    /// expires everything on every sweep — which would tear down live calls and
    /// look identical in a test that only checks that stale entries go away.
    #[test]
    fn a_call_carrying_data_is_not_expired_7699() {
        let (pac, pns) = (ip("198.51.100.7"), ip("203.0.113.9"));
        let ctl = ControlChannelId::new(pac, 49152, pns, 1723);
        let mut t = PptpAssociations::default();
        let handle = t
            .install(PptpCall::new(pac, 0xAAAA, pns, 0xBBBB), ctl, T0)
            .expect("install");

        // Data keeps flowing right up to the bound.
        let touched_at = T0 + ASSOCIATION_IDLE_TIMEOUT_NS;
        assert_eq!(
            t.resolve_and_touch(pns, 0xBBBB, touched_at),
            Some(handle),
            "a live call must resolve"
        );

        // A sweep just under a full timeout after that touch leaves it alone.
        assert_eq!(
            t.expire_idle(touched_at + ASSOCIATION_IDLE_TIMEOUT_NS, ASSOCIATION_IDLE_TIMEOUT_NS),
            0,
            "a call refreshed by data traffic must survive; the bound is time \
             SINCE TRAFFIC, not age"
        );
        assert_eq!(t.resolve(pns, 0xBBBB), Some(handle));

        // ...and one tick past it, the same call does age out — so the
        // assertion above is about the refresh and not about a timeout that
        // never fires.
        assert_eq!(
            t.expire_idle(
                touched_at + ASSOCIATION_IDLE_TIMEOUT_NS + 1,
                ASSOCIATION_IDLE_TIMEOUT_NS
            ),
            1
        );
    }

    /// An association must not outlive the control channel that taught it.
    ///
    /// Also a missed-teardown shape: the channel goes away by FIN/RST or its
    /// own timeout, and the per-call notifies for the calls it set up will now
    /// never arrive. Waiting out the idle bound would leave that window open
    /// for no reason — the calls cannot be renegotiated through a channel that
    /// is gone.
    #[test]
    fn losing_the_control_channel_forgets_its_calls_7699() {
        let (pac, pns) = (ip("198.51.100.7"), ip("203.0.113.9"));
        let doomed = ControlChannelId::new(pac, 49152, pns, 1723);
        let other = ControlChannelId::new(pac, 49153, pns, 1723);
        let mut t = PptpAssociations::default();

        t.install(PptpCall::new(pac, 0xAAAA, pns, 0xBBBB), doomed, T0)
            .expect("call A");
        t.install(PptpCall::new(pac, 0xCCCC, pns, 0xDDDD), doomed, T0)
            .expect("call B");
        let survivor = t
            .install(PptpCall::new(pac, 0xEEEE, pns, 0xFFFF), other, T0)
            .expect("call on another channel");

        assert!(t.resolve(pns, 0xBBBB).is_some());
        assert!(t.resolve(pns, 0xDDDD).is_some());
        assert_eq!(
            t.forget_control_channel(doomed),
            2,
            "both calls learned on that channel must go, with NO time passing \
             and NO Call-Disconnect-Notify"
        );
        assert_eq!(t.resolve(pns, 0xBBBB), None);
        assert_eq!(t.resolve(pns, 0xDDDD), None);
        assert_eq!(
            t.resolve(pns, 0xFFFF),
            Some(survivor),
            "losing one control channel must not forget calls set up on another"
        );
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn a_delayed_control_close_preserves_a_relearned_call_11053() {
        let (pac, pns) = (ip("198.51.100.7"), ip("203.0.113.9"));
        let control = ControlChannelId::new(pac, 49152, pns, 1723);
        let call = PptpCall::new(pac, 0xAAAA, pns, 0xBBBB);
        let mut t = PptpAssociations::default();
        let handle = t.install(call, control, 10).expect("first learn");
        assert_eq!(t.install(call, control, 20), Ok(handle), "relearn");

        assert_eq!(t.forget_control_channel_learned_by(control, 15), 0);
        assert_eq!(
            t.resolve(pns, 0xBBBB),
            Some(handle),
            "a delayed close must not delete a call learned after its close time"
        );
    }
}

#[cfg(test)]
mod sweep_wiring_tests_7699 {
    use super::*;
    use crate::session::SessionTable;

    /// The expiry runs from the PERIODIC SWEEP, not just when a test calls it.
    ///
    /// Every cell in `expiry_tests_7699` calls `expire_idle` directly, so all of
    /// them stay green against a build where nothing in production ever calls
    /// it — the association would then live forever on a real box and
    /// mis-attribute a reused call id, with the suite entirely quiet. That is
    /// the two-correct-halves-and-no-join shape that hid a missing metrics
    /// wiring in #7685 and a missing drain arm in #8392, and that I wrote an
    /// unfalsifiable comment about in #8396.
    ///
    /// So this drives `SessionTable::expire_stale_entries` — the real sweep the
    /// worker loop calls — and asserts the association is gone afterwards.
    ///
    /// FAIL-ON-REVERT: delete the `self.pptp.expire_idle(..)` call from
    /// `expire_stale_entries_ha` and this reds while every direct-call cell
    /// passes.
    #[test]
    fn the_periodic_sweep_expires_stale_associations_7699() {
        let (pac, pns): (IpAddr, IpAddr) = (
            "198.51.100.7".parse().unwrap(),
            "203.0.113.9".parse().unwrap(),
        );
        let ctl = ControlChannelId::new(pac, 49152, pns, 1723);
        const T0: u64 = 1_000_000_000_000;

        let mut sessions = SessionTable::new();
        sessions
            .pptp_mut()
            .install(PptpCall::new(pac, 0xAAAA, pns, 0xBBBB), ctl, T0)
            .expect("install");
        assert!(
            sessions.pptp().resolve(pns, 0xBBBB).is_some(),
            "precondition: the association must be present before the sweep"
        );

        // The sweep the worker loop runs, one tick past the idle bound.
        sessions.expire_stale_entries(T0 + ASSOCIATION_IDLE_TIMEOUT_NS + 1);

        assert_eq!(
            sessions.pptp().resolve(pns, 0xBBBB),
            None,
            "the periodic sweep did not age the association out, so nothing in \
             production bounds it: a missed Call-Disconnect-Notify would leave \
             it resolving a REUSED call id onto a dead handle forever"
        );
    }

    /// The association expiry runs ONCE PER GC INTERVAL, not on every call.
    ///
    /// `expire_stale_entries_ha` is called from the worker poll loop and its
    /// gc-interval gate is what makes it periodic. When this landed the
    /// `expire_idle` call sat ABOVE that gate, so it scanned the whole
    /// association map at POLL frequency — per-poll work in a tree whose entire
    /// discipline is not doing per-poll work. Every cell in this file passed
    /// either way, because they all assert what the table ends up containing
    /// and the placement changes only how often it is computed.
    ///
    /// So the placement is bound by its OBSERVABLE consequence: a sweep the
    /// gate short-circuits must not expire anything, even something already
    /// stale. Above the gate it would.
    ///
    /// The three steps are the whole point — the middle one is the assertion,
    /// and the third proves the association really was expirable, so the middle
    /// is about the GATE rather than about a timeout that never fires.
    #[test]
    fn the_association_expiry_respects_the_gc_interval_gate_7699() {
        let (pac, pns): (IpAddr, IpAddr) = (
            "198.51.100.7".parse().unwrap(),
            "203.0.113.9".parse().unwrap(),
        );
        let ctl = ControlChannelId::new(pac, 49152, pns, 1723);
        const T0: u64 = 1_000_000_000_000;
        const HALF_SECOND: u64 = 500_000_000;
        const SECOND: u64 = 1_000_000_000;

        let mut sessions = SessionTable::new();
        let handle = sessions
            .pptp_mut()
            .install(PptpCall::new(pac, 0xAAAA, pns, 0xBBBB), ctl, T0)
            .expect("install");

        // 1. A sweep exactly AT the bound: not yet stale (`> timeout`), and it
        //    sets the gc clock so the next call is gated.
        sessions.expire_stale_entries(T0 + ASSOCIATION_IDLE_TIMEOUT_NS);
        assert_eq!(sessions.pptp().resolve(pns, 0xBBBB), Some(handle));

        // 2. Half a second later the association IS stale — but the gate
        //    short-circuits this call, so no expiry work happens.
        sessions.expire_stale_entries(T0 + ASSOCIATION_IDLE_TIMEOUT_NS + HALF_SECOND);
        assert_eq!(
            sessions.pptp().resolve(pns, 0xBBBB),
            Some(handle),
            "a gc-gated call expired an association, so the expiry is running \
             ABOVE the gate — i.e. on every poll-loop call, scanning the whole \
             association map at poll frequency"
        );

        // 3. Past the interval the gate opens and the same association goes,
        //    proving step 2 was about the gate and not an inert timeout.
        sessions.expire_stale_entries(T0 + ASSOCIATION_IDLE_TIMEOUT_NS + SECOND + HALF_SECOND);
        assert_eq!(
            sessions.pptp().resolve(pns, 0xBBBB),
            None,
            "control: once the gate opens the stale association must go"
        );
    }

    /// ANTI-VACUITY for the cell above: the same sweep run BEFORE the bound
    /// leaves the association alone.
    ///
    /// Without this, a sweep that unconditionally cleared the table would
    /// satisfy the wiring cell while tearing down every live call.
    #[test]
    fn the_periodic_sweep_leaves_fresh_associations_alone_7699() {
        let (pac, pns): (IpAddr, IpAddr) = (
            "198.51.100.7".parse().unwrap(),
            "203.0.113.9".parse().unwrap(),
        );
        let ctl = ControlChannelId::new(pac, 49152, pns, 1723);
        const T0: u64 = 1_000_000_000_000;

        let mut sessions = SessionTable::new();
        let handle = sessions
            .pptp_mut()
            .install(PptpCall::new(pac, 0xAAAA, pns, 0xBBBB), ctl, T0)
            .expect("install");

        sessions.expire_stale_entries(T0 + ASSOCIATION_IDLE_TIMEOUT_NS - 1);

        assert_eq!(
            sessions.pptp().resolve(pns, 0xBBBB),
            Some(handle),
            "the sweep expired a live association before its idle bound"
        );
    }
}
