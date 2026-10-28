use std::sync::atomic::AtomicU64;
#[cfg(test)]
use std::sync::atomic::Ordering;

/// #16561: NAT'd forward removals that fell back to the legacy
/// O(table) survivor scan under the `shared_sessions` mutex because
/// the wire-owner roster could not be trusted for that key (unrecorded
/// owner, or live roster population at its ceiling). The roster is
/// sized to the shared-session ceiling and trust is a live function,
/// so on a healthy node this stays at zero; a rising value means
/// removals are again paying O(table) per close under the global
/// mutex — the #15106/#16561 regression — and names the cause.
/// Surfaced as `xpf_userspace_shared_wire_fallback_scans_total`.
pub(crate) static SHARED_WIRE_FALLBACK_SCANS: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
pub(crate) fn shared_wire_fallback_scans_total() -> u64 {
    SHARED_WIRE_FALLBACK_SCANS.load(Ordering::Relaxed)
}
