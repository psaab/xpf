// BPF map file descriptors owned by the Coordinator. Bundled
// together because they share lifecycle (loaded on `cluster up`,
// dropped on `cluster down`) and have no other state.

use crate::afxdp::bpf_map::OwnedFd;

/// #7209: the coordinator's BPF map descriptors, published behind an
/// `ArcSwap` so a reader can hold them across a teardown that replaces
/// them.
///
/// **The REFCOUNT is what makes this sound, not the swap.** These are
/// `Option<OwnedFd>`, and `OwnedFd::drop` calls `close(2)`. A reader that
/// obtained a raw `fd` from a plain field could have it closed underneath
/// it by a concurrent teardown — a use-after-close, not a stale read, so
/// republishing a "current" value cannot fix it. Holding an `Arc` keeps the
/// descriptors alive for exactly as long as the reader needs them: the old
/// set is dropped, and its fds closed, only when the last holder releases.
///
/// So do NOT "simplify" this to a `Mutex<BpfMaps>` or back to a plain
/// field on the grounds that it is only a publish mechanism. A mutex would
/// serialise access without extending any lifetime, and every existing test
/// would still pass, because nothing today reads these concurrently — safe
/// Rust prevents it, since every mutator takes `&mut self`. #7209 removes
/// that guarantee by putting the Coordinator behind an `Arc`; this field is
/// what replaces it.
///
/// Writers replace the WHOLE set (teardown → `BpfMaps::default()`, bringup
/// → the newly opened descriptors), never a single field, so a reader can
/// never observe a half-updated generation.
///
/// Not a hot path: packet workers copy raw descriptors into their own
/// `WorkerBpfMaps` at spawn and never load this.
#[derive(Default)]
pub(crate) struct BpfMaps {
    pub(crate) map_fd: Option<OwnedFd>,
    pub(crate) heartbeat_map_fd: Option<OwnedFd>,
    pub(crate) session_map_fd: Option<OwnedFd>,
    pub(crate) conntrack_v4_fd: Option<OwnedFd>,
    pub(crate) conntrack_v6_fd: Option<OwnedFd>,
    pub(crate) dnat_table_fd: Option<OwnedFd>,
    pub(crate) dnat_table_v6_fd: Option<OwnedFd>,
}
