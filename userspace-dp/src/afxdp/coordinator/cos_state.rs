use super::*;

pub(crate) struct SharedCoSState {
    pub(crate) owner_worker_by_queue: Arc<ArcSwap<BTreeMap<(i32, u8), u32>>>,
    pub(crate) owner_live_by_queue: Arc<ArcSwap<BTreeMap<(i32, u8), Arc<BindingLiveState>>>>,
    pub(crate) root_leases: Arc<ArcSwap<BTreeMap<i32, Arc<SharedCoSRootLease>>>>,
    pub(crate) exact_backlogs: Arc<ArcSwap<BTreeMap<i32, Arc<SharedCoSExactBacklog>>>>,
    pub(crate) queue_leases: Arc<ArcSwap<BTreeMap<(i32, u8), Arc<SharedCoSQueueLease>>>>,
    /// #917: per-shared_exact-queue V_min coordination Arcs.
    /// Allocated once per shared_exact CoS queue (mirror of
    /// `queue_leases`) and Arc-cloned to every worker servicing the
    /// queue. Slot count = configured num_workers; updated by the
    /// same reconcile pass that rebuilds leases.
    pub(crate) queue_vtime_floors: Arc<ArcSwap<BTreeMap<(i32, u8), Arc<SharedCoSQueueVtimeFloor>>>>,
}

impl SharedCoSState {
    pub(super) fn new() -> Self {
        Self {
            owner_worker_by_queue: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            owner_live_by_queue: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            root_leases: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            exact_backlogs: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            queue_leases: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            queue_vtime_floors: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
        }
    }
}
