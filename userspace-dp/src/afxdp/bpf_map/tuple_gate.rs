use crate::session::SessionKey;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, LazyLock, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const SHARD_COUNT: usize = 256;
const SHARD_CAP: usize = 1024;
const ACQUIRE_BUDGET: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GateState {
    Idle,
    Publishing,
    Draining,
    Held,
    Finalizing,
    Aborting,
}

#[derive(Clone, Copy)]
enum GateClaim {
    Publish,
    Install,
    Lease,
}

#[derive(Debug)]
struct GateEntry {
    state: GateState,
    publishers: usize,
    installs: usize,
    sequence: u64,
}

impl GateEntry {
    fn idle() -> Self {
        Self {
            state: GateState::Idle,
            publishers: 0,
            installs: 0,
            sequence: 0,
        }
    }
}

struct Shard {
    entries: Mutex<HashMap<SessionKey, Arc<Mutex<GateEntry>>>>,
    next_sequence: AtomicU64,
}

#[derive(Default)]
struct Admission {
    active: usize,
    clear_pending: bool,
    clear_active: bool,
}

/// Shared helper-side admission gate for bare conntrack tuples.
///
/// The shard lock covers state validation and counter increment together. A
/// permit therefore cannot observe Idle, get pre-empted by a lease transition,
/// and then issue a BPF syscall after the tuple is Held. Different tuples use
/// different shard locks and proceed independently. The admission state fences
/// only the map-wide clear.
pub(crate) struct TupleGate {
    shards: Vec<Shard>,
    admission: Mutex<Admission>,
    admission_changed: Condvar,
}

impl TupleGate {
    pub(crate) fn new() -> Self {
        let shards = (0..SHARD_COUNT)
            .map(|_| Shard {
                entries: Mutex::new(HashMap::new()),
                next_sequence: AtomicU64::new(0),
            })
            .collect();
        Self {
            shards,
            admission: Mutex::new(Admission::default()),
            admission_changed: Condvar::new(),
        }
    }

    fn canonical(key: &SessionKey) -> SessionKey {
        let mut key = key.clone();
        key.routing_domain = 0;
        key.discriminator = Default::default();
        key
    }

    fn shard_index(key: &SessionKey) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) & (SHARD_COUNT - 1)
    }

    fn claim_entry(
        &self,
        key: &SessionKey,
        mode: GateClaim,
    ) -> Result<(usize, Arc<Mutex<GateEntry>>, u64), &'static str> {
        let index = Self::shard_index(key);
        let mut entries = self.shards[index]
            .entries
            .lock()
            .expect("tuple gate shard poisoned");
        let entry = if let Some(entry) = entries.get(key) {
            Arc::clone(entry)
        } else {
            if entries.len() >= SHARD_CAP {
                return Err("gate_shard_full");
            }
            let entry = Arc::new(Mutex::new(GateEntry::idle()));
            entries.insert(key.clone(), Arc::clone(&entry));
            entry
        };
        let mut state = entry.lock().expect("tuple gate entry poisoned");
        let allowed = match mode {
            GateClaim::Publish | GateClaim::Install => state.state == GateState::Idle,
            GateClaim::Lease => {
                state.state == GateState::Idle || state.state == GateState::Publishing
            }
        };
        if !allowed {
            return Err("gate_busy");
        }
        let sequence = if matches!(mode, GateClaim::Lease) {
            let sequence = self.shards[index]
                .next_sequence
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(1);
            state.sequence = sequence;
            state.state = GateState::Draining;
            sequence
        } else {
            state.state = GateState::Publishing;
            match mode {
                GateClaim::Publish => state.publishers += 1,
                GateClaim::Install => state.installs += 1,
                GateClaim::Lease => unreachable!(),
            }
            state.sequence
        };
        Ok((index, Arc::clone(&entry), sequence))
    }

    fn admit_tuple(self: &Arc<Self>) -> Result<Arc<TupleAdmission>, &'static str> {
        let mut admission = self.admission.lock().expect("tuple gate admission poisoned");
        if admission.clear_pending || admission.clear_active {
            return Err("clear_in_progress");
        }
        admission.active += 1;
        Ok(Arc::new(TupleAdmission {
            gate: Arc::clone(self),
        }))
    }

    fn remove_if_idle(&self, index: usize, key: &SessionKey, entry: &Arc<Mutex<GateEntry>>) {
        let mut shard = self.shards[index]
            .entries
            .lock()
            .expect("tuple gate shard poisoned");
        if !shard
            .get(key)
            .is_some_and(|current| Arc::ptr_eq(current, entry))
        {
            return;
        }
        // Keep the shard lock while re-checking the entry. No caller can
        // remove-and-reinsert this tuple between the check and the removal,
        // which closes the permit/ABA window.
        let state = entry.lock().expect("tuple gate entry poisoned");
        if state.state == GateState::Idle && state.publishers == 0 && state.installs == 0 {
            drop(state);
            shard.remove(key);
        }
    }

    fn rollback_claim(entry: &Arc<Mutex<GateEntry>>) {
        let mut state = entry.lock().expect("tuple gate entry poisoned");
        if state.state == GateState::Draining {
            state.state = if state.publishers == 0 && state.installs == 0 {
                GateState::Idle
            } else {
                GateState::Publishing
            };
        }
    }

    fn release_admission(&self) {
        let mut admission = self.admission.lock().expect("tuple gate admission poisoned");
        admission.active = admission.active.saturating_sub(1);
        self.admission_changed.notify_all();
    }

    pub(crate) fn with_publish<T>(
        self: &Arc<Self>,
        key: &SessionKey,
        f: impl FnOnce() -> T,
    ) -> Result<T, &'static str> {
        let admission = self.admit_tuple()?;
        let canonical = Self::canonical(key);
        let (index, entry, _) = self.claim_entry(&canonical, GateClaim::Publish)?;
        let permit = PublishPermit {
            gate: Arc::clone(self),
            index,
            key: canonical,
            entry,
            admission,
        };
        let result = f();
        drop(permit);
        Ok(result)
    }

    /// Non-blocking worker-install admission. The returned permit remains
    /// live through the complete table/BPF mutation and through clear fencing.
    pub(crate) fn try_acquire_install(
        self: &Arc<Self>,
        key: &SessionKey,
    ) -> Result<InstallPermit, &'static str> {
        let admission = self.admit_tuple()?;
        let canonical = Self::canonical(key);
        let (index, entry, _) = self.claim_entry(&canonical, GateClaim::Install)?;
        Ok(InstallPermit {
            gate: Arc::clone(self),
            index,
            key: canonical,
            entry,
            admission,
        })
    }
    pub(crate) fn try_acquire_installs(
        self: &Arc<Self>,
        keys: impl IntoIterator<Item = SessionKey>,
    ) -> Result<Vec<InstallPermit>, &'static str> {
        let mut keys: Vec<_> = keys.into_iter().map(|key| Self::canonical(&key)).collect();
        keys.sort_by(|a, b| {
            Self::shard_index(a)
                .cmp(&Self::shard_index(b))
                .then_with(|| format!("{a:?}").cmp(&format!("{b:?}")))
        });
        keys.dedup();
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let admission = self.admit_tuple()?;
        let mut permits = Vec::with_capacity(keys.len());
        for key in keys {
            match self.claim_entry(&key, GateClaim::Install) {
                Ok((index, entry, _)) => permits.push(InstallPermit {
                    gate: Arc::clone(self),
                    index,
                    key,
                    entry,
                    admission: Arc::clone(&admission),
                }),
                Err(err) => {
                    drop(permits);
                    drop(admission);
                    return Err(err);
                }
            }
        }
        Ok(permits)
    }

    pub(crate) fn acquire_lease(
        self: &Arc<Self>,
        keys: impl IntoIterator<Item = SessionKey>,
    ) -> Result<GateLease, &'static str> {
        let mut keys: Vec<_> = keys.into_iter().map(|key| Self::canonical(&key)).collect();
        keys.sort_by(|a, b| {
            Self::shard_index(a)
                .cmp(&Self::shard_index(b))
                .then_with(|| format!("{a:?}").cmp(&format!("{b:?}")))
        });
        keys.dedup();
        if keys.is_empty() {
            return Err("empty_gate_lease");
        }
        let admission = self.admit_tuple()?;
        let deadline = Instant::now() + ACQUIRE_BUDGET;
        loop {
            let mut claimed = Vec::with_capacity(keys.len());
            let mut failed = false;
            for key in &keys {
                let (index, entry, sequence) = match self.claim_entry(key, GateClaim::Lease) {
                    Ok(value) => value,
                    Err(err) => {
                        for (index, key, held_entry, _) in claimed.drain(..) {
                            Self::rollback_claim(&held_entry);
                            self.remove_if_idle(index, &key, &held_entry);
                        }
                        if err == "gate_shard_full" {
                            return Err(err);
                        }
                        failed = true;
                        break;
                    }
                };
                claimed.push((index, key.clone(), entry, sequence));
            }
            if failed {
                for (index, key, held_entry, _) in claimed.drain(..) {
                    Self::rollback_claim(&held_entry);
                    self.remove_if_idle(index, &key, &held_entry);
                }
                if Instant::now() >= deadline {
                    return Err("gate_timeout");
                }
                thread::yield_now();
                continue;
            }
            loop {
                let drained = claimed.iter().all(|(_, _, entry, _)| {
                    let state = entry.lock().expect("tuple gate entry poisoned");
                    state.publishers == 0 && state.installs == 0
                });
                if drained {
                    for (_, _, entry, _) in &claimed {
                        entry.lock().expect("tuple gate entry poisoned").state = GateState::Held;
                    }
                    return Ok(GateLease {
                        gate: Arc::clone(self),
                        entries: claimed,
                        admission,
                    });
                }
                if Instant::now() >= deadline {
                    for (index, key, entry, _) in claimed {
                        Self::rollback_claim(&entry);
                        self.remove_if_idle(index, &key, &entry);
                    }
                    return Err("gate_timeout");
                }
                thread::yield_now();
            }
        }
    }
    pub(crate) fn begin_clear(self: &Arc<Self>) -> Result<ClearFence, &'static str> {
        let mut admission = self.admission.lock().expect("tuple gate admission poisoned");
        admission.clear_pending = true;
        while admission.active != 0 || admission.clear_active {
            let (next, timeout) = self
                .admission_changed
                .wait_timeout(admission, Duration::from_millis(50))
                .expect("tuple gate admission poisoned");
            admission = next;
            if timeout.timed_out() && admission.active != 0 {
                admission.clear_pending = false;
                self.admission_changed.notify_all();
                return Err("clear_timeout");
            }
        }
        admission.clear_active = true;
        admission.clear_pending = false;
        Ok(ClearFence {
            gate: Arc::clone(self),
        })
    }


    pub(crate) fn shard_count(&self) -> usize {
        SHARD_COUNT
    }

    pub(crate) fn shard_capacity(&self) -> usize {
        SHARD_CAP
    }
}

struct TupleAdmission {
    gate: Arc<TupleGate>,
}

impl Drop for TupleAdmission {
    fn drop(&mut self) {
        self.gate.release_admission();
    }
}

pub(crate) struct GateLease {
    gate: Arc<TupleGate>,
    entries: Vec<(usize, SessionKey, Arc<Mutex<GateEntry>>, u64)>,
    admission: Arc<TupleAdmission>,
}

impl GateLease {
    pub(crate) fn sequence(&self, key: &SessionKey) -> Option<u64> {
        let key = TupleGate::canonical(key);
        self.entries
            .iter()
            .find(|(_, held, _, _)| *held == key)
            .map(|(_, _, _, sequence)| *sequence)
    }

    /// Whether this lease fences `key` (canonical bare-tuple compare). Lets a
    /// repair path mechanically verify its probe set against its lease instead
    /// of trusting the caller to pass matching sets — an uncovered repair is
    /// a programmer bug that must fail loud, never run unfenced.
    pub(crate) fn covers(&self, key: &SessionKey) -> bool {
        let key = TupleGate::canonical(key);
        self.entries.iter().any(|(_, held, _, _)| *held == key)
    }

    /// Transition the lease to Finalizing before the final survivor probe.
    pub(crate) fn begin_finalizing(&self) -> Result<(), &'static str> {
        for (_, _, entry, _) in &self.entries {
            let mut state = entry.lock().expect("tuple gate entry poisoned");
            if state.state != GateState::Held || state.publishers != 0 || state.installs != 0 {
                return Err("gate_busy");
            }
            state.state = GateState::Finalizing;
        }
        Ok(())
    }
}

impl Drop for GateLease {
    fn drop(&mut self) {
        for (index, key, entry, _) in self.entries.drain(..) {
            let mut state = entry.lock().expect("tuple gate entry poisoned");
            state.state = GateState::Idle;
            drop(state);
            self.gate.remove_if_idle(index, &key, &entry);
        }
    }
}

pub(crate) struct PublishPermit {
    gate: Arc<TupleGate>,
    index: usize,
    key: SessionKey,
    entry: Arc<Mutex<GateEntry>>,
    admission: Arc<TupleAdmission>,
}

impl Drop for PublishPermit {
    fn drop(&mut self) {
        let mut state = self.entry.lock().expect("tuple gate entry poisoned");
        state.publishers = state.publishers.saturating_sub(1);
        // A lease may already have moved Publishing -> Draining. Preserve
        // Draining after the last publisher exits so the lease can atomically
        // observe zero counts and claim Held without an admission gap.
        if state.publishers == 0
            && state.installs == 0
            && state.state == GateState::Publishing
        {
            state.state = GateState::Idle;
        }
        drop(state);
        self.gate.remove_if_idle(self.index, &self.key, &self.entry);
    }
}

pub(crate) struct InstallPermit {
    gate: Arc<TupleGate>,
    index: usize,
    key: SessionKey,
    entry: Arc<Mutex<GateEntry>>,
    admission: Arc<TupleAdmission>,
}

impl Drop for InstallPermit {
    fn drop(&mut self) {
        let mut state = self.entry.lock().expect("tuple gate entry poisoned");
        state.installs = state.installs.saturating_sub(1);
        if state.publishers == 0
            && state.installs == 0
            && state.state == GateState::Publishing
        {
            state.state = GateState::Idle;
        }
        drop(state);
        self.gate.remove_if_idle(self.index, &self.key, &self.entry);
    }
}

pub(crate) struct ClearFence {
    gate: Arc<TupleGate>,
}

impl Drop for ClearFence {
    fn drop(&mut self) {
        let mut admission = self.gate.admission.lock().expect("tuple gate admission poisoned");
        admission.clear_active = false;
        self.gate.admission_changed.notify_all();
    }
}

static GLOBAL_TUPLE_GATE: LazyLock<Arc<TupleGate>> = LazyLock::new(|| Arc::new(TupleGate::new()));

pub(crate) fn global_tuple_gate() -> Arc<TupleGate> {
    Arc::clone(&GLOBAL_TUPLE_GATE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::mpsc;

    fn key(port: u16, domain: u32) -> SessionKey {
        SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: 6,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            src_port: port,
            dst_port: 443,
            discriminator: Default::default(),
            routing_domain: domain,
        }
    }

    #[test]
    fn unrelated_tuples_have_independent_entries() {
        let gate = Arc::new(TupleGate::new());
        assert_eq!(gate.shard_count(), 256);
        assert_eq!(gate.shard_capacity(), 1024);
        gate.with_publish(&key(1000, 7), || ()).unwrap();
        gate.with_publish(&key(1001, 8), || ()).unwrap();
    }

    #[test]
    fn lease_blocks_same_tuple_publish_without_racing() {
        let gate = Arc::new(TupleGate::new());
        let lease = gate.acquire_lease([key(1000, 7)]).unwrap();
        assert_eq!(gate.with_publish(&key(1000, 8), || ()), Err("gate_busy"));
        drop(lease);
        assert_eq!(gate.with_publish(&key(1000, 8), || ()), Ok(()));
    }

    #[test]
    fn lease_drains_existing_publisher_and_blocks_reentry() {
        let gate = Arc::new(TupleGate::new());
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker_gate = Arc::clone(&gate);
        let worker = thread::spawn(move || {
            worker_gate
                .with_publish(&key(1000, 7), || {
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                })
                .unwrap();
        });
        started_rx.recv().unwrap();
        let lease_gate = Arc::clone(&gate);
        let lease_worker = thread::spawn(move || lease_gate.acquire_lease([key(1000, 8)]));
        thread::sleep(Duration::from_millis(2));
        assert_eq!(gate.with_publish(&key(1000, 9), || ()), Err("gate_busy"));
        release_tx.send(()).unwrap();
        worker.join().unwrap();
        let lease = lease_worker.join().unwrap().unwrap();
        assert!(lease.sequence(&key(1000, 10)).is_some());
        drop(lease);
    }

    #[test]
    fn lease_sequence_survives_entry_recreation() {
        let gate = Arc::new(TupleGate::new());
        let first = gate.acquire_lease([key(1000, 1)]).unwrap();
        let first_seq = first.sequence(&key(1000, 2)).unwrap();
        drop(first);
        let second = gate.acquire_lease([key(1000, 3)]).unwrap();
        let second_seq = second.sequence(&key(1000, 4)).unwrap();
        assert!(second_seq > first_seq);
    }
    #[test]
    fn finalizing_lease_blocks_publish_and_install_until_drop() {
        let gate = Arc::new(TupleGate::new());
        let lease = gate.acquire_lease([key(1000, 7)]).unwrap();
        assert_eq!(gate.with_publish(&key(1000, 8), || ()), Err("gate_busy"));
        assert!(matches!(
            gate.try_acquire_install(&key(1000, 9)),
            Err("gate_busy")
        ));
        drop(lease);
        assert_eq!(gate.with_publish(&key(1000, 10), || ()), Ok(()));
    }

    #[test]
    fn lease_covers_matches_bare_tuples_10512() {
        let gate = Arc::new(TupleGate::new());
        let lease = gate.acquire_lease([key(1000, 1), key(2000, 1)]).unwrap();
        assert!(lease.covers(&key(1000, 1)));
        assert!(lease.covers(&key(2000, 1)));
        assert!(!lease.covers(&key(3000, 1)));
        // Canonicalization: routing domain and discriminator are ignored,
        // so scoped variants of a leased tuple still report covered.
        let mut scoped = key(1000, 1);
        scoped.routing_domain = 100007;
        scoped.discriminator = crate::session::TunnelDiscriminator::Keyed(9);
        assert!(lease.covers(&scoped));
        drop(lease);
    }

    #[test]
    fn paired_install_failure_releases_prior_claim() {
        let gate = Arc::new(TupleGate::new());
        let held = gate.acquire_lease([key(1001, 1)]).unwrap();
        assert!(matches!(
            gate.try_acquire_installs([key(1000, 1), key(1001, 2)]),
            Err("gate_busy")
        ));
        drop(held);
        assert!(gate.try_acquire_install(&key(1000, 1)).is_ok());
    }

    #[test]
    fn clear_fence_rejects_new_admission() {
        let gate = Arc::new(TupleGate::new());
        let fence = gate.begin_clear().unwrap();
        assert_eq!(gate.with_publish(&key(1000, 7), || ()), Err("clear_in_progress"));
        drop(fence);
        assert_eq!(gate.with_publish(&key(1000, 7), || ()), Ok(()));
    }

    #[test]
    fn clear_fence_rejects_new_tuple_lease() {
        let gate = Arc::new(TupleGate::new());
        let fence = gate.begin_clear().unwrap();
        assert!(matches!(
            gate.acquire_lease([key(1000, 7)]),
            Err("clear_in_progress")
        ));
        drop(fence);
        assert!(gate.acquire_lease([key(1000, 7)]).is_ok());
    }

    #[test]
    fn clear_waits_for_active_permit() {
        let gate = Arc::new(TupleGate::new());
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker_gate = Arc::clone(&gate);
        let worker = thread::spawn(move || {
            worker_gate
                .with_publish(&key(1000, 7), || {
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                })
                .unwrap();
        });
        started_rx.recv().unwrap();
        let clear_gate = Arc::clone(&gate);
        let clear = thread::spawn(move || clear_gate.begin_clear().unwrap());
        thread::sleep(Duration::from_millis(2));
        assert!(!clear.is_finished());
        release_tx.send(()).unwrap();
        worker.join().unwrap();
        drop(clear.join().unwrap());
    }
}
