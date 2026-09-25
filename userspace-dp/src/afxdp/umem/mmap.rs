// Raw OS memory allocation for AF_XDP UMEM regions.
//
// Owns the mmap()/munmap() lifecycle and the hugepage selection
// policy: try explicit 2 MB hugepages first, fall back to standard
// pages with a transparent-hugepage advisory hint.

use crate::afxdp::UMEM_FRAME_SIZE;
use std::io;
use std::os::raw::c_void;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Running total of UMEM bytes that FAILED to get explicit 2 MB hugepages and
/// fell back to standard pages. Reported on every fallback so the magnitude of
/// a partial shortfall is visible, not just its existence.
static FALLBACK_BYTES: AtomicU64 = AtomicU64::new(0);
/// Gates the one-time remedy line. The per-allocation line below always fires;
/// this keeps the (long) operator instruction from repeating once per binding.
static FALLBACK_REPORTED: AtomicBool = AtomicBool::new(false);

/// Process-wide UMEM fallback total for the status snapshot (#10729 X1-09).
/// Monotonic: regions never un-fall-back, so a Relaxed load is exact enough
/// for a ≤1/s operator scrape.
pub(in crate::afxdp) fn umem_fallback_bytes_total() -> u64 {
    FALLBACK_BYTES.load(Ordering::Relaxed)
}

pub(in crate::afxdp) struct MmapArea {
    ptr: NonNull<u8>,
    /// Original requested size (passed to XSK via as_nonnull_slice).
    len: usize,
    /// Actual mmap size (may be rounded up for hugepage alignment).
    mapped_len: usize,
    /// Whether the region is backed by explicit 2 MB hugepages.
    hugepage: bool,
}

const HUGE_PAGE_SIZE: usize = 2 * 1024 * 1024;

/// #9900 F-091: single-frame containment for a `(offset, len)` slice request.
///
/// A descriptor's bytes must live in ONE UMEM frame: a `(offset, len)` that
/// spans a 4 KiB boundary would forward the adjacent frame's bytes (a
/// cross-flow leak) instead of failing closed. The mapping-bounds check in
/// the callers stays; this is the second, orthogonal bound.
///
/// Boundary-inclusive by construction: a full frame at an aligned base
/// (`0 + 4096`), an RX descriptor at `base + 256` with `len <= 3840`, the
/// 96-byte meta read ending exactly at `desc.addr`, and in-place `±4`
/// views all pass. `len > 4096` or a boundary-crossing span fails. The
/// addition cannot overflow: `len <= 4096` is established first, so the sum
/// is at most `4095 + 4096`.
#[inline]
fn frame_contained(offset: usize, len: usize) -> bool {
    let frame = UMEM_FRAME_SIZE as usize;
    if len > frame {
        return false;
    }
    (offset & (frame - 1)) + len <= frame
}

impl MmapArea {
    pub(in crate::afxdp) fn new(len: usize) -> io::Result<Self> {
        // #1020: harden two corner cases that the syscall would otherwise
        // surface as a less-direct EINVAL or — worse — silently under-
        // allocate by wrapping past usize::MAX during alignment rounding.
        if len == 0 {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        // Round up to 2 MB boundary for hugepage eligibility, with a
        // checked add so a `len` near usize::MAX produces a clean error
        // instead of a wrapped (smaller) `aligned_len` that would
        // succeed mmap but under-allocate the UMEM.
        let aligned_len = len
            .checked_add(HUGE_PAGE_SIZE - 1)
            .ok_or_else(|| {
                io::Error::other("umem len would overflow on hugepage alignment")
            })?
            & !(HUGE_PAGE_SIZE - 1);

        // Attempt 1: explicit 2 MB hugepages (requires system reservation).
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                aligned_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE
                    | libc::MAP_ANONYMOUS
                    | libc::MAP_HUGETLB
                    | libc::MAP_POPULATE
                    | (21 << libc::MAP_HUGE_SHIFT), // MAP_HUGE_2MB
                -1,
                0,
            )
        };
        if ptr != libc::MAP_FAILED {
            let ptr = NonNull::new(ptr.cast::<u8>())
                .ok_or_else(|| io::Error::other("null mmap pointer"))?;
            eprintln!(
                "xpf-ha: umem alloc {} bytes ({} MB, 2MB hugepages)",
                aligned_len,
                aligned_len / (1024 * 1024)
            );
            return Ok(Self {
                ptr,
                len,
                mapped_len: aligned_len,
                hugepage: true,
            });
        }

        // Attempt 2: standard pages with MAP_POPULATE + THP advisory hint.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                aligned_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_POPULATE,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        // Best-effort: request transparent hugepage backing.
        // `madvise(MADV_HUGEPAGE)` can fail (EINVAL on unsupported
        // kernels, ENOMEM under pressure); the return is ignored
        // intentionally because falling back to non-THP standard
        // pages is correct.
        unsafe {
            libc::madvise(ptr, aligned_len, libc::MADV_HUGEPAGE);
        }
        let ptr =
            NonNull::new(ptr.cast::<u8>()).ok_or_else(|| io::Error::other("null mmap pointer"))?;
        // #7497 criterion 1: this fallback is a THROUGHPUT CLIFF, not a
        // neutral allocation strategy, and until now it announced itself in
        // the same register as the success path ("standard pages + THP hint").
        //
        // MADV_HUGEPAGE is advisory: the kernel may promote none of it. At
        // ring-entries 16384 one binding is 40960 4 KB pages, so an unpromoted
        // UMEM costs ~40960 TLB entries instead of ~80, and measured
        // throughput drops from 22.1 to 20.4 Gbps
        // (docs/userspace-dataplane-architecture.md). Nothing else reports it:
        // `is_hugepage_backed` has no consumer, there is no counter, and the
        // per-allocation line is one of hundreds in a boot.
        //
        // The deficit is a PROVISIONING error with a one-line remedy, so name
        // the remedy. `vm.nr_hugepages` must cover EVERY binding the planner
        // mints — `Σ min(rx_queues, 16)` over all binding candidates since
        // #7497, not one NIC's worth — and the pool is reservable only at boot
        // or via sysctl, never by this process.
        let total = FALLBACK_BYTES.fetch_add(aligned_len as u64, Ordering::Relaxed)
            + aligned_len as u64;
        eprintln!(
            "xpf-ha: umem alloc {} bytes ({} MB, standard pages + THP hint) \
             — NO explicit hugepages ({} MB of UMEM now unbacked)",
            aligned_len,
            aligned_len / (1024 * 1024),
            total / (1024 * 1024)
        );
        if !FALLBACK_REPORTED.swap(true, Ordering::Relaxed) {
            eprintln!(
                "xpf-ha: WARNING: the 2 MB hugepage pool could not back this UMEM. \
                 THP promotion is advisory, so throughput may stall in TLB-miss \
                 latency. This region alone needed {} x 2 MB pages; size \
                 vm.nr_hugepages (etc/sysctl.d/99-xpf-hugepages.conf) to cover \
                 EVERY region, i.e. the SUM of each interface's \
                 min(rx_queues, 16) over all binding candidates since #7497 \
                 (a shared-UMEM group is one region spanning several bindings). \
                 Then `sysctl --system` and restart xpfd; verify with \
                 `grep HugePages_ /proc/meminfo`.",
                aligned_len.div_ceil(HUGE_PAGE_SIZE)
            );
        }
        Ok(Self {
            ptr,
            len,
            mapped_len: aligned_len,
            hugepage: false,
        })
    }

    /// Returns the original requested length (for XSK registration).
    pub(in crate::afxdp) fn as_nonnull_slice(&self) -> NonNull<[u8]> {
        NonNull::slice_from_raw_parts(self.ptr, self.len)
    }

    /// Whether this region is backed by explicit 2 MB hugepages.
    pub(in crate::afxdp) fn is_hugepage_backed(&self) -> bool {
        self.hugepage
    }

    /// Byte view of `[offset, offset + len)` — `None` unless the range is
    /// inside the mapping AND contained in a single UMEM frame (#9900 F-091).
    pub(in crate::afxdp) fn slice(&self, offset: usize, len: usize) -> Option<&[u8]> {
        let end = offset.checked_add(len)?;
        if end > self.len {
            return None;
        }
        if !frame_contained(offset, len) {
            return None;
        }
        Some(unsafe { std::slice::from_raw_parts(self.ptr.as_ptr().add(offset), len) })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(in crate::afxdp) fn slice_mut(&mut self, offset: usize, len: usize) -> Option<&mut [u8]> {
        unsafe { self.slice_mut_unchecked(offset, len) }
    }

    /// Returns a `&mut [u8]` view into the UMEM region from a
    /// shared `&self` reference.
    ///
    /// It refers to ALIASING ONLY. The range itself IS checked: `offset +
    /// len` is computed with `checked_add` (so it cannot wrap), is rejected
    /// when it exceeds `self.len`, and — since #9900 F-091 — is rejected
    /// unless contained in a single UMEM frame (see `frame_contained`),
    /// returning `None` — every call site therefore already handles an
    /// out-of-range request. There is no bounds hole here; #7750 row 07
    /// proposed a bounds-checked variant on the strength of the name, which
    /// is why this paragraph exists.
    ///
    /// What is genuinely unchecked is the exclusivity of the returned `&mut`,
    /// which is produced from a shared `&self` and so cannot be enforced by
    /// the borrow checker. That is the caller's obligation, below.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that no other borrow (mutable or
    /// shared) into the same `[offset, offset + len)` byte range
    /// is live for the lifetime of the returned slice, and that no
    /// other thread is concurrently reading or writing that range.
    /// AF_XDP single-writer (owner-worker) discipline plus per-frame
    /// offset assignment from the free-frame ring is what holds
    /// these invariants in production.
    pub(in crate::afxdp) unsafe fn slice_mut_unchecked(
        &self,
        offset: usize,
        len: usize,
    ) -> Option<&mut [u8]> {
        let end = offset.checked_add(len)?;
        if end > self.len {
            return None;
        }
        if !frame_contained(offset, len) {
            return None;
        }
        Some(unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr().add(offset), len) })
    }
}

impl Drop for MmapArea {
    fn drop(&mut self) {
        // #5192: this `munmap` must not run until the `Umem` registered
        // against the region is gone — see `WorkerUmemInner`'s field
        // order and `crate::drop_order_probe`.
        #[cfg(test)]
        crate::drop_order_probe::record(crate::drop_order_probe::DropTag::MmapArea);
        let _ = unsafe { libc::munmap(self.ptr.as_ptr().cast::<c_void>(), self.mapped_len) };
    }
}


#[cfg(test)]
#[path = "mmap_tests.rs"]
mod harden_tests;
