/*
 * C bridge to libxdp's XSK helpers.
 *
 * libxdp's xsk.h provides inline ring operations and library functions
 * for UMEM/socket creation. The inline functions cannot be called
 * directly from Rust FFI, so we wrap them here.
 *
 * Linked against the libxdp and libbpf snapshots build.rs takes (#9726):
 * -lxpfxdp, then -lxpfbpf for the libbpf symbols libxdp leaves undefined.
 * Neither is a system archive; see "Linked library provenance" in the README.
 */
#include <xdp/xsk.h>
#include <linux/if_xdp.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <poll.h>
#include <unistd.h>
#include <stddef.h>

/*
 * ── Build-time ABI coupling (#4976) ───────────────────────────────────
 *
 * The Rust side (src/xsk_ffi.rs) hand-mirrors these libxdp ring structs as
 * `XskRingProd`/`XskRingCons` and hands zeroed boxes of them to the creation
 * functions below for libxdp to populate in place as native
 * `struct xsk_ring_{prod,cons}`. Nothing else couples the *installed* libxdp
 * layout (this translation unit compiles against the xdp/xsk.h in libxdp's
 * pkg-config includedir, #9726) to that independent Rust copy. A
 * libxdp/header package upgrade that reorders or resizes the ring struct
 * would otherwise silently turn a clean rebuild into out-of-bounds writes /
 * misread indices at runtime.
 *
 * These assertions pin the installed `struct xsk_ring_{prod,cons}` to a fixed
 * 64-bit ABI contract; src/xsk_ffi.rs pins its Rust mirror to the SAME
 * numbers. If a libxdp upgrade changes the ring layout, this file fails to
 * compile (via build.rs's cc invocation) and the build stops here. Keep these
 * numbers in lockstep with the `const _` assertions in src/xsk_ffi.rs.
 */
_Static_assert(sizeof(void *) == 8, "xsk ring ABI assumes 64-bit pointers");

/*
 * #9726: the helper attaches its own XDP program and must keep libxdp from
 * loading one. bridge_fill_socket_config (below) sets
 * XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD in the config both socket-create
 * functions pass. Pin the header's value here, and export it, so a Rust test
 * can compare it with the libxdp_flags each create function passes to libxdp,
 * which the test-only capture seam (below) records.
 */
_Static_assert(XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD == 1,
               "libxdp changed XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD; re-validate bridge_fill_socket_config");

int bridge_xsk_libxdp_inhibit_prog_load_flag(void)
{
    return XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD;
}

#define XSK_RING_ABI_ASSERT(T)                                                 \
    _Static_assert(sizeof(struct T) == 48, #T " size drift vs Rust mirror");   \
    _Static_assert(_Alignof(struct T) == 8, #T " align drift vs Rust mirror"); \
    _Static_assert(offsetof(struct T, cached_prod) == 0, #T " cached_prod");   \
    _Static_assert(offsetof(struct T, cached_cons) == 4, #T " cached_cons");   \
    _Static_assert(offsetof(struct T, mask) == 8, #T " mask");                 \
    _Static_assert(offsetof(struct T, size) == 12, #T " size");                \
    _Static_assert(offsetof(struct T, producer) == 16, #T " producer");        \
    _Static_assert(offsetof(struct T, consumer) == 24, #T " consumer");        \
    _Static_assert(offsetof(struct T, ring) == 32, #T " ring");                \
    _Static_assert(offsetof(struct T, flags) == 40, #T " flags")

XSK_RING_ABI_ASSERT(xsk_ring_prod);
XSK_RING_ABI_ASSERT(xsk_ring_cons);

/* ── UMEM creation / destruction ──────────────────────────────────── */

int bridge_xsk_umem_create(
    struct xsk_umem **umem_out,
    void *umem_area,
    __u64 size,
    struct xsk_ring_prod *fill,
    struct xsk_ring_cons *comp,
    __u32 fill_size,
    __u32 comp_size,
    __u32 frame_size,
    __u32 headroom,
    __u32 flags)
{
    struct xsk_umem_config cfg = {
        .fill_size   = fill_size,
        .comp_size   = comp_size,
        .frame_size  = frame_size,
        .frame_headroom = headroom,
        .flags       = flags,
    };
    return xsk_umem__create(umem_out, umem_area, size, fill, comp, &cfg);
}

int bridge_xsk_umem_delete(struct xsk_umem *umem)
{
    return xsk_umem__delete(umem);
}

int bridge_xsk_umem_fd(const struct xsk_umem *umem)
{
    return xsk_umem__fd(umem);
}

/* ── Socket creation / destruction ────────────────────────────────── */

/*
 * #9726: the one place a socket config is filled. The helper attaches its own
 * XDP program, so libxdp must not load one (INHIBIT_PROG_LOAD), and xdp_flags
 * stays 0. Both create functions below fill their config here.
 */
static void bridge_fill_socket_config(
    struct xsk_socket_config *cfg,
    __u32 rx_size,
    __u32 tx_size,
    __u16 bind_flags)
{
    *cfg = (struct xsk_socket_config){
        .rx_size      = rx_size,
        .tx_size      = tx_size,
        .libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags    = 0,
        .bind_flags   = bind_flags,
    };
}

/*
 * #9726: TEST-ONLY SEAM. The create functions below reach libxdp through these
 * pointers. Production never calls bridge_xsk_capture_socket_create_for_test,
 * so the pointers keep their defaults, libxdp's xsk_socket__create and
 * xsk_socket__create_shared. A Rust test (src/xsk_ffi_tests.rs) swaps in the
 * capture functions to observe the config each create function passes to
 * libxdp. The pointers take their types from libxdp's declarations, so a
 * capture whose signature drifts from libxdp's fails to compile. The swap is not
 * synchronized: the crate's suite runs single-threaded (#8291).
 */
static __typeof__(xsk_socket__create) *bridge_socket_create = xsk_socket__create;
static __typeof__(xsk_socket__create_shared) *bridge_socket_create_shared =
    xsk_socket__create_shared;
static __u32 bridge_captured_libxdp_flags;

/* Each capture records config->libxdp_flags and returns -EINVAL. It reads no
 * other argument and creates no socket, so a test may pass null pointers. */
static int bridge_capture_socket_create(
    struct xsk_socket **xsk,
    const char *ifname,
    __u32 queue_id,
    struct xsk_umem *umem,
    struct xsk_ring_cons *rx,
    struct xsk_ring_prod *tx,
    const struct xsk_socket_config *config)
{
    bridge_captured_libxdp_flags = config->libxdp_flags;
    return -EINVAL;
}

static int bridge_capture_socket_create_shared(
    struct xsk_socket **xsk,
    const char *ifname,
    __u32 queue_id,
    struct xsk_umem *umem,
    struct xsk_ring_cons *rx,
    struct xsk_ring_prod *tx,
    struct xsk_ring_prod *fill,
    struct xsk_ring_cons *comp,
    const struct xsk_socket_config *config)
{
    bridge_captured_libxdp_flags = config->libxdp_flags;
    return -EINVAL;
}

/* #9726: test-only. A non-zero enable routes both create functions to the
 * captures; 0 restores libxdp's functions. Either resets the captured flags to 0. */
void bridge_xsk_capture_socket_create_for_test(int enable)
{
    bridge_captured_libxdp_flags = 0;
    bridge_socket_create = enable ? bridge_capture_socket_create : xsk_socket__create;
    bridge_socket_create_shared =
        enable ? bridge_capture_socket_create_shared : xsk_socket__create_shared;
}

/* #9726: test-only. The libxdp_flags a capture recorded since the last enable. */
__u32 bridge_xsk_captured_libxdp_flags(void)
{
    return bridge_captured_libxdp_flags;
}

int bridge_xsk_socket_create_private(
    struct xsk_socket **xsk_out,
    const char *ifname,
    __u32 queue_id,
    struct xsk_umem *umem,
    struct xsk_ring_cons *rx,
    struct xsk_ring_prod *tx,
    struct xsk_ring_prod *fill,
    struct xsk_ring_cons *comp,
    __u32 rx_size,
    __u32 tx_size,
    __u16 bind_flags)
{
    struct xsk_socket_config cfg;

    bridge_fill_socket_config(&cfg, rx_size, tx_size, bind_flags);
    /* Private UMEM mode: one socket owns one UMEM.  Non-shared create uses
     * the UMEM's fill/comp rings directly, so the per-socket fill/comp
     * parameters are ignored by design. */
    (void)fill;
    (void)comp;
    return bridge_socket_create(xsk_out, ifname, queue_id, umem, rx, tx, &cfg);
}

int bridge_xsk_socket_create_shared(
    struct xsk_socket **xsk_out,
    const char *ifname,
    __u32 queue_id,
    struct xsk_umem *umem,
    struct xsk_ring_cons *rx,
    struct xsk_ring_prod *tx,
    struct xsk_ring_prod *fill,
    struct xsk_ring_cons *comp,
    __u32 rx_size,
    __u32 tx_size,
    __u16 bind_flags)
{
    struct xsk_socket_config cfg;

    bridge_fill_socket_config(&cfg, rx_size, tx_size, bind_flags);
    return bridge_socket_create_shared(xsk_out, ifname, queue_id, umem,
                                       rx, tx, fill, comp, &cfg);
}

void bridge_xsk_socket_delete(struct xsk_socket *xsk)
{
    xsk_socket__delete(xsk);
}

int bridge_xsk_socket_fd(const struct xsk_socket *xsk)
{
    return xsk_socket__fd(xsk);
}

/* ── Fill ring (producer) ─────────────────────────────────────────── */

__u32 bridge_xsk_ring_prod_reserve(
    struct xsk_ring_prod *ring,
    __u32 nb,
    __u32 *idx_out)
{
    return xsk_ring_prod__reserve(ring, nb, idx_out);
}

void bridge_xsk_ring_prod_submit(struct xsk_ring_prod *ring, __u32 nb)
{
    xsk_ring_prod__submit(ring, nb);
}

void bridge_xsk_ring_prod_cancel(struct xsk_ring_prod *ring, __u32 nb)
{
    ring->cached_prod -= nb;
}

int bridge_xsk_ring_prod_needs_wakeup(const struct xsk_ring_prod *ring)
{
    return xsk_ring_prod__needs_wakeup(ring);
}

void bridge_xsk_fill_addr_set(
    struct xsk_ring_prod *fill,
    __u32 idx,
    __u64 addr)
{
    *xsk_ring_prod__fill_addr(fill, idx) = addr;
}

void bridge_xsk_tx_desc_set(
    struct xsk_ring_prod *tx,
    __u32 idx,
    __u64 addr,
    __u32 len,
    __u32 options)
{
    struct xdp_desc *desc = xsk_ring_prod__tx_desc(tx, idx);
    desc->addr = addr;
    desc->len  = len;
    desc->options = options;
}

/* ── RX ring (consumer) ───────────────────────────────────────────── */

__u32 bridge_xsk_ring_cons_peek(
    struct xsk_ring_cons *ring,
    __u32 nb,
    __u32 *idx_out)
{
    return xsk_ring_cons__peek(ring, nb, idx_out);
}

void bridge_xsk_ring_cons_release(struct xsk_ring_cons *ring, __u32 nb)
{
    xsk_ring_cons__release(ring, nb);
}

void bridge_xsk_ring_cons_cancel(struct xsk_ring_cons *ring, __u32 nb)
{
    xsk_ring_cons__cancel(ring, nb);
}

void bridge_xsk_rx_desc_get(
    const struct xsk_ring_cons *rx,
    __u32 idx,
    __u64 *addr_out,
    __u32 *len_out,
    __u32 *options_out)
{
    const struct xdp_desc *desc = xsk_ring_cons__rx_desc(rx, idx);
    *addr_out    = desc->addr;
    *len_out     = desc->len;
    *options_out = desc->options;
}

__u64 bridge_xsk_comp_addr_get(
    const struct xsk_ring_cons *comp,
    __u32 idx)
{
    return *xsk_ring_cons__comp_addr(comp, idx);
}

/* ── Ring state queries ───────────────────────────────────────────── */

__u32 bridge_xsk_cons_nb_avail(struct xsk_ring_cons *ring, __u32 nb)
{
    return xsk_cons_nb_avail(ring, nb);
}

__u32 bridge_xsk_prod_nb_free(struct xsk_ring_prod *ring, __u32 nb)
{
    return xsk_prod_nb_free(ring, nb);
}

/* Raw producer/consumer access for diagnostics */
__u32 bridge_xsk_ring_prod_producer(const struct xsk_ring_prod *ring)
{
    return __atomic_load_n(ring->producer, __ATOMIC_RELAXED);
}

__u32 bridge_xsk_ring_prod_consumer(const struct xsk_ring_prod *ring)
{
    return __atomic_load_n(ring->consumer, __ATOMIC_RELAXED);
}

__u32 bridge_xsk_ring_cons_producer(const struct xsk_ring_cons *ring)
{
    return __atomic_load_n(ring->producer, __ATOMIC_RELAXED);
}

__u32 bridge_xsk_ring_cons_consumer(const struct xsk_ring_cons *ring)
{
    return __atomic_load_n(ring->consumer, __ATOMIC_RELAXED);
}

/* ── XDP statistics via getsockopt ────────────────────────────────── */

int bridge_xsk_get_stats_v2(
    int fd,
    __u64 *rx_dropped,
    __u64 *rx_invalid_descs,
    __u64 *tx_invalid_descs,
    __u64 *rx_ring_full,
    __u64 *rx_fill_ring_empty_descs,
    __u64 *tx_ring_empty_descs)
{
    struct xdp_statistics stats;
    memset(&stats, 0, sizeof(stats));
    socklen_t optlen = sizeof(stats);
    int rc = getsockopt(fd, SOL_XDP, XDP_STATISTICS,
                        &stats, &optlen);
    if (rc != 0) return -errno;
    *rx_dropped               = stats.rx_dropped;
    *rx_invalid_descs         = stats.rx_invalid_descs;
    *tx_invalid_descs         = stats.tx_invalid_descs;
    *rx_ring_full             = stats.rx_ring_full;
    *rx_fill_ring_empty_descs = stats.rx_fill_ring_empty_descs;
    *tx_ring_empty_descs      = stats.tx_ring_empty_descs;
    return 0;
}
