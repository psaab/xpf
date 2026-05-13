/*
 * C bridge to libxdp's XSK helpers.
 *
 * libxdp's xsk.h provides inline ring operations and library functions
 * for UMEM/socket creation. The inline functions cannot be called
 * directly from Rust FFI, so we wrap them here.
 *
 * Linked against -lxdp (which pulls in -lbpf).
 */
#include <xdp/xsk.h>
#include <linux/if_xdp.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <poll.h>
#include <unistd.h>

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
    __u32 libxdp_flags,
    __u32 xdp_flags,
    __u16 bind_flags)
{
    struct xsk_socket_config cfg = {
        .rx_size      = rx_size,
        .tx_size      = tx_size,
        .libxdp_flags = libxdp_flags,
        .xdp_flags    = xdp_flags,
        .bind_flags   = bind_flags,
    };
    /* Private UMEM mode: one socket owns one UMEM.  Non-shared create uses
     * the UMEM's fill/comp rings directly, so the per-socket fill/comp
     * parameters are ignored by design. */
    (void)fill;
    (void)comp;
    return xsk_socket__create(xsk_out, ifname, queue_id, umem, rx, tx, &cfg);
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
    __u32 libxdp_flags,
    __u32 xdp_flags,
    __u16 bind_flags)
{
    struct xsk_socket_config cfg = {
        .rx_size      = rx_size,
        .tx_size      = tx_size,
        .libxdp_flags = libxdp_flags,
        .xdp_flags    = xdp_flags,
        .bind_flags   = bind_flags,
    };
    return xsk_socket__create_shared(xsk_out, ifname, queue_id, umem,
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
