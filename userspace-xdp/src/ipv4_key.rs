//! #14323: the IPv4 BPF map-key encoding, stated once.
//!
//! The `userspace_local_v4` / `userspace_interface_nat_v4` / `dnat_table`
//! keys are the integer whose in-memory bytes are the wire octets: Go
//! writes them with `binary.BigEndian.Uint32` (maps_sync.go), and
//! `parse_ipv4` reads them back with `u32::from_be_bytes` of the header
//! octets. `early_filter.rs` documents the same convention.
//!
//! Two sites used `u32::from_ne_bytes` instead — the native-GRE inner
//! classifier in `lib.rs` and `shim_v4_key` in the WG kernel path — under
//! comments claiming Go uses native endian. On a little-endian host that
//! byte-reverses every non-palindromic address, so local/NAT/DNAT probes
//! missed real local addresses and falsely claimed transit destinations
//! whose reversal happened to be local.
//!
//! Nothing in here may take a dependency on `aya`, on a BPF map, or on
//! `std` — that is what keeps it host-compilable, and it is the whole
//! point (same shape as `early_filter` / `ipv4_len_gate`).

/// The BPF map key for an IPv4 address given as wire octets:
/// `u32::from_be_bytes`, matching Go's `binary.BigEndian.Uint32` writer
/// and `parse_ipv4`'s `dst_v4`.
#[inline(always)]
pub fn ipv4_map_key(octets: [u8; 4]) -> u32 {
    u32::from_be_bytes(octets)
}
