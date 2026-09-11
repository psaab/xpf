//! SYN-cookie codec, SipHash24 MAC primitive, and validated-client
//! cache. Kept in one sibling so security-path crypto and its
//! supporting cache are auditable as a unit.
//!
//! Items live here:
//! - `SynCookieTuple` (4-tuple key)
//! - `SynCookieValidation`, `SynCookieChallenge`, `SynCookieAckVerdict`
//! - `SynCookieCodec` (mint/validate ISN, MAC derivation, epoch math)
//! - `SipHash24` (private MAC primitive)
//! - `SynCookieClientKey` (validated-client whitelist key: source-scoped,
//!   NO ephemeral source port — #9419)
//! - `SynCookieValidatedCache` (4-way set-associative recent-validated
//!   cookie cache so the ACK+SYN bypass path doesn't re-validate per
//!   packet). Keyed by `(zone_id, profile_gen, src_ip, dst_ip, dst_port)`
//!   (#2446 + #9419) and consulted non-destructively: the
//!   per-zone SYN-cookie profile generation is stamped on insert and
//!   compared on lookup, so a client validated under an old profile is a
//!   miss after the zone's SYN-cookie profile changes (the new profile's
//!   SYN-flood counter then re-sees the connection). Entries live for one
//!   cookie epoch and survive being read, so the client's post-RST
//!   `connect()` — on a NEW ephemeral port — is admitted (#9419).

use std::net::IpAddr;

use sha2::{Digest, Sha256};

use super::packet::ScreenPacketInfo;

// Bit-layout constants. Tests inspect mint_isn output bit-by-bit so
// these are pub(crate) (re-exported under #[cfg(test)] by mod.rs).
pub(crate) const SYN_COOKIE_EPOCH_BITS: u32 = 5;
pub(crate) const SYN_COOKIE_MSS_BITS: u32 = 3;
pub(crate) const SYN_COOKIE_MAC_BITS: u32 = 24;
pub(crate) const SYN_COOKIE_ISN_BITS: u32 = 32;
pub(crate) const SYN_COOKIE_LAYOUT_BITS: u32 =
    SYN_COOKIE_EPOCH_BITS + SYN_COOKIE_MSS_BITS + SYN_COOKIE_MAC_BITS;
pub(crate) const SYN_COOKIE_EPOCH_MASK: u32 = (1 << SYN_COOKIE_EPOCH_BITS) - 1;
pub(crate) const SYN_COOKIE_MSS_MASK: u32 = (1 << SYN_COOKIE_MSS_BITS) - 1;
const SYN_COOKIE_MAC_MASK: u32 = (1 << SYN_COOKIE_MAC_BITS) - 1;
pub(crate) const SYN_COOKIE_EPOCH_SHIFT: u32 = SYN_COOKIE_MSS_BITS + SYN_COOKIE_MAC_BITS;
pub(crate) const SYN_COOKIE_MSS_SHIFT: u32 = SYN_COOKIE_MAC_BITS;
const SYN_COOKIE_MAC_DOMAIN: u64 = u64::from_be_bytes(*b"xpf-sync");
const SYN_COOKIE_SECRET_LEFT_DOMAIN: u64 = u64::from_be_bytes(*b"xpf-sck0");
const SYN_COOKIE_SECRET_RIGHT_DOMAIN: u64 = u64::from_be_bytes(*b"xpf-sck1");
const SYN_COOKIE_CACHE_LEFT_DOMAIN: u64 = u64::from_be_bytes(*b"xpf-scv0");
const SYN_COOKIE_CACHE_RIGHT_DOMAIN: u64 = u64::from_be_bytes(*b"xpf-scv1");
const SYN_COOKIE_VALIDATED_CACHE_CAPACITY: usize = 4096;
const SYN_COOKIE_VALIDATED_CACHE_WAYS: usize = 4;
const SYN_COOKIE_VALIDATED_CACHE_TTL_SECS: u64 = SynCookieCodec::EPOCH_SECS;
#[cfg(not(test))]
pub(super) const SYN_COOKIE_STANDBY_ACK_VALIDATION_RATE_LIMIT_PER_SEC: u32 = 4096;
#[cfg(test)]
pub(super) const SYN_COOKIE_STANDBY_ACK_VALIDATION_RATE_LIMIT_PER_SEC: u32 = 8;
const _: [(); SYN_COOKIE_ISN_BITS as usize] = [(); SYN_COOKIE_LAYOUT_BITS as usize];

/// Three-bit MSS table encoded in userspace SYN cookies.
///
/// The index, not the raw MSS, is transmitted in the ISN. Values are sorted so
/// selection can choose the largest value not exceeding the peer-advertised MSS.
pub(crate) const SYN_COOKIE_MSS_VALUES: [u16; 8] =
    [536, 1200, 1300, 1360, 1400, 1440, 1460, 8960];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct SynCookieTuple {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

impl SynCookieTuple {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn from_packet(pkt: &ScreenPacketInfo) -> Self {
        Self {
            src_ip: pkt.src_ip,
            dst_ip: pkt.dst_ip,
            src_port: pkt.src_port,
            dst_port: pkt.dst_port,
        }
    }
}

/// Validated-client whitelist key (#9419).
///
/// Deliberately NOT `SynCookieTuple`. The cookie MAC binds the full
/// 4-tuple (that is what makes a cookie unforgeable for a given
/// connection), but the whitelist answers a different question: "has
/// this SOURCE recently proved, by returning a valid cookie, that it is
/// not spoofed?". That property belongs to the source ADDRESS and the
/// service it reached, never to one ephemeral port.
///
/// Including `src_port` made the design's own recovery step
/// (`docs/syn-cookie-flood-protection.md`, "Client retransmits SYN ->
/// passes as validated") unreachable: the challenge path answers a valid
/// cookie ACK with a RST, which aborts the just-ESTABLISHED socket, and
/// no TCP stack retransmits a SYN after `ECONNRESET` — the application
/// calls `connect()` again on a NEW ephemeral port, which missed the
/// port-scoped whitelist and was challenged and reset again, forever.
/// The eBPF ancestor keyed on `{src_ip, dst_ip, dst_port}` with no source
/// port (`git show 13fa1009ea:bpf/headers/xpf_common.h` —
/// `struct validated_client_key`); this restores that shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct SynCookieClientKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

impl SynCookieClientKey {
    pub(crate) fn from_packet(pkt: &ScreenPacketInfo) -> Self {
        Self {
            src_ip: pkt.src_ip,
            dst_ip: pkt.dst_ip,
            dst_port: pkt.dst_port,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct SynCookieValidation {
    pub full_epoch: u64,
    pub mss_index: u8,
    pub mss: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct SynCookieChallenge {
    pub cookie_isn: u32,
    pub peer_mss: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum SynCookieAckVerdict {
    NotApplicable,
    Validated,
    Invalid,
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct SynCookieCodec {
    master_key: [u8; 16],
}

impl SynCookieCodec {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const EPOCH_SECS: u64 = 64;

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const fn new(master_key: [u8; 16]) -> Self {
        Self { master_key }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn full_epoch_from_unix_secs(unix_secs: u64) -> u64 {
        unix_secs / Self::EPOCH_SECS
    }

    /// Derive the SYN-cookie full epoch from a caller-supplied Unix
    /// wall-clock seconds value. The timestamp is read once per monotonic
    /// second by `ScreenState::current_syn_cookie_full_epoch` rather than
    /// per packet (#3032): under a SYN flood every minted/validated cookie
    /// in the same second shares the same 64-second epoch, so the per-packet
    /// `SystemTime::now()` was redundant CPU. This leaf is pure — it never
    /// reads the OS clock. The seconds MUST be Unix wall-clock (not
    /// `CLOCK_MONOTONIC`): HA peers derive identical epochs across failover
    /// only because their Unix clocks are NTP-synced while their monotonic
    /// bases are unrelated (see `ScreenState::update_syn_cookie_master_key`).
    pub(super) fn current_full_epoch(now_secs: u64) -> u64 {
        Self::full_epoch_from_unix_secs(now_secs)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn mss_index(peer_mss: u16) -> u8 {
        let mut selected = 0u8;
        let mut i = 1;
        while i < SYN_COOKIE_MSS_VALUES.len() {
            if peer_mss >= SYN_COOKIE_MSS_VALUES[i] {
                selected = i as u8;
            }
            i += 1;
        }
        selected
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn mint_isn(
        &self,
        tuple: SynCookieTuple,
        zone_id: u16,
        full_epoch: u64,
        peer_mss: u16,
    ) -> u32 {
        let mss_index = Self::mss_index(peer_mss);
        let mac = self.cookie_mac(tuple, zone_id, full_epoch, mss_index);
        ((full_epoch as u32 & SYN_COOKIE_EPOCH_MASK) << SYN_COOKIE_EPOCH_SHIFT)
            | ((mss_index as u32 & SYN_COOKIE_MSS_MASK) << SYN_COOKIE_MSS_SHIFT)
            | mac
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn validate_isn(
        &self,
        tuple: SynCookieTuple,
        zone_id: u16,
        current_full_epoch: u64,
        cookie_isn: u32,
    ) -> Option<SynCookieValidation> {
        let full_epoch = Self::cookie_full_epoch(current_full_epoch, cookie_isn)?;
        self.validate_isn_at_epoch(tuple, zone_id, full_epoch, cookie_isn)
    }

    /// The full epoch a cookie was minted in: the validation candidate (next,
    /// current, previous) whose low bits match the cookie's wire epoch. The
    /// candidates are consecutive, so at most one value matches; #9173 selects
    /// the cookie's key by it.
    pub(crate) fn cookie_full_epoch(current_full_epoch: u64, cookie_isn: u32) -> Option<u64> {
        let wire_epoch = Self::wire_epoch(cookie_isn);
        Self::candidate_validation_epochs(current_full_epoch)
            .into_iter()
            .find(|epoch| (*epoch as u32 & SYN_COOKIE_EPOCH_MASK) == wire_epoch)
    }

    /// Check a cookie's MAC in a known full epoch (see `cookie_full_epoch`).
    pub(crate) fn validate_isn_at_epoch(
        &self,
        tuple: SynCookieTuple,
        zone_id: u16,
        full_epoch: u64,
        cookie_isn: u32,
    ) -> Option<SynCookieValidation> {
        let mss_index = ((cookie_isn >> SYN_COOKIE_MSS_SHIFT) & SYN_COOKIE_MSS_MASK) as u8;
        let wire_mac = cookie_isn & SYN_COOKIE_MAC_MASK;
        (self.cookie_mac(tuple, zone_id, full_epoch, mss_index) == wire_mac).then(|| {
            SynCookieValidation {
                full_epoch,
                mss_index,
                mss: SYN_COOKIE_MSS_VALUES[mss_index as usize],
            }
        })
    }

    fn candidate_validation_epochs(current_full_epoch: u64) -> [u64; 3] {
        [
            current_full_epoch.saturating_add(1),
            current_full_epoch,
            current_full_epoch.saturating_sub(1),
        ]
    }

    fn wire_epoch(cookie_isn: u32) -> u32 {
        (cookie_isn >> SYN_COOKIE_EPOCH_SHIFT) & SYN_COOKIE_EPOCH_MASK
    }

    pub(super) fn wire_epoch_matches_validation_window(
        current_full_epoch: u64,
        cookie_isn: u32,
    ) -> bool {
        let wire_epoch = Self::wire_epoch(cookie_isn);
        Self::candidate_validation_epochs(current_full_epoch)
            .iter()
            .any(|epoch| (*epoch as u32 & SYN_COOKIE_EPOCH_MASK) == wire_epoch)
    }

    fn cookie_mac(
        &self,
        tuple: SynCookieTuple,
        zone_id: u16,
        full_epoch: u64,
        mss_index: u8,
    ) -> u32 {
        let secret = self.epoch_secret(zone_id, full_epoch);
        let mut sip = SipHash24::new(secret[0], secret[1]);
        sip.write_u64(SYN_COOKIE_MAC_DOMAIN);
        sip.write_u16(zone_id);
        sip.write_u64(full_epoch);
        sip.write_u8(mss_index);
        sip.write_ip(tuple.src_ip);
        sip.write_ip(tuple.dst_ip);
        sip.write_u16(tuple.src_port);
        sip.write_u16(tuple.dst_port);
        (sip.finish() as u32) & SYN_COOKIE_MAC_MASK
    }

    fn epoch_secret(&self, zone_id: u16, full_epoch: u64) -> [u64; 2] {
        let k0 = u64::from_le_bytes(self.master_key[0..8].try_into().expect("fixed slice"));
        let k1 = u64::from_le_bytes(self.master_key[8..16].try_into().expect("fixed slice"));

        let mut left = SipHash24::new(k0, k1);
        left.write_u64(SYN_COOKIE_SECRET_LEFT_DOMAIN);
        left.write_u16(zone_id);
        left.write_u64(full_epoch);

        let mut right = SipHash24::new(k0, k1);
        right.write_u64(SYN_COOKIE_SECRET_RIGHT_DOMAIN);
        right.write_u16(zone_id);
        right.write_u64(full_epoch);

        [left.finish(), right.finish()]
    }

    pub(super) fn cache_hash_keys(&self) -> [u64; 2] {
        let k0 = u64::from_le_bytes(self.master_key[0..8].try_into().expect("fixed slice"));
        let k1 = u64::from_le_bytes(self.master_key[8..16].try_into().expect("fixed slice"));

        let mut left = SipHash24::new(k0, k1);
        left.write_u64(SYN_COOKIE_CACHE_LEFT_DOMAIN);

        let mut right = SipHash24::new(k0, k1);
        right.write_u64(SYN_COOKIE_CACHE_RIGHT_DOMAIN);

        [left.finish(), right.finish()]
    }
}

/// #9173: the SYN-cookie key ring, resolved from its published bases.
///
/// The control plane publishes BASES, not keys. A period's key is
/// HMAC-SHA256(base, "xpf-syncookie\0v3-epoch\0" || rotation epoch as 8
/// big-endian bytes), truncated to 16 bytes -- the Go control plane's
/// `deriveSYNCookieEpochKey` -- so keys rotate on the wall clock with no
/// republish, and two nodes holding one base agree on every period's key.
///
/// A key is chosen by the COOKIE's own full epoch (rotation epoch = full epoch
/// / `period_epochs`), never by publish order, so a cookie minted just before a
/// period boundary validates just after it. `refresh` derives the keys for the
/// rotation epochs before, at and after the latched epoch's, so a cookie two
/// periods old finds no key. Only the keys for the cookie's own period are tried
/// -- one, or two while a #6630 PSK rotation window adds an accept-only base --
/// so the adjacent periods add no attempts per ACK; only the PSK overlap
/// deliberately adds a second.
///
/// ABSENT (`Default`) and PRESENT are different states. An absent ring is an
/// older control plane that never sends one, and leaves the caller on its legacy
/// key. A present ring is authoritative: one with no usable base -- empty,
/// malformed, or with a period that is not a whole number of cookie epochs --
/// fails closed instead of falling back to the legacy key.
#[derive(Clone, Default)]
pub(crate) struct SynCookieKeyRing {
    present: bool,
    period_epochs: u64,
    bases: Vec<SynCookieRingBase>,
    /// The rotation epoch `entries` were derived around.
    derived_for: Option<u64>,
    entries: Vec<SynCookieRingEntry>,
}

#[derive(Clone, Copy)]
struct SynCookieRingBase {
    base: [u8; 32],
    accept_only: bool,
}

#[derive(Clone, Copy)]
struct SynCookieRingEntry {
    rotation_epoch: u64,
    accept_only: bool,
    codec: SynCookieCodec,
}

impl std::fmt::Debug for SynCookieKeyRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Bases and codecs hold key bytes: render the ring's shape, never a key.
        f.debug_struct("SynCookieKeyRing")
            .field("present", &self.present)
            .field("period_epochs", &self.period_epochs)
            .field("bases", &format_args!("{} <redacted>", self.bases.len()))
            .field("derived_for", &self.derived_for)
            .finish()
    }
}

/// HMAC-SHA256 (RFC 2104) under a 32-byte key, over the concatenation of `parts`.
fn hmac_sha256(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut block = [0u8; 64];
    block[..32].copy_from_slice(key);
    let mut inner = Sha256::new();
    inner.update(block.map(|b| b ^ 0x36));
    for part in parts {
        inner.update(*part);
    }
    let mut outer = Sha256::new();
    outer.update(block.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    let mut mac = [0u8; 32];
    mac.copy_from_slice(outer.finalize().as_slice());
    mac
}

impl SynCookieKeyRing {
    /// Build a PRESENT ring from `(base, accept_only)` bases. A period that is
    /// zero or not a whole number of cookie epochs yields a present ring with no
    /// usable key, which fails every cookie closed.
    pub(crate) fn new(
        period_secs: u64,
        bases: impl IntoIterator<Item = ([u8; 32], bool)>,
    ) -> Self {
        if period_secs == 0 || period_secs % SynCookieCodec::EPOCH_SECS != 0 {
            return Self::failed_closed();
        }
        Self {
            present: true,
            period_epochs: period_secs / SynCookieCodec::EPOCH_SECS,
            bases: bases
                .into_iter()
                .map(|(base, accept_only)| SynCookieRingBase { base, accept_only })
                .collect(),
            derived_for: None,
            entries: Vec::new(),
        }
    }

    /// A present ring with no usable key: what a malformed published ring
    /// becomes, so it fails closed rather than reading as absent.
    pub(crate) fn failed_closed() -> Self {
        Self {
            present: true,
            ..Self::default()
        }
    }

    /// One rotation epoch's 16-byte key from `base`: the helper's half of the
    /// control plane's `deriveSYNCookieEpochKey`.
    pub(crate) fn derive_epoch_key(base: &[u8; 32], rotation_epoch: u64) -> [u8; 16] {
        let epoch = rotation_epoch.to_be_bytes();
        let mac = hmac_sha256(base, &[&b"xpf-syncookie\0v3-epoch\0"[..], &epoch[..]]);
        let mut key = [0u8; 16];
        key.copy_from_slice(&mac[..16]);
        key
    }

    fn rotation_epoch(&self, full_epoch: u64) -> Option<u64> {
        full_epoch.checked_div(self.period_epochs)
    }

    /// Derive the keys for the rotation epochs before, at and after
    /// `full_epoch`'s. A no-op while that rotation epoch is unchanged, so the
    /// HMACs run once a period per worker, never per packet.
    pub(super) fn refresh(&mut self, full_epoch: u64) {
        let Some(rotation_epoch) = self.rotation_epoch(full_epoch) else {
            return;
        };
        if self.derived_for == Some(rotation_epoch) {
            return;
        }
        self.entries.clear();
        for epoch in rotation_epoch.saturating_sub(1)..=rotation_epoch.saturating_add(1) {
            for base in &self.bases {
                self.entries.push(SynCookieRingEntry {
                    rotation_epoch: epoch,
                    accept_only: base.accept_only,
                    codec: SynCookieCodec::new(Self::derive_epoch_key(&base.base, epoch)),
                });
            }
        }
        self.derived_for = Some(rotation_epoch);
    }

    /// The key to mint with in `full_epoch`, if one is derived. Accept-only
    /// keys never mint.
    pub(super) fn mint_codec(&self, full_epoch: u64) -> Option<SynCookieCodec> {
        let rotation_epoch = self.rotation_epoch(full_epoch)?;
        self.entries
            .iter()
            .find(|entry| !entry.accept_only && entry.rotation_epoch == rotation_epoch)
            .map(|entry| entry.codec)
    }

    /// Whether a control plane published this ring. A present ring is
    /// authoritative for every period; only an absent one leaves the caller on
    /// its legacy key. Only the cells read it; the dataplane branches on
    /// `present` inside the ring.
    #[cfg(test)]
    pub(super) fn is_present(&self) -> bool {
        self.present
    }

    /// The rotation epochs `refresh` derived keys for, ascending. Only the cells
    /// read it.
    #[cfg(test)]
    pub(super) fn derived_rotation_epochs(&self) -> Vec<u64> {
        let mut epochs: Vec<u64> = self
            .entries
            .iter()
            .map(|entry| entry.rotation_epoch)
            .collect();
        epochs.sort_unstable();
        epochs.dedup();
        epochs
    }

    /// The codec to mint with in `full_epoch`. A present ring gives this
    /// period's key, or `None` when it has no usable base, so the cookie fails
    /// closed rather than falling back to the legacy key. Only an absent ring
    /// (an older control plane) mints with `legacy`.
    pub(super) fn mint_codec_or_legacy(
        &self,
        full_epoch: u64,
        legacy: SynCookieCodec,
    ) -> Option<SynCookieCodec> {
        if self.present {
            self.mint_codec(full_epoch)
        } else {
            Some(legacy)
        }
    }

    /// Whether a cookie minted in `full_epoch` validates: against that period's
    /// keys for a present ring (a period with none is refused), or against
    /// `legacy` when the ring is absent.
    pub(super) fn validates(
        &self,
        legacy: SynCookieCodec,
        tuple: SynCookieTuple,
        zone_id: u16,
        full_epoch: u64,
        cookie_isn: u32,
    ) -> bool {
        if self.present {
            self.validate_isn_at_epoch(tuple, zone_id, full_epoch, cookie_isn)
        } else {
            legacy
                .validate_isn_at_epoch(tuple, zone_id, full_epoch, cookie_isn)
                .is_some()
        }
    }

    /// The cookie-epoch latch after reading the wall clock's `raw` epoch, with
    /// the keys derived for the result. Non-decreasing, as the cookie epoch has
    /// always been: following a backward clock step would re-accept cookies from
    /// epochs this node has already left, so a recorded ACK could validate again.
    /// Derived keys cover every epoch, so no step leaves the latch without a key.
    /// What the latch costs an HA peer on a different clock is #9712.
    pub(super) fn latch(&mut self, latched: u64, raw: u64) -> u64 {
        let epoch = latched.max(raw);
        self.refresh(epoch);
        epoch
    }

    /// Validate a cookie against the keys for `full_epoch`'s period only.
    pub(super) fn validate_isn_at_epoch(
        &self,
        tuple: SynCookieTuple,
        zone_id: u16,
        full_epoch: u64,
        cookie_isn: u32,
    ) -> bool {
        let Some(rotation_epoch) = self.rotation_epoch(full_epoch) else {
            return false;
        };
        self.entries
            .iter()
            .filter(|entry| entry.rotation_epoch == rotation_epoch)
            .any(|entry| {
                entry
                    .codec
                    .validate_isn_at_epoch(tuple, zone_id, full_epoch, cookie_isn)
                    .is_some()
            })
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SipHash24 {
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
    tail: [u8; 8],
    tail_len: usize,
    len: u64,
}

impl SipHash24 {
    pub(super) fn new(k0: u64, k1: u64) -> Self {
        Self {
            v0: 0x736f_6d65_7073_6575 ^ k0,
            v1: 0x646f_7261_6e64_6f6d ^ k1,
            v2: 0x6c79_6765_6e65_7261 ^ k0,
            v3: 0x7465_6462_7974_6573 ^ k1,
            tail: [0; 8],
            tail_len: 0,
            len: 0,
        }
    }

    pub(super) fn write_ip(&mut self, ip: IpAddr) {
        match ip {
            IpAddr::V4(v4) => {
                self.write_u8(4);
                self.write_bytes(&v4.octets());
            }
            IpAddr::V6(v6) => {
                self.write_u8(6);
                self.write_bytes(&v6.octets());
            }
        }
    }

    pub(super) fn write_u8(&mut self, value: u8) {
        self.write_bytes(&[value]);
    }

    pub(super) fn write_u16(&mut self, value: u16) {
        self.write_bytes(&value.to_be_bytes());
    }

    pub(super) fn write_u64(&mut self, value: u64) {
        self.write_bytes(&value.to_be_bytes());
    }

    pub(super) fn write_bytes(&mut self, mut bytes: &[u8]) {
        self.len += bytes.len() as u64;

        if self.tail_len > 0 {
            let fill = (8 - self.tail_len).min(bytes.len());
            self.tail[self.tail_len..self.tail_len + fill].copy_from_slice(&bytes[..fill]);
            self.tail_len += fill;
            bytes = &bytes[fill..];
            if self.tail_len == 8 {
                self.compress(u64::from_le_bytes(self.tail));
                self.tail = [0; 8];
                self.tail_len = 0;
            }
        }

        while bytes.len() >= 8 {
            let block = u64::from_le_bytes(bytes[..8].try_into().expect("fixed slice"));
            self.compress(block);
            bytes = &bytes[8..];
        }

        if !bytes.is_empty() {
            self.tail[..bytes.len()].copy_from_slice(bytes);
            self.tail_len = bytes.len();
        }
    }

    pub(super) fn finish(mut self) -> u64 {
        let mut last = self.len << 56;
        let mut i = 0;
        while i < self.tail_len {
            last |= (self.tail[i] as u64) << (8 * i);
            i += 1;
        }
        self.compress(last);
        self.v2 ^= 0xff;
        self.round();
        self.round();
        self.round();
        self.round();
        self.v0 ^ self.v1 ^ self.v2 ^ self.v3
    }

    fn compress(&mut self, block: u64) {
        self.v3 ^= block;
        self.round();
        self.round();
        self.v0 ^= block;
    }

    fn round(&mut self) {
        self.v0 = self.v0.wrapping_add(self.v1);
        self.v2 = self.v2.wrapping_add(self.v3);
        self.v1 = self.v1.rotate_left(13);
        self.v3 = self.v3.rotate_left(16);
        self.v1 ^= self.v0;
        self.v3 ^= self.v2;
        self.v0 = self.v0.rotate_left(32);
        self.v2 = self.v2.wrapping_add(self.v1);
        self.v0 = self.v0.wrapping_add(self.v3);
        self.v1 = self.v1.rotate_left(17);
        self.v3 = self.v3.rotate_left(21);
        self.v1 ^= self.v2;
        self.v3 ^= self.v0;
        self.v2 = self.v2.rotate_left(32);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct SynCookieValidatedKey {
    zone_id: u16,
    /// Per-zone SYN-cookie profile generation captured at validation time
    /// (#2446). A cached entry is only consumable while the zone's current
    /// generation still matches: a SYN-cookie-relevant profile change
    /// (disable/re-enable, syn-flood-threshold change, zone→profile
    /// rebinding) bumps the generation, so a tuple validated under the old
    /// profile is treated as a miss and re-validated under the new profile —
    /// the new profile's SYN-flood counter then sees the connection. The
    /// master-key-change `set_hash_keys` clear remains as defense in depth.
    profile_gen: u64,
    /// #9419: source-scoped, NOT the 4-tuple. See `SynCookieClientKey`.
    client: SynCookieClientKey,
}

#[derive(Clone, Copy, Debug)]
struct SynCookieValidatedEntry {
    key: SynCookieValidatedKey,
    expires_secs: u64,
    age: u64,
}

#[derive(Clone, Copy, Debug)]
struct SynCookieValidatedSet {
    entries: [Option<SynCookieValidatedEntry>; SYN_COOKIE_VALIDATED_CACHE_WAYS],
}

impl Default for SynCookieValidatedSet {
    fn default() -> Self {
        Self {
            entries: [None; SYN_COOKIE_VALIDATED_CACHE_WAYS],
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SynCookieValidatedCache {
    sets: Box<[SynCookieValidatedSet]>,
    ttl_secs: u64,
    hash_keys: [u64; 2],
    len: usize,
    clock: u64,
}

impl Default for SynCookieValidatedCache {
    fn default() -> Self {
        Self::new(
            SYN_COOKIE_VALIDATED_CACHE_CAPACITY,
            SYN_COOKIE_VALIDATED_CACHE_TTL_SECS,
        )
    }
}

impl SynCookieValidatedCache {
    pub(super) fn new(capacity: usize, ttl_secs: u64) -> Self {
        let set_count = capacity.div_ceil(SYN_COOKIE_VALIDATED_CACHE_WAYS);
        Self {
            sets: vec![SynCookieValidatedSet::default(); set_count].into_boxed_slice(),
            ttl_secs,
            hash_keys: [0x0706_0504_0302_0100, 0x0f0e_0d0c_0b0a_0908],
            len: 0,
            clock: 0,
        }
    }

    pub(super) fn insert(
        &mut self,
        zone_id: u16,
        profile_gen: u64,
        client: SynCookieClientKey,
        now_secs: u64,
    ) {
        if self.sets.is_empty() {
            return;
        }
        let key = SynCookieValidatedKey {
            zone_id,
            profile_gen,
            client,
        };
        let set_index = self.set_index(&key);
        self.clock = self.clock.wrapping_add(1);
        let set = &mut self.sets[set_index];
        let new_entry = SynCookieValidatedEntry {
            key,
            expires_secs: now_secs.saturating_add(self.ttl_secs),
            age: self.clock,
        };

        let mut empty_or_expired = None;
        let mut oldest_index = 0;
        let mut oldest_age = u64::MAX;

        for index in 0..SYN_COOKIE_VALIDATED_CACHE_WAYS {
            match set.entries[index] {
                Some(entry) if entry.key == key => {
                    set.entries[index] = Some(new_entry);
                    return;
                }
                Some(entry) if entry.expires_secs <= now_secs => {
                    empty_or_expired.get_or_insert(index);
                }
                Some(entry) => {
                    if entry.age < oldest_age {
                        oldest_age = entry.age;
                        oldest_index = index;
                    }
                }
                None => {
                    empty_or_expired.get_or_insert(index);
                }
            }
        }

        let replace_index = empty_or_expired.unwrap_or(oldest_index);
        if set.entries[replace_index].is_none() {
            self.len += 1;
        }
        set.entries[replace_index] = Some(new_entry);
    }

    /// Is this client currently whitelisted? #9419: this is a PEEK, not a
    /// take. It was `take_valid` — a hit removed the entry, so a client was
    /// admitted exactly once per cookie solved. Combined with the
    /// challenge-and-reset design (the valid ACK is answered with a RST, so
    /// the client must `connect()` again) that made a second connection
    /// impossible even from the same 4-tuple, and every subsequent one was
    /// re-challenged and re-reset. The whitelist is now bounded by its TTL
    /// (`SYN_COOKIE_VALIDATED_CACHE_TTL_SECS`, one cookie epoch) and by the
    /// #2446 profile generation, exactly like the eBPF `LRU_HASH` ancestor.
    /// Renamed rather than edited in place so any caller still assuming
    /// consume-on-hit fails to compile.
    ///
    /// Still `&mut self`: an entry that has aged out is reclaimed on the way
    /// past, and a matched-but-expired entry is evicted rather than left to
    /// occupy a way.
    pub(super) fn contains_valid(
        &mut self,
        zone_id: u16,
        profile_gen: u64,
        client: SynCookieClientKey,
        now_secs: u64,
    ) -> bool {
        if self.sets.is_empty() {
            return false;
        }
        let key = SynCookieValidatedKey {
            zone_id,
            profile_gen,
            client,
        };
        let set_index = self.set_index(&key);
        let set = &mut self.sets[set_index];
        let mut valid = false;

        for index in 0..SYN_COOKIE_VALIDATED_CACHE_WAYS {
            let Some(entry) = set.entries[index] else {
                continue;
            };
            if entry.key == key {
                valid = entry.expires_secs > now_secs;
                if !valid {
                    // Expired: reclaim the way instead of retaining a dead
                    // entry that would keep answering "miss".
                    set.entries[index] = None;
                    self.len = self.len.saturating_sub(1);
                }
                break;
            }
            if entry.expires_secs <= now_secs {
                set.entries[index] = None;
                self.len = self.len.saturating_sub(1);
            }
        }

        valid
    }

    pub(super) fn set_hash_keys(&mut self, hash_keys: [u64; 2]) {
        if self.hash_keys != hash_keys {
            self.hash_keys = hash_keys;
            self.clear();
        }
    }

    pub(super) fn clear(&mut self) {
        for set in self.sets.iter_mut() {
            *set = SynCookieValidatedSet::default();
        }
        self.len = 0;
        self.clock = 0;
    }

    fn set_index(&self, key: &SynCookieValidatedKey) -> usize {
        debug_assert!(!self.sets.is_empty());
        (self.key_hash(key) as usize) % self.sets.len()
    }

    fn key_hash(&self, key: &SynCookieValidatedKey) -> u64 {
        let mut sip = SipHash24::new(self.hash_keys[0], self.hash_keys[1]);
        sip.write_u16(key.zone_id);
        sip.write_u64(key.profile_gen);
        sip.write_ip(key.client.src_ip);
        sip.write_ip(key.client.dst_ip);
        sip.write_u16(key.client.dst_port);
        sip.finish()
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.len
    }

    #[cfg(test)]
    pub(super) fn capacity(&self) -> usize {
        self.sets.len() * SYN_COOKIE_VALIDATED_CACHE_WAYS
    }

    #[cfg(test)]
    pub(super) fn debug_set_index(
        &self,
        zone_id: u16,
        profile_gen: u64,
        client: SynCookieClientKey,
    ) -> Option<usize> {
        if self.sets.is_empty() {
            return None;
        }
        Some(self.set_index(&SynCookieValidatedKey {
            zone_id,
            profile_gen,
            client,
        }))
    }
}
