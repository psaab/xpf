//! WireGuard on-wire handshake-message framing (message types 1 and 2).
//!
//! The engine ([`super::engine`]) drives the Noise IKpsk2 handshake through
//! `snow`, which emits only the raw Noise message body. This module wraps
//! that body in the WireGuard outer framing so the bytes are byte-identical
//! to what kernel WireGuard / wireguard-go / UniFi put on the wire:
//!
//! ## Message 1 — Handshake Initiation (148 bytes)
//!
//! ```text
//!   off  size  field
//!    0    1    message_type = 1
//!    1    3    reserved_zero = {0,0,0}
//!    4    4    sender_index            (LE u32, initiator-chosen)
//!    8   32    unencrypted_ephemeral   ─┐
//!   40   48    encrypted_static (32+16) ├─ snow IK msg1 body (108 bytes)
//!   88   28    encrypted_timestamp(12+16)┘  Noise payload = 12-byte TAI64N
//!  116   16    mac1
//!  132   16    mac2
//! ```
//!
//! ## Message 2 — Handshake Response (92 bytes)
//!
//! ```text
//!   off  size  field
//!    0    1    message_type = 2
//!    1    3    reserved_zero = {0,0,0}
//!    4    4    sender_index            (LE u32, responder-chosen)
//!    8    4    receiver_index          (LE u32, echoes msg1.sender_index)
//!   12   32    unencrypted_ephemeral   ─┐ snow IK msg2 body (48 bytes)
//!   44   16    encrypted_nothing (0+16) ┘  Noise payload = empty
//!   60   16    mac1
//!   76   16    mac2
//! ```
//!
//! ## MAC1
//!
//! `mac1 = keyed-BLAKE2s-128(key, msg[0 .. offsetof(mac1)])` where
//! `key = BLAKE2s-256(LABEL_MAC1 || recipient_static_public)` and
//! `LABEL_MAC1 = b"mac1----"`. The MAC keys on the RECIPIENT's static
//! public key: for msg1 the recipient is the responder, for msg2 the
//! recipient is the initiator. This is keyed-BLAKE2s, NOT HMAC — the KAT
//! tests pin the distinction (an HMAC over the same key/message yields a
//! different value).
//!
//! ## MAC2
//!
//! `mac2 = keyed-BLAKE2s-128(last_received_cookie, msg[0 .. offsetof(mac2)])`
//! or all-zeros when no cookie has been received. S1 only ever emits zeros
//! (cookie/type-3 handling is #1703 S7) and SKIP-verifies inbound mac2 (a
//! peer holding our cookie sets it; treating non-zero as malformed would
//! wrongly drop such a peer). mac2 generation/verification lands in S7.

use blake2::Blake2s256;
use blake2::Blake2sMac;
use blake2::digest::consts::U16;
use blake2::digest::{FixedOutput, KeyInit, Update};
use blake2::digest::Digest;

use super::{
    WG_KEY_LEN, WG_LABEL_MAC1, WG_MAC_LEN, WG_MSG_INIT_LEN, WG_MSG_RESPONSE_LEN,
    WG_TYPE_INITIATION, WG_TYPE_RESPONSE,
};

/// snow IK message-1 Noise body length:
///   ephemeral(32) + encrypted_static(32+16) + encrypted_timestamp(12+16).
pub(crate) const MSG_INIT_NOISE_LEN: usize = 32 + (32 + 16) + (12 + 16); // 108

/// snow IK message-2 Noise body length:
///   ephemeral(32) + encrypted_nothing(0+16).
pub(crate) const MSG_RESPONSE_NOISE_LEN: usize = 32 + 16; // 48

// Message-1 field offsets.
const M1_TYPE: usize = 0;
const M1_SENDER: usize = 4;
const M1_NOISE: usize = 8;
const M1_MAC1: usize = M1_NOISE + MSG_INIT_NOISE_LEN; // 116
const M1_MAC2: usize = M1_MAC1 + WG_MAC_LEN; // 132

// Message-2 field offsets.
const M2_TYPE: usize = 0;
const M2_SENDER: usize = 4;
const M2_RECEIVER: usize = 8;
const M2_NOISE: usize = 12;
const M2_MAC1: usize = M2_NOISE + MSG_RESPONSE_NOISE_LEN; // 60
const M2_MAC2: usize = M2_MAC1 + WG_MAC_LEN; // 76

// Compile-time invariants: the offset arithmetic must agree with the
// published wire lengths.
const _: () = assert!(M1_MAC2 + WG_MAC_LEN == WG_MSG_INIT_LEN);
const _: () = assert!(M2_MAC2 + WG_MAC_LEN == WG_MSG_RESPONSE_LEN);

/// Framing errors. All variants are non-fatal at the call site (the slow
/// path counts them); a malformed or unauthenticated message is dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FramingError {
    /// The datagram length is not EXACTLY the fixed message size. WG
    /// handshake messages are fixed-length (148 / 92 bytes); kernel WG and
    /// wireguard-go reject `len != MessageInitiationSize` / `MessageResponseSize`
    /// outright. We reject both too-short AND too-long (a trailing-garbage
    /// datagram whose 148/92-byte prefix happens to verify must not parse).
    WrongLength,
    /// Output buffer too small to hold the framed message.
    OutputTooSmall,
    /// `message_type` byte is not the expected 1 (init) or 2 (response).
    BadType,
    /// The supplied Noise body length does not match the message type.
    BadNoiseLen,
    /// mac1 did not verify against `BLAKE2s-256(LABEL_MAC1 || our_pub)`.
    /// A compliant peer (and kernel WG) drops the datagram here, before
    /// any Noise crypto.
    Mac1Mismatch,
}

/// Derive the MAC1 keyed-hash key for `recipient_static_pub`:
/// `BLAKE2s-256(LABEL_MAC1 || recipient_pub)`. #9918 F-144: the engine
/// precomputes this once at construction (its local pub never changes)
/// so the inbound parse avoids one BLAKE2s-256 per message on the
/// under-load flood path.
pub(crate) fn mac1_key_for(recipient_static_pub: &[u8; WG_KEY_LEN]) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    Digest::update(&mut hasher, WG_LABEL_MAC1);
    Digest::update(&mut hasher, recipient_static_pub);
    hasher.finalize().into()
}

/// Compute MAC1 with a precomputed key (see [`mac1_key_for`]).
/// `mac1 = keyed-BLAKE2s-128(key, data)`. NOT HMAC.
pub(crate) fn compute_mac1_with_key(key: &[u8; 32], data: &[u8]) -> [u8; WG_MAC_LEN] {
    let mut mac = <Blake2sMac<U16> as KeyInit>::new_from_slice(key)
        .expect("MAC1 key is a valid 32-byte BLAKE2s key");
    Update::update(&mut mac, data);
    let mut out = [0u8; WG_MAC_LEN];
    FixedOutput::finalize_into(mac, (&mut out).into());
    out
}

/// Compute the keyed-BLAKE2s-128 MAC1 over `data` using the recipient's
/// static public key.
///
/// `key = BLAKE2s-256(LABEL_MAC1 || recipient_static_pub)`,
/// `mac1 = keyed-BLAKE2s-128(key, data)`.
///
/// Slow path only (handshake build/parse), never per-packet.
pub(crate) fn compute_mac1(recipient_static_pub: &[u8; WG_KEY_LEN], data: &[u8]) -> [u8; WG_MAC_LEN] {
    compute_mac1_with_key(&mac1_key_for(recipient_static_pub), data)
}

/// Constant-time-ish comparison of two 16-byte MACs. MAC1 is computed over
/// public inputs (the message + a public key + a public label), so it is
/// not a secret-key comparison in the AEAD sense; nonetheless we avoid an
/// early-return byte loop to keep the habit. (`subtle` is not a dep here;
/// the fold avoids the short-circuit.)
#[inline]
fn macs_equal(a: &[u8; WG_MAC_LEN], b: &[u8; WG_MAC_LEN]) -> bool {
    let mut diff = 0u8;
    for i in 0..WG_MAC_LEN {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// A WG type-1 initiation produced by [`build_initiation`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct BuiltInitiation {
    pub len: usize,
}

/// Frame a WG type-1 initiation around a snow msg1 Noise body.
///
/// - `out` must be at least [`WG_MSG_INIT_LEN`] (148) bytes; the framed
///   message is written at `out[0..148]`.
/// - `sender_index` is the initiator's locally-chosen index (LE on wire).
/// - `noise_body` is exactly what snow `write_message(tai64n, ..)` produced
///   — must be [`MSG_INIT_NOISE_LEN`] (108) bytes.
/// - `responder_static_pub` keys mac1 (the recipient of msg1).
/// - mac2 is all-zeros in S1.
pub(crate) fn build_initiation(
    out: &mut [u8],
    sender_index: u32,
    noise_body: &[u8],
    responder_static_pub: &[u8; WG_KEY_LEN],
) -> Result<BuiltInitiation, FramingError> {
    if noise_body.len() != MSG_INIT_NOISE_LEN {
        return Err(FramingError::BadNoiseLen);
    }
    let msg = out.get_mut(..WG_MSG_INIT_LEN).ok_or(FramingError::OutputTooSmall)?;
    msg[M1_TYPE] = WG_TYPE_INITIATION;
    msg[1] = 0;
    msg[2] = 0;
    msg[3] = 0;
    msg[M1_SENDER..M1_SENDER + 4].copy_from_slice(&sender_index.to_le_bytes());
    msg[M1_NOISE..M1_MAC1].copy_from_slice(noise_body);
    // mac1 over msg[0..116].
    let mac1 = compute_mac1(responder_static_pub, &msg[..M1_MAC1]);
    msg[M1_MAC1..M1_MAC2].copy_from_slice(&mac1);
    // mac2 = zeros (S1).
    msg[M1_MAC2..WG_MSG_INIT_LEN].fill(0);
    Ok(BuiltInitiation {
        len: WG_MSG_INIT_LEN,
    })
}

/// A parsed WG type-1 initiation. Borrows the Noise body from the input.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ParsedInitiation<'a> {
    pub sender_index: u32,
    pub noise_body: &'a [u8],
}

/// Parse + authenticate a WG type-1 initiation with a precomputed MAC1 key.
/// Single core: [`parse_initiation`] derives the key inline and delegates
/// here, so the strict parse (length + canonical u32 type-word + MAC1)
/// cannot drift between the two entry points. #9918 F-144.
pub(crate) fn parse_initiation_with_key<'a>(
    msg: &'a [u8],
    mac1_key: &[u8; 32],
) -> Result<ParsedInitiation<'a>, FramingError> {
    // WG handshake messages are fixed-length; require EXACTLY 148 bytes
    // (kernel WG / wireguard-go reject any other length).
    if msg.len() != WG_MSG_INIT_LEN {
        return Err(FramingError::WrongLength);
    }
    // WG's message_type is a 32-bit little-endian word: a canonical
    // initiation is exactly 0x00000001, i.e. type byte = 1 AND the three
    // reserved bytes = 0. wireguard-go / kernel WG read the full u32 and
    // reject a non-canonical high byte, so we do too (strict parse). This is
    // also belt-and-suspenders: mac1 already covers bytes [0..116] including
    // the reserved bytes, so a forged non-zero-reserved datagram would fail
    // mac1 regardless — but rejecting it up front keeps us byte-strict.
    if !is_canonical_type(msg, WG_TYPE_INITIATION) {
        return Err(FramingError::BadType);
    }
    // Verify mac1 over msg[0..116] BEFORE handing the body to snow — kernel
    // WG drops on a bad mac1 before any crypto, and so do we.
    let expect = compute_mac1_with_key(mac1_key, &msg[..M1_MAC1]);
    let got = {
        let mut m = [0u8; WG_MAC_LEN];
        m.copy_from_slice(&msg[M1_MAC1..M1_MAC2]);
        m
    };
    if !macs_equal(&expect, &got) {
        return Err(FramingError::Mac1Mismatch);
    }
    // mac2 (msg[132..148]) is skip-verified in S1 (cookie handling is S7).
    let sender_index = u32::from_le_bytes([msg[4], msg[5], msg[6], msg[7]]);
    Ok(ParsedInitiation {
        sender_index,
        noise_body: &msg[M1_NOISE..M1_MAC1],
    })
}

/// Parse + authenticate a WG type-1 initiation.
///
/// `our_static_pub` is xpf's own static public key — the recipient key for
/// an inbound initiation; mac1 is verified against
/// `BLAKE2s-256(LABEL_MAC1 || our_static_pub)`. mac2 is NOT verified in S1
/// (skip-verify; a peer holding our cookie legitimately sets it). The
/// returned `noise_body` (108 bytes) is fed to snow `read_message`.
pub(crate) fn parse_initiation<'a>(
    msg: &'a [u8],
    our_static_pub: &[u8; WG_KEY_LEN],
) -> Result<ParsedInitiation<'a>, FramingError> {
    parse_initiation_with_key(msg, &mac1_key_for(our_static_pub))
}

/// True iff `msg`'s leading 4 bytes are exactly the little-endian u32
/// `expected_type` — i.e. the type byte matches AND the three reserved bytes
/// are zero. WG transmits `message_type` as a u32; a compliant peer's
/// initiation/response always has zero reserved bytes.
///
/// `pub(super)` since #5191 (A1-b9-F5): this is the SSOT for the WG type-word
/// check across the whole `wg` module. The transport-data parser
/// (`framing::parse_data_header`) and the CookieReply decrypt
/// (`cookie::decrypt_cookie_reply`) previously compared only the low byte,
/// which made xpf accept datagrams kernel WG / wireguard-go reject — a parser
/// differential, and the kind of ambiguity an evasion probe looks for. Callers
/// must length-check before calling: this indexes `msg[0..4]`.
#[inline]
pub(super) fn is_canonical_type(msg: &[u8], expected_type: u8) -> bool {
    let word = u32::from_le_bytes([msg[0], msg[1], msg[2], msg[3]]);
    word == expected_type as u32
}

/// A WG type-2 response produced by [`build_response`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct BuiltResponse {
    pub len: usize,
}

/// Frame a WG type-2 response around a snow msg2 Noise body.
///
/// - `out` must be at least [`WG_MSG_RESPONSE_LEN`] (92) bytes.
/// - `sender_index` is the responder's locally-chosen index.
/// - `receiver_index` MUST echo the initiator's msg1 sender_index.
/// - `noise_body` is snow `write_message(&[], ..)` output — must be
///   [`MSG_RESPONSE_NOISE_LEN`] (48) bytes.
/// - `initiator_static_pub` keys mac1 (the recipient of msg2).
pub(crate) fn build_response(
    out: &mut [u8],
    sender_index: u32,
    receiver_index: u32,
    noise_body: &[u8],
    initiator_static_pub: &[u8; WG_KEY_LEN],
) -> Result<BuiltResponse, FramingError> {
    if noise_body.len() != MSG_RESPONSE_NOISE_LEN {
        return Err(FramingError::BadNoiseLen);
    }
    let msg = out.get_mut(..WG_MSG_RESPONSE_LEN).ok_or(FramingError::OutputTooSmall)?;
    msg[M2_TYPE] = WG_TYPE_RESPONSE;
    msg[1] = 0;
    msg[2] = 0;
    msg[3] = 0;
    msg[M2_SENDER..M2_SENDER + 4].copy_from_slice(&sender_index.to_le_bytes());
    msg[M2_RECEIVER..M2_RECEIVER + 4].copy_from_slice(&receiver_index.to_le_bytes());
    msg[M2_NOISE..M2_MAC1].copy_from_slice(noise_body);
    let mac1 = compute_mac1(initiator_static_pub, &msg[..M2_MAC1]);
    msg[M2_MAC1..M2_MAC2].copy_from_slice(&mac1);
    msg[M2_MAC2..WG_MSG_RESPONSE_LEN].fill(0);
    Ok(BuiltResponse {
        len: WG_MSG_RESPONSE_LEN,
    })
}

/// A parsed WG type-2 response. Borrows the Noise body from the input.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ParsedResponse<'a> {
    pub sender_index: u32,
    pub receiver_index: u32,
    pub noise_body: &'a [u8],
}

/// Parse + authenticate a WG type-2 response with a precomputed MAC1 key.
/// Single core; [`parse_response`] delegates here. #9918 F-144.
pub(crate) fn parse_response_with_key<'a>(
    msg: &'a [u8],
    mac1_key: &[u8; 32],
) -> Result<ParsedResponse<'a>, FramingError> {
    if msg.len() != WG_MSG_RESPONSE_LEN {
        return Err(FramingError::WrongLength);
    }
    // Strict 32-bit LE type word (type byte 2 + zero reserved). See
    // `parse_initiation` / `is_canonical_type`.
    if !is_canonical_type(msg, WG_TYPE_RESPONSE) {
        return Err(FramingError::BadType);
    }
    let expect = compute_mac1_with_key(mac1_key, &msg[..M2_MAC1]);
    let got = {
        let mut m = [0u8; WG_MAC_LEN];
        m.copy_from_slice(&msg[M2_MAC1..M2_MAC2]);
        m
    };
    if !macs_equal(&expect, &got) {
        return Err(FramingError::Mac1Mismatch);
    }
    let sender_index = u32::from_le_bytes([msg[4], msg[5], msg[6], msg[7]]);
    let receiver_index = u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]);
    Ok(ParsedResponse {
        sender_index,
        receiver_index,
        noise_body: &msg[M2_NOISE..M2_MAC1],
    })
}

/// Parse + authenticate a WG type-2 response. `our_static_pub` is xpf's own
/// static public key (the recipient of a response is the initiator = us).
/// mac1 verified; mac2 skipped (S1).
pub(crate) fn parse_response<'a>(
    msg: &'a [u8],
    our_static_pub: &[u8; WG_KEY_LEN],
) -> Result<ParsedResponse<'a>, FramingError> {
    parse_response_with_key(msg, &mac1_key_for(our_static_pub))
}

#[cfg(test)]
#[path = "handshake_tests.rs"]
mod tests;
