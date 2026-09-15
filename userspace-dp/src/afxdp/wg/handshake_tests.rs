use super::*;

/// Independently re-derive the WG construction hashes the same way the
/// reference does (`InitialChainKey = BLAKE2s-256(NoiseConstruction)`,
/// `InitialHash = BLAKE2s-256(InitialChainKey || WGIdentifier)`), and
/// pin them to the canonical hex. Dual-source: a transcription typo
/// fails the hex, an impl/primitive bug fails the re-derivation. This
/// proves the `blake2` crate computes the WG hashes correctly even
/// though snow's prologue (not this module) is what mixes them at
/// runtime — it is the foundation the MAC1 KAT builds on.
#[test]
fn construction_hashes_match_spec() {
    let ick = {
        let mut h = Blake2s256::new();
        Digest::update(&mut h, b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s");
        h.finalize()
    };
    let ih = {
        let mut h = Blake2s256::new();
        Digest::update(&mut h, &ick);
        Digest::update(&mut h, b"WireGuard v1 zx2c4 Jason@zx2c4.com");
        h.finalize()
    };
    // Canonical values (computed offline from the WG construction; also
    // reproduced here from first principles above).
    let ick_hex = "60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36";
    let ih_hex = "2211b361081ac566691243db458ad5322d9c6c662293e8b70ee19c65ba079ef3";
    assert_eq!(hex(&ick), ick_hex);
    assert_eq!(hex(&ih), ih_hex);
}

/// MAC1 KAT: keyed-BLAKE2s-128, NOT HMAC. Dual-source — assert the baked
/// hex AND re-derive `compute_mac1`'s key independently. The baked value
/// `78df3b0a...` is the keyed-BLAKE2s-128 output; an HMAC-BLAKE2s
/// implementation over the same key + message would instead produce
/// `778123b8eb3dffafb3cc980b88b84bbc` (independently computed by Codex in
/// the plan-review), so pinning the keyed value to this exact hex would
/// fail loudly if `compute_mac1` were ever switched to HMAC — locking the
/// keyed-vs-HMAC distinction without taking an `hmac` dependency.
#[test]
fn mac1_keyed_blake2s_128_kat() {
    let pk = [0x42u8; 32];
    // compute_mac1 over message "abc" — the keyed-BLAKE2s-128 value.
    let mac = compute_mac1(&pk, b"abc");
    assert_eq!(hex(&mac), "78df3b0a90577688ce9d272d04a8fb90");
    // The HMAC-BLAKE2s value over the same inputs is documented-different;
    // this is NOT it, confirming compute_mac1 is keyed-BLAKE2s.
    assert_ne!(hex(&mac), "778123b8eb3dffafb3cc980b88b84bbc");

    // Independently re-derive the MAC1 key and confirm.
    let key = {
        let mut h = Blake2s256::new();
        Digest::update(&mut h, b"mac1----");
        Digest::update(&mut h, &pk);
        h.finalize()
    };
    assert_eq!(
        hex(&key),
        "172c34d6807bd7acef1a2471f20e928626c23ce0b9f90b326cf5f82d12480a4e"
    );
}

/// mac1 keys on the RECIPIENT's static pub: a msg1 built toward
/// responder R verifies under R's pubkey and FAILS under any other.
#[test]
fn mac1_keys_on_recipient_static_pub() {
    let resp_pub = [0x11u8; 32];
    let other_pub = [0x22u8; 32];
    let noise = [0xABu8; MSG_INIT_NOISE_LEN];
    let mut buf = [0u8; WG_MSG_INIT_LEN];
    build_initiation(&mut buf, 0xDEADBEEF, &noise, &resp_pub).unwrap();

    // Verifies under the responder pubkey it was built for.
    assert!(parse_initiation(&buf, &resp_pub).is_ok());
    // Fails under a different recipient pubkey.
    assert_eq!(
        parse_initiation(&buf, &other_pub).unwrap_err(),
        FramingError::Mac1Mismatch
    );
}

#[test]
fn msg1_layout_byte_offsets() {
    let resp_pub = [0x33u8; 32];
    let mut noise = [0u8; MSG_INIT_NOISE_LEN];
    for (i, b) in noise.iter_mut().enumerate() {
        *b = i as u8;
    }
    let mut buf = [0xFFu8; WG_MSG_INIT_LEN];
    let built = build_initiation(&mut buf, 0x01020304, &noise, &resp_pub).unwrap();
    assert_eq!(built.len, 148);
    assert_eq!(buf[0], WG_TYPE_INITIATION);
    assert_eq!(&buf[1..4], &[0, 0, 0], "reserved must be zero");
    // sender_index is little-endian.
    assert_eq!(&buf[4..8], &0x01020304u32.to_le_bytes());
    assert_eq!(&buf[8..116], &noise, "noise body at offset 8..116");
    // mac2 zeros.
    assert_eq!(&buf[132..148], &[0u8; 16]);
}

#[test]
fn msg2_layout_byte_offsets() {
    let init_pub = [0x44u8; 32];
    let mut noise = [0u8; MSG_RESPONSE_NOISE_LEN];
    for (i, b) in noise.iter_mut().enumerate() {
        *b = (i + 1) as u8;
    }
    let mut buf = [0xFFu8; WG_MSG_RESPONSE_LEN];
    let built = build_response(&mut buf, 0x0A0B0C0D, 0x01020304, &noise, &init_pub).unwrap();
    assert_eq!(built.len, 92);
    assert_eq!(buf[0], WG_TYPE_RESPONSE);
    assert_eq!(&buf[1..4], &[0, 0, 0]);
    assert_eq!(&buf[4..8], &0x0A0B0C0Du32.to_le_bytes(), "sender LE");
    assert_eq!(&buf[8..12], &0x01020304u32.to_le_bytes(), "receiver LE");
    assert_eq!(&buf[12..60], &noise, "noise body at offset 12..60");
    assert_eq!(&buf[76..92], &[0u8; 16], "mac2 zeros");
}

/// Full byte-exact msg1 KAT with a fixed responder pubkey and a fixed
/// (deterministic) Noise body. This pins the entire framing assembly —
/// type byte, reserved, LE sender, body placement, and the mac1 over
/// msg[0..116] — so an offset or endianness bug in the assembly fails
/// here even when the per-field KATs pass. (The Noise body is a fixed
/// pattern rather than a real snow output: this module's job is the
/// framing assembly + mac1; real snow transcript byte-exactness is covered
/// by `deterministic_handshake_vectors_9918` (production builders with
/// fixed ephemerals) and the S2 live kernel-WG interop.)
#[test]
fn msg1_full_kat_fixed_body() {
    let resp_pub = [0x42u8; 32];
    let mut noise = [0u8; MSG_INIT_NOISE_LEN];
    for (i, b) in noise.iter_mut().enumerate() {
        *b = i as u8;
    }
    let mut buf = [0u8; WG_MSG_INIT_LEN];
    build_initiation(&mut buf, 0x11223344, &noise, &resp_pub).unwrap();

    // Re-derive the expected mac1 independently of build_initiation's
    // own path: assemble the prefix by hand and keyed-BLAKE2s it.
    let mut prefix = Vec::with_capacity(116);
    prefix.push(1u8);
    prefix.extend_from_slice(&[0, 0, 0]);
    prefix.extend_from_slice(&0x11223344u32.to_le_bytes());
    prefix.extend_from_slice(&noise);
    assert_eq!(prefix.len(), 116);
    let expect_mac1 = compute_mac1(&resp_pub, &prefix);
    assert_eq!(&buf[116..132], &expect_mac1, "mac1 over msg[0..116]");
    assert_eq!(&buf[0..116], &prefix[..], "framed prefix byte-exact");
    assert_eq!(&buf[132..148], &[0u8; 16], "mac2 zeros");
}

/// Full byte-exact msg2 KAT (mirror of msg1).
#[test]
fn msg2_full_kat_fixed_body() {
    let init_pub = [0x42u8; 32];
    let mut noise = [0u8; MSG_RESPONSE_NOISE_LEN];
    for (i, b) in noise.iter_mut().enumerate() {
        *b = (200 - i) as u8;
    }
    let mut buf = [0u8; WG_MSG_RESPONSE_LEN];
    build_response(&mut buf, 0xAABBCCDD, 0x11223344, &noise, &init_pub).unwrap();

    let mut prefix = Vec::with_capacity(60);
    prefix.push(2u8);
    prefix.extend_from_slice(&[0, 0, 0]);
    prefix.extend_from_slice(&0xAABBCCDDu32.to_le_bytes());
    prefix.extend_from_slice(&0x11223344u32.to_le_bytes());
    prefix.extend_from_slice(&noise);
    assert_eq!(prefix.len(), 60);
    let expect_mac1 = compute_mac1(&init_pub, &prefix);
    assert_eq!(&buf[60..76], &expect_mac1, "mac1 over msg[0..60]");
    assert_eq!(&buf[0..60], &prefix[..], "framed prefix byte-exact");
    assert_eq!(&buf[76..92], &[0u8; 16], "mac2 zeros");
}

#[test]
fn framing_roundtrip_initiation() {
    let resp_pub = [0x55u8; 32];
    let noise = [0x77u8; MSG_INIT_NOISE_LEN];
    let mut buf = [0u8; WG_MSG_INIT_LEN];
    build_initiation(&mut buf, 0xCAFEF00D, &noise, &resp_pub).unwrap();
    let parsed = parse_initiation(&buf, &resp_pub).unwrap();
    assert_eq!(parsed.sender_index, 0xCAFEF00D);
    assert_eq!(parsed.noise_body, &noise);
}

#[test]
fn framing_roundtrip_response() {
    let init_pub = [0x66u8; 32];
    let noise = [0x88u8; MSG_RESPONSE_NOISE_LEN];
    let mut buf = [0u8; WG_MSG_RESPONSE_LEN];
    build_response(&mut buf, 0x12345678, 0x9ABCDEF0, &noise, &init_pub).unwrap();
    let parsed = parse_response(&buf, &init_pub).unwrap();
    assert_eq!(parsed.sender_index, 0x12345678);
    assert_eq!(parsed.receiver_index, 0x9ABCDEF0);
    assert_eq!(parsed.noise_body, &noise);
}

#[test]
fn parse_rejects_wrong_length_and_bad_type() {
    let pub_k = [0x99u8; 32];
    // Too short.
    assert_eq!(
        parse_initiation(&[0u8; 100], &pub_k).unwrap_err(),
        FramingError::WrongLength
    );
    // Too LONG: a valid 148-byte msg1 with trailing garbage must be
    // rejected (Copilot finding — fixed-length messages, no truncation).
    let resp_pub = [0x5Bu8; 32];
    let noise = [0x2Du8; MSG_INIT_NOISE_LEN];
    let mut over = vec![0u8; WG_MSG_INIT_LEN + 8];
    build_initiation(&mut over[..WG_MSG_INIT_LEN], 9, &noise, &resp_pub).unwrap();
    assert_eq!(
        parse_initiation(&over, &resp_pub).unwrap_err(),
        FramingError::WrongLength,
        "an oversized datagram must NOT parse by truncation"
    );
    // The exact-length prefix still parses on its own.
    assert!(parse_initiation(&over[..WG_MSG_INIT_LEN], &resp_pub).is_ok());

    // Same for the response: too-long is rejected.
    let init_pub = [0x6Cu8; 32];
    let rnoise = [0x3Eu8; MSG_RESPONSE_NOISE_LEN];
    let mut rover = vec![0u8; WG_MSG_RESPONSE_LEN + 4];
    build_response(&mut rover[..WG_MSG_RESPONSE_LEN], 1, 2, &rnoise, &init_pub).unwrap();
    assert_eq!(
        parse_response(&rover, &init_pub).unwrap_err(),
        FramingError::WrongLength
    );

    // Wrong type byte (response bytes parsed as initiation).
    let mut buf = [0u8; WG_MSG_INIT_LEN];
    buf[0] = WG_TYPE_RESPONSE;
    assert_eq!(
        parse_initiation(&buf, &pub_k).unwrap_err(),
        FramingError::BadType
    );
}

/// Strict 32-bit-LE type word: a correct type byte but a NON-ZERO
/// reserved byte must be rejected (the type is the u32 `0x00000001`, not
/// just byte 0). A real WG peer always sends zero reserved bytes; this
/// rejects non-canonical datagrams up front (Codex code-review finding 3).
#[test]
fn parse_rejects_nonzero_reserved_bytes() {
    let resp_pub = [0x5Au8; 32];
    let noise = [0x3Cu8; MSG_INIT_NOISE_LEN];
    let mut buf = [0u8; WG_MSG_INIT_LEN];
    build_initiation(&mut buf, 0x1234, &noise, &resp_pub).unwrap();
    // Sanity: canonical build parses.
    assert!(parse_initiation(&buf, &resp_pub).is_ok());
    // Flip a reserved byte — must be rejected as BadType (the high bytes
    // of the type word are non-zero), regardless of mac1.
    buf[2] = 0x01;
    assert_eq!(
        parse_initiation(&buf, &resp_pub).unwrap_err(),
        FramingError::BadType
    );

    // Same for the response.
    let init_pub = [0xA5u8; 32];
    let rnoise = [0xC3u8; MSG_RESPONSE_NOISE_LEN];
    let mut rbuf = [0u8; WG_MSG_RESPONSE_LEN];
    build_response(&mut rbuf, 1, 2, &rnoise, &init_pub).unwrap();
    assert!(parse_response(&rbuf, &init_pub).is_ok());
    rbuf[1] = 0xFF;
    assert_eq!(
        parse_response(&rbuf, &init_pub).unwrap_err(),
        FramingError::BadType
    );
}

/// S1 must SKIP-verify mac2: a peer that holds our cookie sets a
/// non-zero mac2; treating it as malformed would wrongly drop the
/// initiation. mac1 still authenticates the message.
#[test]
fn parse_initiation_accepts_nonzero_mac2() {
    let resp_pub = [0xAAu8; 32];
    let noise = [0xBBu8; MSG_INIT_NOISE_LEN];
    let mut buf = [0u8; WG_MSG_INIT_LEN];
    build_initiation(&mut buf, 7, &noise, &resp_pub).unwrap();
    // Stamp a non-zero mac2 (last 16 bytes) — must NOT affect parse,
    // because mac1 (which covers only msg[0..116]) is unchanged.
    buf[132..148].copy_from_slice(&[0xCD; 16]);
    let parsed = parse_initiation(&buf, &resp_pub).expect("non-zero mac2 must parse");
    assert_eq!(parsed.sender_index, 7);
}

#[test]
fn build_rejects_wrong_noise_len() {
    let pub_k = [0u8; 32];
    let mut buf = [0u8; WG_MSG_INIT_LEN];
    assert_eq!(
        build_initiation(&mut buf, 0, &[0u8; 10], &pub_k).unwrap_err(),
        FramingError::BadNoiseLen
    );
    let mut buf2 = [0u8; WG_MSG_RESPONSE_LEN];
    assert_eq!(
        build_response(&mut buf2, 0, 0, &[0u8; 10], &pub_k).unwrap_err(),
        FramingError::BadNoiseLen
    );
}

#[test]
fn build_rejects_small_output() {
    let pub_k = [0u8; 32];
    let noise = [0u8; MSG_INIT_NOISE_LEN];
    let mut small = [0u8; 100];
    assert_eq!(
        build_initiation(&mut small, 0, &noise, &pub_k).unwrap_err(),
        FramingError::OutputTooSmall
    );
}
/// #9918 F-144: the precomputed MAC1 key path is byte-identical to the
/// per-message derivation. All existing KATs exercise `compute_mac1` /
/// `parse_*` (which now delegate to the `_with_key` cores); this pins the
/// equivalence directly so a divergence fails loudly.
#[test]
fn mac1_precomputed_key_matches_kat_9918() {
    let pk = [0x42u8; 32];
    let key = mac1_key_for(&pk);
    assert_eq!(
        hex(&key),
        "172c34d6807bd7acef1a2471f20e928626c23ce0b9f90b326cf5f82d12480a4e"
    );
    let mac_a = compute_mac1(&pk, b"abc");
    let mac_b = compute_mac1_with_key(&key, b"abc");
    assert_eq!(mac_a, mac_b);
    assert_eq!(hex(&mac_b), "78df3b0a90577688ce9d272d04a8fb90");
    // Parses agree too.
    let noise = [0xABu8; MSG_INIT_NOISE_LEN];
    let mut buf = [0u8; WG_MSG_INIT_LEN];
    build_initiation(&mut buf, 1, &noise, &pk).unwrap();
    assert!(parse_initiation(&buf, &pk).is_ok());
    assert!(parse_initiation_with_key(&buf, &key).is_ok());
    let mut bad = buf;
    bad[116] ^= 0x01;
    assert!(parse_initiation(&bad, &pk).is_err());
    assert!(parse_initiation_with_key(&bad, &key).is_err());
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
