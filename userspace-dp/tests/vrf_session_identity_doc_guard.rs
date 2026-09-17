//! #2387 VRF/routing-instance session-identity decision-record guard.
//!
//! `userspace-dp/src/afxdp/forwarding/README.md` documents the single-
//! forwarding-domain session-identity limitation and cites
//! `docs/research/2387-vrf-flow-identity/plan.md` as the decision record for
//! the deferred real fix (Track B). That plan lived ONLY on the unmerged
//! `research/2387-vrf-flow-identity` branch, so the in-tree citation dangled —
//! the same failure the #3643/#3651 guard (`pkg/api/zone_counter_doc_ref_test.go`)
//! exists to prevent, which its own comment records happening once before.
//!
//! FAIL-ON-REVERT: deleting the plan doc, dropping its §0 anchors, or restoring
//! the superseded "the fix needs an HA session-sync wire bump" wording in the
//! README makes this test go RED.
//!
//! The doc claims are also bound to the code they describe, so the decision
//! record cannot silently drift away from the runtime:
//!   * `SessionKey` is still the bare 5-tuple (no routing-domain field). When
//!     Track B lands this assertion fires and the README/plan MUST be updated
//!     in the same change — that is the point.
//!   * `install_with_protocol_with_origin` still opens with an unconditional
//!     `remove_entry(&key, RemovalKind::Replace)`, which is why "decline the
//!     fall through to the session-miss path" is not a viable cheap mitigation
//!     (the two colliding flows would evict each other per packet).
//!   * `pkg/cluster/sync_protocol.go` still uses length-gated trailing VALUE
//!     fields, which is why the domain can be carried additively with no
//!     `CurrentHAProtocolVersion` bump (plan §0a, correcting plan §4d).

use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("userspace-dp should live directly under the repo root")
        .to_path_buf()
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {}: {}", path.display(), e))
}

#[test]
fn vrf_session_identity_decision_record_exists_and_matches_runtime() {
    let root = repo_root();
    let plan_rel = "docs/research/2387-vrf-flow-identity/plan.md";
    let plan_path = root.join(plan_rel);
    let readme_path = root.join("userspace-dp/src/afxdp/forwarding/README.md");

    let readme = read(&readme_path);

    // The README must still be the citer; if the citation is dropped, this
    // guard has no subject and should be deleted deliberately, not silently.
    assert!(
        readme.contains(plan_rel),
        "{} must cite the #2387 decision record {plan_rel}",
        readme_path.display()
    );

    // The decision record itself must be on master, not stranded on a research
    // branch. `read` panics with the path when it is missing.
    let plan = read(&plan_path);

    for anchor in [
        "## 0. v5 engineering-time addendum",
        "### 0a.",
        "does NOT bump SessionSyncWireVersion",
        "install.rs:139",
        "**DENY**",
        "**ISOLATE**",
    ] {
        assert!(
            plan.contains(anchor),
            "{} must keep the {anchor:?} anchor the #2387 README claims rest on",
            plan_path.display()
        );
    }

    // The superseded cost claim (plan §4d as applied to a VALUE-carried domain)
    // must not come back into the shipped README: the fix does NOT need an HA
    // protocol-version bump.
    assert!(
        !readme.contains("wire bump"),
        "{} still carries the superseded \"HA session-sync wire bump\" claim for #2387; \
         the routing-domain rides as a length-gated trailing VALUE field (plan §0a)",
        readme_path.display()
    );
    for required in [
        "The HA session-sync wire does NOT need a version bump",
        "`CurrentHAProtocolVersion` never moves.",
        "Do NOT \"decline the hit and fall through\"",
    ] {
        assert!(
            readme.contains(required),
            "{} must document {required:?} (#2387 plan §0)",
            readme_path.display()
        );
    }
}

#[test]
fn vrf_session_identity_doc_claims_still_match_the_code() {
    let root = repo_root();

    // Claim 1 (#7160, Track B-P0 landed): the key now CARRIES a routing
    // domain. This assertion used to read `!key_rs.contains("routing_domain")`
    // and fired when the field was added, which is what forced the doc update
    // in the same change. Rather than delete it, it is INVERTED: the same
    // guard now pins the invariants the field depends on, so it keeps working
    // for the change after this one instead of silently retiring.
    let key_rs = read(&root.join("userspace-dp/src/session/key.rs"));
    assert!(
        key_rs.contains("pub routing_domain: u32,"),
        "SessionKey LOST its routing-domain discriminator. Reverting it \
         re-opens the #2387 cross-tenant collision: two routing instances \
         sharing a 5-tuple collapse to one conntrack entry, and the \
         established-session fast path hands tenant B tenant A's cached \
         egress, NAT and POLICY decision."
    );

    // The five key transforms split into two groups, and BOTH halves are
    // load-bearing. Phase 1 had all five preserving the domain, on the belief
    // that a flow's routing domain is the same in both directions. Phase 2
    // measured that and it is FALSE in this dataplane: the transit route
    // lookup is not VRF-isolated (it uses the default table unless a PBR term
    // overrides it), so a flow that ingresses on a routing-instance member
    // interface and egresses out of the default instance is a real, working
    // configuration whose reply resolves a different domain.
    //
    //   * SAME-DIRECTION transforms PRESERVE it (forward_wire_key,
    //     translated_session_key, reverse_session_key) — they name another key
    //     of the same direction, or navigate between the two halves of one
    //     flow.
    //   * REVERSE-MATCH transforms ZERO it (reverse_wire_key,
    //     reverse_canonical_key) — they build the index a REPLY is looked up
    //     under, and preserving the domain there blackholes every
    //     non-contained VRF flow's replies. That is a forwarding outage, not a
    //     hardening.
    //
    // Counted, not merely searched, both ways: a partial revert that "restores
    // symmetry" on one reverse transform and not the other, or that zeroes a
    // same-direction transform, is exactly the plausible mistake — and no
    // single-instance test can see either, because the field is 0 everywhere
    // in a single-instance config.
    let preserved = key_rs.matches("routing_domain: forward_key.routing_domain,").count()
        + key_rs.matches("routing_domain: key.routing_domain,").count();
    assert_eq!(
        preserved, 3,
        "expected the 3 SAME-DIRECTION key transforms (forward_wire_key, \
         translated_session_key, reverse_session_key) to carry the source \
         key's routing_domain, found {preserved}. A transform that zeroes one \
         of those loses the discriminator on a path that shares the forward \
         direction's identity."
    );
    let zeroed = key_rs
        .matches("// #7160 (#2387): REVERSE-MATCH key")
        .count();
    assert_eq!(
        zeroed, 2,
        "expected the 2 REVERSE-MATCH transforms (reverse_wire_key, \
         reverse_canonical_key) to build a domain-agnostic key, found \
         {zeroed} carrying the #7160 marker comment. Preserving the domain \
         there blackholes the replies of every flow whose reply arrives in \
         another routing domain."
    );

    // The zeroing above is only SAFE because the reverse bucket walk spends
    // the reply's own domain on a PREFERENCE instead. Delete the preference
    // and the reverse direction silently becomes first-installed-wins across
    // tenants while every test still passes, because a single-instance bucket
    // has one candidate either way.
    let lookup_rs = read(&root.join("userspace-dp/src/session/lookup.rs"));
    assert!(
        lookup_rs.contains("if record.key.routing_domain == reply_key.routing_domain {"),
        "find_forward_nat_match lost the #7160 two-pass domain preference over \
         the reverse bucket. The reverse-match index is keyed domain-agnostically \
         on purpose; the preference is the only thing that demuxes two contained \
         tenants sharing a 5-tuple on the reply direction."
    );
    assert!(
        lookup_rs.contains("zeroed = reverse_match_key(reply_key);"),
        "find_forward_nat_match no longer zeroes the reply key before probing \
         the reverse bucket — the two halves of the #7160 domain-agnostic \
         reverse-match convention have drifted apart, and a reply that resolved \
         a domain now looks for a bucket that was never inserted."
    );

    // Claim 1b (#7160 phase 2): the field is POPULATED, from ONE site.
    //
    // This assertion used to read `!on_the_wire` and fire when `routing_domain`
    // reached `src/protocol/`, which is what forced this doc update. Rather
    // than delete it, it is INVERTED: the config snapshot must still be where
    // the number arrives, and the stamp must still be a single site, so a
    // future change that starts deriving the domain somewhere else has to come
    // back through here.
    let snapshot_rs = read(&root.join("userspace-dp/src/protocol/snapshot.rs"));
    assert!(
        snapshot_rs.contains("pub routing_domain: u32,"),
        "InterfaceSnapshot LOST its routing_domain. The number is decided in Go \
         (routingInstanceDomain, pkg/dataplane/userspace/routes.go) and shipped \
         per interface; re-deriving it in Rust would be a second spelling of one \
         fact that has to mean the same thing on the HA peer."
    );
    let poll_rs = read(&root.join("userspace-dp/src/afxdp/poll_descriptor/mod.rs"));
    let stamps = poll_rs
        .matches("flow.forward_key.routing_domain =")
        .count();
    assert_eq!(
        stamps, 1,
        "expected EXACTLY ONE site stamping the flow's routing domain in the \
         poll path, found {stamps}. Every key the descriptor derives — lookup \
         key, installed forward key, reverse companion, index entries — has to \
         carry ONE domain; a second stamp is how they come to disagree."
    );

    // The stamp must run AFTER fabric-ingress classification. A frame that
    // arrived over the fabric link did not arrive on the flow's real ingress
    // interface, so the fabric link's own membership is a WRONG answer rather
    // than a missing one, and the peer's zone encoding is the only ingress
    // identity this node can resolve a domain from. Move the stamp above
    // stage 9 and that input is simply not available yet.
    let fabric_stage = poll_rs
        .find("stage_classify_fabric_ingress(packet_frame, &mut meta, now_secs, worker_ctx)")
        .expect("poll path should still call stage_classify_fabric_ingress");
    let stamp_at = poll_rs
        .find("flow.forward_key.routing_domain =")
        .expect("poll path should still stamp the routing domain");
    assert!(
        stamp_at > fabric_stage,
        "the #7160 routing-domain stamp moved ABOVE fabric-ingress \
         classification, so a fabric-redirected frame is now stamped with the \
         FABRIC LINK's routing domain instead of the peer-encoded ingress \
         zone's."
    );

    // The HA peer DERIVES the domain from the #7095 cluster-stable ingress
    // identity rather than reading a wire field. That is what keeps
    // CurrentHAProtocolVersion still, and what makes the two nodes unable to
    // disagree — there is only one spelling.
    let coordinator_rs = read(&root.join("userspace-dp/src/afxdp/coordinator/routing_domain.rs"));
    assert!(
        coordinator_rs.contains("pub fn synced_routing_domain("),
        "the #7160 synced-session routing-domain derivation is gone. If it was \
         replaced by a wire field, CurrentHAProtocolVersion still must not move \
         (plan v5 \u{a7}0a) and the field must be length-gated and trailing — and \
         this guard, the README wire bullet and the plan status all have to say \
         so."
    );

    // Claim 2: session install unconditionally evicts a same-key incumbent,
    // which is why declining a cross-domain hit and falling through to the
    // session-miss path is not a viable mitigation.
    let install_rs = read(&root.join("userspace-dp/src/session/install.rs"));
    assert!(
        install_rs.contains("let _previous = self.remove_entry(&key, RemovalKind::Replace);"),
        "session install no longer unconditionally evicts a same-key incumbent — \
         the #2387 README/plan rationale for rejecting \"decline the hit and fall \
         through\" no longer holds and must be revisited"
    );

    // Claim 3: the cross-chassis session wire still grows by length-gated
    // trailing VALUE fields, so a routing-domain is an append, not a flag day.
    let sync_go = read(&root.join("pkg/cluster/sync_protocol.go"));
    assert!(
        sync_go.contains("length-gated trailing field"),
        "pkg/cluster/sync_protocol.go lost its length-gated trailing-field \
         contract — the #2387 plan §0a \"no HA protocol-version bump\" finding \
         must be re-derived"
    );
    assert!(
        sync_go.contains("if off+8 <= len(payload)"),
        "pkg/cluster/sync_protocol.go lost the bounds-gated trailing-field \
         decode that makes an absent #2387 routing-domain decode as the default \
         routing-instance for a legacy peer"
    );

    // Claim 4: the Rust<->Go control-socket session sync is serde-defaulted, so
    // the same append is additive there too.
    let control_rs = read(&root.join("userspace-dp/src/protocol/control.rs"));
    let sync_req = control_rs
        .split_once("pub(crate) struct SessionSyncRequest {")
        .expect("SessionSyncRequest struct should exist in protocol/control.rs")
        .1;
    let sync_req_body = sync_req
        .split_once("\n}")
        .expect("SessionSyncRequest struct should be brace-terminated")
        .0;
    assert!(
        sync_req_body.contains("serde(default)"),
        "SessionSyncRequest is no longer serde-defaulted — the #2387 plan §0a \
         additive control-socket finding must be re-derived"
    );
}
