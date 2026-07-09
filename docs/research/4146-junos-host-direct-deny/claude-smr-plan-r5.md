# Claude SMR — hostile plan-review r5 — #4146 (on plan r7)

Reviewer: Claude (self-model, HOSTILE). Base `b4f2ddb2f`, plan rev r7.

Codex r4 (on r6): (A) three-tier program RESOLVED, (C) IKE/NAT-T exemption
RESOLVED; (B) STILL-OPEN — the TCP/113 exclusion predicate. r7 folds it.

- **(B) TCP/113 fail-open — CLOSED.** Verified: with `system-services { all,
  ident-reset }` the coarse gate emits a bare all-`accept` that shadows the
  ident-reset RST (`daemon_nft.go:661`; Rust short-circuits on `all_services`,
  `forwarding.rs:399`), so 113 is coarse-ACCEPTED there. r6 excluded 113 from the
  fine drop whenever ident-reset was merely configured → an `application any`
  deny would exempt 113 then coarse-accept it (silent fail-open). r7 §6.7 now
  excludes 113 ONLY when the effective coarse verdict is the RST (`ident-reset ∈
  services` AND NOT `hostInboundAllowsAll`); a `{all, ident-reset}` zone keeps 113
  fine-eligible so the deny drops it. The general principle is now correct: a
  class is exempted from the fine DROP only when its effective coarse verdict is a
  non-`accept` terminal/exempt (ESP/AH always; coarse-admitted IKE; ident-reset
  RST) — never when coarse would `accept` it. §9.2 adds the `{all, ident-reset}`
  regression.

The r7 rule generalizes correctly and I could not construct a further fail-open:
ESP/AH is always pre-fine; IKE excluded only when coarse-admitted (else
coarse-dropped, immaterial); 113 excluded only when coarse-RST. Any coarse-accept
class stays fine-eligible so the deny can tighten it.

**Verdict: PLAN-READY.** r7 closes Codex r4's TCP/113 fail-open with the correct
effective-coarse-verdict predicate; the DROP-only + set-subtraction + three-tier +
verdict-aware fine-eligible-domain model is now a faithful, safe kernel projection
of the representable junos-host DENY subset. Residual items are the flagged
/engineer implementation risks (iifname/RETH resolution, fail-closed apply,
reading the zone coarse set for the domain predicate). Not a re-defer, not a
PLAN-KILL.
