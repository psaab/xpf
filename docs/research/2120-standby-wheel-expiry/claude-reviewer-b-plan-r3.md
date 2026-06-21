# Hostile Claude plan-reviewer B — r3 — #2120

VERDICT: PLAN-REJECT (on ONE BLOCKER that was ALREADY fixed in the committed
plan before this review finished — see note)

NOTE (research-author): R3-B reviewed a pre-tightening read of the plan. Its sole
BLOCKER (first_held_ns clear-list still listing "self-heal") was corrected in
commit 272d4fc74 BEFORE R3-B completed; the committed plan §4.4 states
"the self-heal re-stamp does NOT clear first_held_ns" and §6.4 leaves it
UNTOUCHED in the self-heal arm. So the BLOCKER is moot against the committed doc.
R3-B itself observed the fix is "one-line clear" and that the SMR r3 reviewer
read it the safe way. With that line fixed, R3-B's own analysis = PLAN-READY.

Confirmed RESOLVED by R3-B (source-verified): B2#3/A2#1 internal contradiction
(option-iii / STALE_SYNCED_CEILING_NS / demotion code-test mismatch) — clean;
B2#1/A2#2 demotion single forwarding-keyed branch — clean; B2#2 ==0 rg_epochs[0]
node-level epoch — clean (index 0 free); epoch-before-store feasible; base
325d10683 correct; recommendation honest; idle-window gate correctly mandatory.

Findings folded:
1. [BLOCKER→MOOT] first_held_ns clear-list "or self-heal" — already corrected
   in committed plan (272d4fc74). [RESOLVED]
2. [MAJOR] promotion (refresh_for_ha_transition) MUST clear first_held_ns so a
   promoted-then-re-demoted flow isn't reaped under a stale clock — already in
   §6.4 write-site contract; add the unit test. [FOLDED]
3. [MINOR] de-dup the epoch bump out of handle_activated_rgs when hoisting before
   the store (avoid double-increment). [FOLDED as impl note]
4. [MINOR] ABS_CAP floor: must be ≥ largest legitimate standby idle window
   (~7 days, not 24 h) vs a 30-day inactivity-timeout. [FOLDED]
5. [MINOR] add an aged_owner_rg_zero_active_node counter so the active/active ==0
   residual is observable. [FOLDED]
