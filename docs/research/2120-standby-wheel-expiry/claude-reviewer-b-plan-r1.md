# Hostile Claude plan-reviewer B — r1 — #2120

VERDICT: PLAN-READY-WITH-NITS (concurs Option B is correct, contingent on
fixing findings 1 & 2)

Source-verified the root-cause chain and confirmed B is the architecturally
correct fix (restores the daemon_run.go:745-748 documented IsLocalPrimary
contract, no hot-path/steady-state cost). Findings:

1. [MAJOR] Leak-mitigation is factually wrong: warm reconnect does NOT
   bulk-sync (coldStart-only, sync_conn.go:197-209; reconcileStaleSessions
   guarded by bulkInProgress, sync.go:601-604). Only backstop is the bounded
   + lossy deleteJournal (sync_conn.go:541-543, DeletesDropped). So a lost
   Close delta + evicted journal entry → INDEFINITE hold under B. Make the
   stale-synced ceiling NON-optional. Acknowledge A's edge: A ages everything,
   so a lost delete self-heals at timeout.
2. [MAJOR] "Re-bucket self-heals a skipped RefreshOwnerRGS" is false:
   re-bucket (expire.rs:175-198) does not touch last_seen; only
   refresh_for_ha_transition (mod.rs:601) / upsert_synced (install.rs:234)
   re-stamp. Store-before-enqueue gap (ha.rs:39 vs :114) lets a worker observe
   active-HA-but-no-refresh-command and run its 1/s expire in that gap → removes
   the stale-last_seen session. Drop the false claim; close via self-heal or
   coordinator-ordering.
3. [MINOR] #270 did NOT reinstate the fast-path; 62e3a9026 ("adaptive sync
   sweep interval") added it, 0dc166c7b relocated it. b35bb45 removed only the
   older single-NEW-counter fast-path.
4. [MINOR] Focus-#4 lease-race is a NON-issue: lease set atomically with active
   at promotion (runtime.rs:222-234; ha.rs:12-24,39); no lease-gap drop window.
   Only the command-apply gap (finding 2) exists. State this to stop a reviewer
   chasing it.
5. [MINOR] Standalone gate: confirm clustered-pre-first-update (empty ha_state +
   owner_rg_id>0) over-retain window is acceptable; standalone sessions have
   owner_rg_id==0 (the real gate).
6. [NIT] Cost comparison honest / understates A: A re-installs the entire
   active-flow table on the peer CONTROL SOCKET every second
   (PutClusterSyncedV4→SetClusterSyncedSessionV4) — the >1/s contention class
   CLAUDE.md warns about. Name it in the B recommendation.
7. [NIT] Short-timeout substitution is valid (session_timeout_ns resolves synced
   TCP to config-driven tcp_established_ns; identical code path). Test must verify
   origin.is_peer_synced + owner_rg_id>0 + standby RG inactive, and assert the
   held counter.

A-vs-B: concurs B (contingent on 1&2). If reviewers reject unbounded-hold,
ship B + non-optional ceiling, NOT a fallback to A.
