# Reviewer task IDs — #1445

PLAN-KILLED at study time (2026-05-26 21:41 UTC).
No Codex / Gemini / AGY / Copilot reviewers were dispatched.

Reason: the call sites cited in the issue
(`pkg/config/compiler_security.go:760-782`,
`pkg/cli/cli_request.go:1019-1044`,
`pkg/dataplane/userspace/snapshot.go:2396-2411`) all point past the
end of the respective files at `origin/master @ cd048d2f`, and the
named functions (`validatePrivateKey`, `handleRequestSecurityWireGuard`,
`deriveWgPublicKey`) do not exist anywhere in the Go tree. There is no
duplicated WireGuard / X25519 logic to consolidate.

See `plan.md` for the full kill rationale.
