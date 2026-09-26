#!/usr/bin/env bash
# Builds the retained Rust AF_XDP shim object and — only after the
# kernel BPF verifier accepts the candidate — installs it over the
# git-tracked pkg/dataplane/userspace_xdp_bpfel.o.
#
# #1864 hardening (2026-06-10 incident: an unpinned `nightly` rebuild
# produced an object that blew the verifier's 1M processed-insn cap
# and took both HA cluster dataplanes down):
#   - The Rust toolchain is PINNED via userspace-xdp/rust-toolchain.toml
#     (single source of truth; parsed below). Override with
#     RUST_BPF_TOOLCHAIN=... for bisects, but unpinned builds refuse to
#     install unless XPF_SHIM_ALLOW_UNPINNED_INSTALL=1 is also set.
#   - bpf-linker is version-pinned (it embeds its own LLVM and is as
#     much a codegen input as rustc).
#   - VERIFY-THEN-INSTALL: the candidate is loaded through the real
#     kernel verifier (cmd/shimverify, anonymous maps, no pins, no
#     attach) BEFORE the tracked .o is touched. No verified PASS ⇒ no
#     install, exit nonzero. There is no unverified-install path.
#
# Recovery if a bad object ever lands anyway:
#   git checkout -- pkg/dataplane/userspace_xdp_bpfel.o && make build
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CRATE_DIR="${REPO_ROOT}/userspace-xdp"
OUT_FILE="${SCRIPT_DIR}/userspace_xdp_bpfel.o"
CANDIDATE="${CRATE_DIR}/target/bpfel-unknown-none/release/libxpf_userspace_xdp.so"
CARGO_BIN="${CARGO:-${HOME}/.cargo/bin/cargo}"
RUSTUP_BIN="${RUSTUP:-${HOME}/.cargo/bin/rustup}"
GO_BIN="${GO:-go}"

# bpf-linker pin. Bump together with the rust-toolchain.toml pin, and
# only after the verifier gate below passes with the new pair.
PINNED_BPF_LINKER_VERSION="0.10.2"

fail() {
	echo "build-userspace-xdp.sh: $*" >&2
	exit 1
}

# --- Toolchain pin (single source of truth: rust-toolchain.toml) ---
TOOLCHAIN_TOML="${CRATE_DIR}/rust-toolchain.toml"
[[ -f "${TOOLCHAIN_TOML}" ]] || fail "missing ${TOOLCHAIN_TOML} (toolchain pin SSOT)"
# Tolerant of quote style, spacing, and trailing comments; scoped to
# the [toolchain] table; requires EXACTLY ONE channel key; strict
# format check afterwards. A garbled, missing, duplicated, or
# wrong-table parse fails loudly and can never fall back to an
# unpinned toolchain.
CHANNEL_LINES="$(awk '
	/^[[:space:]]*\[/ { in_tc = ($0 ~ /^[[:space:]]*\[toolchain\][[:space:]]*$/) }
	in_tc && /^[[:space:]]*channel[[:space:]]*=/ {
		v=$0; sub(/^[^=]*=/, "", v); sub(/#.*/, "", v)
		gsub(/[[:space:]"'"'"']/, "", v); print v
	}' "${TOOLCHAIN_TOML}")"
[[ "$(wc -l <<<"${CHANNEL_LINES}")" -eq 1 && -n "${CHANNEL_LINES}" ]] || \
	fail "expected exactly one 'channel' key in the [toolchain] table of ${TOOLCHAIN_TOML}; got: '${CHANNEL_LINES}'"
PINNED_TOOLCHAIN="${CHANNEL_LINES}"
[[ "${PINNED_TOOLCHAIN}" =~ ^nightly-[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || \
	fail "could not parse a nightly-YYYY-MM-DD channel pin from ${TOOLCHAIN_TOML} (got '${PINNED_TOOLCHAIN}')"

TOOLCHAIN="${RUST_BPF_TOOLCHAIN:-${PINNED_TOOLCHAIN}}"
UNPINNED=0
if [[ "${TOOLCHAIN}" != "${PINNED_TOOLCHAIN}" ]]; then
	UNPINNED=1
	echo "build-userspace-xdp.sh: WARNING: building with UNPINNED toolchain '${TOOLCHAIN}' (pin is '${PINNED_TOOLCHAIN}')" >&2
fi

[[ -x "${CARGO_BIN}" ]] || fail "cargo not found at ${CARGO_BIN}"

if ! "${CARGO_BIN}" "+${TOOLCHAIN}" --version >/dev/null 2>&1; then
	fail "Rust toolchain '${TOOLCHAIN}' is not installed.
  Install the pinned BPF toolchain with:
    rustup toolchain install ${PINNED_TOOLCHAIN} --profile minimal --component rust-src"
fi
if [[ -x "${RUSTUP_BIN}" ]]; then
	"${RUSTUP_BIN}" component add rust-src --toolchain "${TOOLCHAIN}-x86_64-unknown-linux-gnu" >/dev/null 2>&1 || \
	"${RUSTUP_BIN}" component add rust-src --toolchain "${TOOLCHAIN}" >/dev/null 2>&1 || true
fi

# --- bpf-linker pin: check the exact binary cargo will execute. ---
# .cargo/config.toml sets `linker = "bpf-linker"` (PATH-resolved);
# prepend ~/.cargo/bin deterministically so the script and cargo agree
# on which binary that is.
export PATH="${HOME}/.cargo/bin:${PATH}"
BPF_LINKER_BIN="$(command -v bpf-linker || true)"
[[ -n "${BPF_LINKER_BIN}" ]] || fail "bpf-linker not found on PATH.
  Install the pinned linker with:
    cargo install bpf-linker --version ${PINNED_BPF_LINKER_VERSION} --locked"
BPF_LINKER_VERSION="$("${BPF_LINKER_BIN}" --version 2>/dev/null | awk '{print $2; exit}')"
if [[ "${BPF_LINKER_VERSION}" != "${PINNED_BPF_LINKER_VERSION}" ]]; then
	fail "bpf-linker version drift: ${BPF_LINKER_BIN} is '${BPF_LINKER_VERSION}', pin is '${PINNED_BPF_LINKER_VERSION}'.
  Install the pinned linker with:
    cargo install bpf-linker --version ${PINNED_BPF_LINKER_VERSION} --locked --force"
fi

# Thread MAX_INTERFACES from the C header into the Rust build so
# BINDING_ARRAY_MAX_ENTRIES (and userspace_ingress_ifaces max_entries)
# stay locked to the same value as tx_ports' MAX_INTERFACES. Drift
# between these constants is the exact failure mode #814 is fixing.
MAX_INTERFACES="$(awk '/^#define MAX_INTERFACES /{print $3; exit}' "${REPO_ROOT}/bpf/headers/xpf_common.h")"
[[ -n "${MAX_INTERFACES}" ]] || fail "failed to parse MAX_INTERFACES from ${REPO_ROOT}/bpf/headers/xpf_common.h"
export MAX_INTERFACES

(
	cd "${CRATE_DIR}"
	"${CARGO_BIN}" "+${TOOLCHAIN}" build --release
)
[[ -f "${CANDIDATE}" ]] || fail "cargo build did not produce ${CANDIDATE}"

# --- VERIFY-THEN-INSTALL: the kernel verifier gates the install. ---
# Static checks cannot substitute: the 2026-06-10 incident objects
# differed by 7 static insns; the blowup was the verifier state walk.
SHIMVERIFY="$(mktemp -t shimverify.XXXXXX)"
SHIMVERIFY_ATTESTATION=""
cleanup() {
	rm -f "${SHIMVERIFY}"
	if [[ -z "${SHIMVERIFY_ATTESTATION}" ]]; then
		return
	fi
	if [[ "$(id -u)" -eq 0 ]]; then
		rm -f "${SHIMVERIFY_ATTESTATION}"
	else
		sudo -n rm -f "${SHIMVERIFY_ATTESTATION}" 2>/dev/null || true
	fi
}
trap cleanup EXIT
(
	cd "${REPO_ROOT}"
	"${GO_BIN}" build -o "${SHIMVERIFY}" ./cmd/shimverify
) || fail "failed to build cmd/shimverify"

run_verifier() {
	# XPF_SHIM_ALLOW_LOW_HEADROOM (#4555) must survive the sudo hop —
	# sudo scrubs the environment, so pass it explicitly via `env` or the
	# documented override silently does nothing.
	local allow_low="${XPF_SHIM_ALLOW_LOW_HEADROOM:-0}"
	if [[ "$(id -u)" -eq 0 ]]; then
		SHIMVERIFY_ATTESTATION="$(mktemp -t shimverify-attestation.XXXXXX)" || return 1
		XPF_SHIM_ALLOW_LOW_HEADROOM="${allow_low}" "${SHIMVERIFY}" "${CANDIDATE}" --gate-verdict "${SHIMVERIFY_ATTESTATION}"
	elif sudo -n true 2>/dev/null; then
		SHIMVERIFY_ATTESTATION="$(sudo -n mktemp -t shimverify-attestation.XXXXXX)" || return 99
		sudo -n chmod 0644 "${SHIMVERIFY_ATTESTATION}" || return 99
		sudo -n env "XPF_SHIM_ALLOW_LOW_HEADROOM=${allow_low}" "${SHIMVERIFY}" "${CANDIDATE}" --gate-verdict "${SHIMVERIFY_ATTESTATION}"
	else
		return 99
	fi
}

set +e
run_verifier
VERIFY_RC=$?
set -e
# #4555/#6923: how the install line below describes the gate. Only rc=0 is a
# measured PASS; rc=6 installed because the operator suppressed the floor, and
# saying "PASS" for it prints the one word an operator greps for to confirm the
# gate was satisfied. The warning on stderr is not enough: stdout and stderr are
# routinely read apart (CI log panes, `2>/dev/null`), so the verdict has to be
# correct in the line that carries it.
VERIFY_VERDICT="verifier PASS"
case "${VERIFY_RC}" in
0) ;;
6)
	VERIFY_VERDICT="verifier headroom gate OVERRIDDEN (XPF_SHIM_ALLOW_LOW_HEADROOM=1), NOT a measured pass"
	# #4555: the headroom gate was OVERRIDDEN. Install (the operator asked
	# for it) but never silently: a distinct code exists so this is
	# distinguishable from a measured PASS without reading stderr.
	echo "build-userspace-xdp.sh: WARNING: installing ${OUT_FILE} with the #4555 headroom gate
  OVERRIDDEN via XPF_SHIM_ALLOW_LOW_HEADROOM=1. See the shimverify banner above for which
  condition was suppressed. This object ships without a satisfied headroom check." >&2 ;;
99)
	fail "cannot run the BPF verifier gate (need root or passwordless sudo).
  The candidate object was built at:
    ${CANDIDATE}
  The tracked ${OUT_FILE} was NOT updated. Re-run this script with sudo
  available, or verify+install manually (verification is REQUIRED — do
  not skip the first command):
    ${GO_BIN} -C ${REPO_ROOT} build -o /tmp/xpf-shimverify ./cmd/shimverify
    sudo /tmp/xpf-shimverify ${CANDIDATE} && install -m 0644 ${CANDIDATE} ${OUT_FILE}" ;;
3)
	fail "kernel verifier REJECTED the candidate object — the tracked ${OUT_FILE} was NOT updated.
  This is the #1864 failure mode (toolchain codegen drift). Do not commit or deploy.
  Pinned toolchain: ${PINNED_TOOLCHAIN}; this build used: ${TOOLCHAIN}." ;;
4)
	fail "the candidate LOADS but is below the #4555 verifier-headroom floor — the tracked
  ${OUT_FILE} was NOT updated. See the shimverify message above for the measured
  numbers. This is the early-warning tripwire, not a kernel rejection: the shim
  previously reached 0.92% headroom with every gate green, and the next edit to its
  parsing paths then hit the 1M processed-insn wall. Reduce verifier cost, or re-run
  with XPF_SHIM_ALLOW_LOW_HEADROOM=1 to install anyway with the risk understood." ;;
5)
	fail "the candidate LOADS but its verifier headroom could NOT be measured — the tracked
  ${OUT_FILE} was NOT updated. This kernel's verifier log carried no
  'processed N insns (limit M)' line, so the #4555 floor could not be applied and how
  close this object sits to the 1M wall is UNKNOWN. Unmeasurable is refused on purpose:
  a gate that switches itself off when the log format changes is exactly how the shim
  crept to 0.92% headroom unnoticed in the first place. If this kernel genuinely reports
  differently, re-run with XPF_SHIM_ALLOW_LOW_HEADROOM=1 — an explicit acknowledgement
  that the object shipped unmeasured." ;;
*)
	fail "shimverify failed (rc=${VERIFY_RC}) — the tracked ${OUT_FILE} was NOT updated." ;;
esac

if [[ "${UNPINNED}" -eq 1 && "${XPF_SHIM_ALLOW_UNPINNED_INSTALL:-0}" != "1" ]]; then
	fail "refusing to install an object built with unpinned toolchain '${TOOLCHAIN}' (pin: '${PINNED_TOOLCHAIN}').
  The verified candidate remains at ${CANDIDATE}.
  Set XPF_SHIM_ALLOW_UNPINNED_INSTALL=1 to install anyway (do NOT commit such an object:
  the PR reproducibility gate regenerates with the pin and requires a clean git diff)."
fi

# Install the verifier's attestation beside the candidate object. Its hash
# binds the verdict to the object bytes installed immediately after it.
install -m 0644 "${CANDIDATE}" "${OUT_FILE}"
install -m 0644 "${SHIMVERIFY_ATTESTATION}" "${SCRIPT_DIR}/userspace_xdp_gate_verdict.json"
echo "build-userspace-xdp.sh: ${VERIFY_VERDICT} — installed ${OUT_FILE} (toolchain ${TOOLCHAIN}, bpf-linker ${BPF_LINKER_VERSION})"

# --- Refresh the source→object freshness manifest (#4977). ---
# `make build` never runs `make generate`, and `make test` never
# rebuilds the shim, so a logic-only edit to userspace-xdp/** that is
# not regenerated would ship this now-stale object silently. Immediately
# after the verified install (so it stays in LOCKSTEP with the object it
# describes), re-hash every freshness-relevant build input plus the
# tracked object into pkg/dataplane/userspace_xdp_manifest.json;
# TestUserspaceXDPShimObjectMatchesSourceManifest fails when the working
# tree drifts from this manifest, directing the operator back to
# `make generate`.
(
	cd "${REPO_ROOT}"
	"${GO_BIN}" run ./cmd/shim-manifest -repo-root .
) || fail "failed to refresh the shim freshness manifest (cmd/shim-manifest)"
echo "build-userspace-xdp.sh: refreshed pkg/dataplane/userspace_xdp_manifest.json (#4977)"
