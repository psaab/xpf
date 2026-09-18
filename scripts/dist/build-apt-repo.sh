#!/bin/sh
# xpf signed apt repository builder (#1924 §5.3).
#
# Default: a FLAT signed repo (apt-ftparchive + gpg) — stateless-CI-safe
# (no reprepro Berkeley DB to carry between runs). Opt into reprepro with
# XPF_APT_TOOL=reprepro for a persistent publisher.
#
# Produces a standard dists/+pool/ tree under <out>/apt, ready to publish to
# XPF_APT_BASE_URL (a directory-serving host — NOT GitHub Releases flat
# assets). The on-disk layout is identical for both tools so install.sh's
# deb822 source is unaffected by the choice.
#
# Usage:
#   build-apt-repo.sh [--out DIR] [--suite stable|edge] [--debs GLOB...]
#
# Env / config inputs (the operator decisions, OQ-2 / §5.6):
#   XPF_GPG_KEY        OpenPGP key id/fingerprint that signs Release.
#                      Unset -> repo is built UNSIGNED (dev only; loud warning;
#                      publish.py refuses an unsigned InRelease).
#   XPF_APT_TOOL       flat (default) | reprepro
#   XPF_APT_SUITE      stable (default) | edge          (overridden by --suite)
#   XPF_APT_COMPONENT  main (default)
#   XPF_APT_ARCH       amd64 (default)
#   XPF_APT_VALID_DAYS Valid-Until horizon in days (default 365 — long, for a
#                      manual/air-gap signing cadence; a short window REQUIRES
#                      an automated re-sign job, §5.6 NIT-1).
#   XPF_APT_ORIGIN     Origin/Label/Suite text (default "xpf").
set -eu

# shellcheck disable=SC1007  # `CDPATH= cd` clears CDPATH for this command only
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
OUT="$ROOT/dist"
SUITE="${XPF_APT_SUITE:-stable}"
COMPONENT="${XPF_APT_COMPONENT:-main}"
ARCH="${XPF_APT_ARCH:-amd64}"
TOOL="${XPF_APT_TOOL:-flat}"
VALID_DAYS="${XPF_APT_VALID_DAYS:-365}"
ORIGIN="${XPF_APT_ORIGIN:-xpf}"
DEBS=""

die() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "==> $*"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="$2"; shift 2 ;;
        --suite) SUITE="$2"; shift 2 ;;
        --debs) shift; while [ $# -gt 0 ] && [ "${1#--}" = "$1" ]; do DEBS="$DEBS $1"; shift; done ;;
        -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
        *) die "unknown arg: $1" ;;
    esac
done

case "$SUITE" in stable|edge) ;; *) die "suite must be stable|edge (got $SUITE)";; esac
# F-066/#9921: COMPONENT/ARCH/ORIGIN are interpolated into repo WRITE paths
# (POOL/DISTDIR below) and signed metadata (apt-ftparchive -o values, reprepro
# distributions). SUITE alone was allowlisted. Validate the rest with the same
# fail-closed discipline BEFORE any write: COMPONENT/ARCH admit no `/` (no
# traversal out of --out) and no newline (no Release-field injection); ORIGIN
# is single-line printable (it lands in single-line field values verbatim —
# quotes/semicolons included — so only a line break could inject a field).
case "$COMPONENT" in ""|*/*|*[!A-Za-z0-9._+-]*|[!A-Za-z0-9]*)
    die "component must match [A-Za-z0-9][A-Za-z0-9._+-]* (got '$COMPONENT')" ;;
esac
case "$ARCH" in ""|*/*|*[!A-Za-z0-9._+-]*|[!A-Za-z0-9]*)
    die "arch must match [A-Za-z0-9][A-Za-z0-9._+-]* (got '$ARCH')" ;;
esac
case "${LC_ALL+set}" in set) _lc_had=1; _lc_saved=$LC_ALL;; *) _lc_had=0;; esac
LC_ALL=C
case "$ORIGIN" in ""|*[![:print:]]*)
    die "origin must be non-empty single-line printable text (got '$ORIGIN')" ;;
esac
if [ "$_lc_had" = "1" ]; then LC_ALL=$_lc_saved; else unset LC_ALL; fi
# F-066c/#9921 (parent review): VALID_DAYS and XPF_GPG_KEY interpolate into
# the reprepro distributions file (ValidFor/SignWith) and the flat Release
# knob (ValidTime). A newline-bearing VALID_DAYS injects a config line, so
# VALID_DAYS is digits-only (1-5 digits; 0 is allowed and fails closed
# downstream as an immediately-stale horizon). XPF_GPG_KEY flows into argv
# (flat gpg --local-user: immune) and a line-based file, so only a newline
# could inject there — reject newlines alone so key IDs, fingerprints, and
# space/unicode UID strings keep working.
case "$VALID_DAYS" in ""|*[!0-9]*|??????*)
    die "valid-days must be 1-5 digits (got '$VALID_DAYS')" ;;
esac
case "${XPF_GPG_KEY-}" in
    *'
'*) die "gpg key id must be single-line" ;;
esac

# Default deb set: the freshly built binary + appliance packages.
if [ -z "$DEBS" ]; then
    DEBS=$(ls "$ROOT"/dist-deb/xpf_*.deb "$ROOT"/dist-deb/xpf-appliance_*.deb 2>/dev/null || true)
    [ -n "$DEBS" ] || die "no debs in dist-deb (run 'make deb' first, or pass --debs)"
fi

APT="$OUT/apt"
# Pool is keyed PER SUITE (#4201): a shared pool/<component> made each suite's
# Packages scan the WHOLE component pool, so a stable rebuild after an edge
# build listed the edge version in stable (validly signed) and a stable
# subscriber could pull an edge build. Isolate the pool under the suite so each
# suite's apt-ftparchive scan sees ONLY its own debs. The reprepro path (below)
# isolates suites in its own database and does not use $POOL.
POOL="$APT/pool/$SUITE/$COMPONENT/x/xpf"
DISTDIR="$APT/dists/$SUITE/$COMPONENT/binary-$ARCH"
mkdir -p "$POOL" "$DISTDIR"
# F-066b/#9921 (parent review): lexical validation cannot see a PRE-PLANTED
# symlink: $OUT/apt/dists/stable/<escape> -> /external makes a lexically
# VALID COMPONENT=escape resolve outside --out, and mkdir -p happily creates
# binary-$ARCH through it. Resolve both COMPONENT-derived sinks and verify
# containment within the resolved --out; die loudly on escape. (Static
# subpaths like conf/ are the operator's exclusive-dir responsibility; only
# validated-input-derived sinks are pinned here. A planter racing mkdir
# itself is narrowed to microseconds by this ordering, not closed — shell
# cannot mkdir with O_NOFOLLOW.)
_out_resolved=$(cd "$OUT" && pwd -P) || die "cannot resolve --out $OUT"
for _d in "$POOL" "$DISTDIR"; do
    _r=$(cd "$_d" 2>/dev/null && pwd -P) || _r=""
    case "${_r:-MISSING}" in
        "$_out_resolved"|"$_out_resolved"/*) : ;;
        *) die "repo path escapes --out ($_d resolves outside $OUT) — refusing to write" ;;
    esac
done
unset _d _r _out_resolved

info "apt repo tool: $TOOL, suite: $SUITE, arch: $ARCH, out: $APT"

# NOTE(F-066/#9921): the COMPONENT/ARCH/ORIGIN/VALID_DAYS/GPG_KEY gate above
# also covers this path's distributions file (allowlisted/digit/single-line
# values cannot inject fields). Reprepro synthesizes its Release from its own
# database plus the ValidFor knob, so verify the emitted file after the final
# includedeb/export rather than comparing against this process's NOW. This
# Date-derived exact epoch is the legitimate reprepro delta from the flat
# path: reprepro chooses Date during export, minutes before this check, while
# the flat path pins Date before apt-ftparchive runs. Requiring one Date as
# well as one Valid-Until makes that derivation unambiguous.
if [ "$TOOL" = "reprepro" ]; then
    command -v reprepro >/dev/null 2>&1 || die "reprepro not found (apt-get install reprepro)"
    [ -n "${XPF_GPG_KEY:-}" ] || die "reprepro path requires XPF_GPG_KEY (signs Release)"
    CONF="$APT/conf"
    mkdir -p "$CONF"
    cat > "$CONF/distributions" <<EOF
Origin: $ORIGIN
Label: $ORIGIN
Suite: $SUITE
Codename: $SUITE
Architectures: $ARCH
Components: $COMPONENT
Description: xpf firewall appliance ($SUITE channel)
SignWith: $XPF_GPG_KEY
ValidFor: ${VALID_DAYS}d
EOF
    for d in $DEBS; do
        info "reprepro includedeb $SUITE $d"
        reprepro -b "$APT" includedeb "$SUITE" "$d"
    done

    REL="$APT/dists/$SUITE/Release"
    [ -f "$REL" ] || die "reprepro emitted no Release at $REL"
    _date_count=$(grep -c "^Date:" "$REL" 2>/dev/null || true)
    [ "$_date_count" = "1" ] || die "reprepro Release has $_date_count Date fields, want exactly 1"
    _vu_count=$(grep -c "^Valid-Until:" "$REL" 2>/dev/null || true)
    [ "$_vu_count" = "1" ] || die "reprepro Release has $_vu_count Valid-Until fields, want exactly 1"
    _date_line=$(grep "^Date:" "$REL")
    _date_epoch=$(LC_ALL=C date -u -d "${_date_line#Date: }" +%s 2>/dev/null) \
        || die "cannot parse reprepro Release Date '$_date_line' (need GNU date)"
    _vu_line=$(grep "^Valid-Until:" "$REL")
    _vu_epoch=$(LC_ALL=C date -u -d "${_vu_line#Valid-Until: }" +%s 2>/dev/null) \
        || die "cannot parse reprepro Release Valid-Until '$_vu_line' (need GNU date)"
    VALID_SECONDS=$((VALID_DAYS * 86400))
    [ "$_vu_epoch" = "$((_date_epoch + VALID_SECONDS))" ] || die \
        "reprepro Release Valid-Until '$_vu_line' != ValidFor-derived value \
(want epoch $((_date_epoch + VALID_SECONDS)), got $_vu_epoch)"
    info "reprepro Release validated ($_date_line; $_vu_line)"
    info "reprepro repo built at $APT"
    exit 0
fi

# ── flat signed repo (default) ───────────────────────────────────────────
command -v apt-ftparchive >/dev/null 2>&1 || die "apt-ftparchive not found (apt-get install apt-utils)"

# Clear stale signed metadata BEFORE rebuilding (Codex-H2): an unsigned
# rebuild that left yesterday's signed InRelease/Release.gpg behind would let
# the publish gate green-light a tampered/unsigned pool against the old
# signature. Always start from a clean Release set for this suite.
rm -f "$APT/dists/$SUITE/Release" "$APT/dists/$SUITE/Release.gpg" \
      "$APT/dists/$SUITE/InRelease"

# DEBS holds paths this script controls (built debs / explicit --debs). Guard
# the word-split loop against pathname globbing with `set -f` (A5); paths must
# not contain whitespace (asserted below).
set -f
for d in $DEBS; do
    set +f
    case "$d" in *[!-./_A-Za-z0-9]*) die "deb path contains an unsupported char: $d";; esac
    cp -f "$d" "$POOL/"
    info "pooled $(basename "$d")"
    set -f
done
set +f

# Packages index (paths in the index are relative to the repo root $APT).
# Scan ONLY this suite's pool (#4201) so a stable rebuild never indexes an edge
# deb sitting in a sibling suite's pool; the emitted Filename: fields then point
# at pool/$SUITE/$COMPONENT/... which apt clients fetch relative to the base URL.
( cd "$APT" && apt-ftparchive packages "pool/$SUITE/$COMPONENT" > "dists/$SUITE/$COMPONENT/binary-$ARCH/Packages" )
gzip -9 -kf "$DISTDIR/Packages"
info "wrote Packages ($(wc -l < "$DISTDIR/Packages") lines) + Packages.gz"

# Release over the suite tree. apt-ftparchive computes the per-index
# checksums; ValidTime (SECONDS, not a date) makes apt-ftparchive emit the
# Valid-Until field (Codex-M3 — APT::FTPArchive::Release::ValidUntil does NOT
# exist; the knob is ValidTime).
NOW=$(date -u +%s)
VALID_SECONDS=$((VALID_DAYS * 86400))
NOWSTR=$(date -u -d "@$NOW" +"%a, %d %b %Y %H:%M:%S UTC" 2>/dev/null \
        || date -u -r "$NOW" +"%a, %d %b %Y %H:%M:%S UTC")
( cd "$APT" && apt-ftparchive \
    -o "APT::FTPArchive::Release::Origin=$ORIGIN" \
    -o "APT::FTPArchive::Release::Label=$ORIGIN" \
    -o "APT::FTPArchive::Release::Suite=$SUITE" \
    -o "APT::FTPArchive::Release::Codename=$SUITE" \
    -o "APT::FTPArchive::Release::Architectures=$ARCH" \
    -o "APT::FTPArchive::Release::Components=$COMPONENT" \
    -o "APT::FTPArchive::Release::Date=$NOWSTR" \
    -o "APT::FTPArchive::Release::ValidTime=$VALID_SECONDS" \
    release "dists/$SUITE" > "dists/$SUITE/Release" )
# Assert the freshness field actually landed EXACTLY ONCE with the exact
# ValidTime-derived value (F-066/#9921). A silent apt-ftparchive knob rename
# must FAIL the build, never ship a repo without Valid-Until — and an injected
# duplicate (e.g. via a newline-bearing Origin, now rejected above) must fail
# it too. apt computes Valid-Until as Date + ValidTime, both second-precision
# and both fixed above, so the epoch comparison is exact (no tolerance); the
# epoch form also tolerates apt's +0000-vs-UTC suffix normalization.
_vu_count=$(grep -c "^Valid-Until:" "$APT/dists/$SUITE/Release" 2>/dev/null || true)
[ "$_vu_count" = "1" ] || die "Release has $_vu_count Valid-Until fields, want exactly 1 \
(a duplicate means field injection — refusing to sign/publish)"
_vu_line=$(grep "^Valid-Until:" "$APT/dists/$SUITE/Release")
_vu_epoch=$(LC_ALL=C date -u -d "${_vu_line#Valid-Until: }" +%s 2>/dev/null) \
    || die "cannot parse Release Valid-Until '$_vu_line' (need GNU date)"
[ "$_vu_epoch" = "$((NOW + VALID_SECONDS))" ] || die "Release Valid-Until '$_vu_line' != \
ValidTime-derived value (want epoch $((NOW + VALID_SECONDS)), got $_vu_epoch)"
info "wrote Release ($_vu_line)"

# Sign Release -> InRelease (inline) + Release.gpg (detached).
if [ -n "${XPF_GPG_KEY:-}" ]; then
    REL="$APT/dists/$SUITE/Release"
    gpg --batch --yes --local-user "$XPF_GPG_KEY" --clearsign \
        -o "$APT/dists/$SUITE/InRelease" "$REL"
    gpg --batch --yes --local-user "$XPF_GPG_KEY" -abs \
        -o "$APT/dists/$SUITE/Release.gpg" "$REL"
    info "signed: InRelease + Release.gpg (key $XPF_GPG_KEY)"
else
    echo "WARNING: XPF_GPG_KEY unset — Release is UNSIGNED. Dev only; this repo "
    echo "         is NOT publishable (publish.py refuses an unsigned InRelease)." >&2
fi

info "flat signed apt repo built at $APT"
info "publish dists/+pool/ to XPF_APT_BASE_URL (a directory-serving host)"
