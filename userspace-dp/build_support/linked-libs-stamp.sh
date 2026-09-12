#!/bin/sh
# #9726: print XPF_LINKED_LIBS_STAMP, the first 32 hex digits of the sha256 of
# the libxdp.a, libxdp.pc and libbpf.pc that build.rs resolves through
# pkg-config, or through the command PKG_CONFIG names. The Makefile's helper
# recipes pass it to cargo, and build.rs re-runs when it changes, so a library
# replaced in place re-records the linked versions even when its mtime went
# backwards.
#
# Every failure exits non-zero with a message on stderr, which fails the recipe
# line. A stamp over input that could not be read would hash nothing, never
# change, and so never re-run build.rs.
set -eu

pc=${PKG_CONFIG:-pkg-config}
version=

# Every failure names the libxdp version when it is known, because this script runs
# BEFORE cargo: without it, a host whose libxdp is outside build.rs's range and whose
# package ships no libxdp.a fails here with "not a readable file" and never names the
# version that explains it.
fail() {
    if [ -n "$version" ]; then
        echo "linked-libs-stamp.sh (#9726): $* (pkg-config reports libxdp $version)" >&2
    else
        echo "linked-libs-stamp.sh (#9726): $*" >&2
    fi
    exit 1
}

# The version FIRST, before any file probe, for the message above. The range decision
# stays in build.rs (libversions::check_libxdp_version): one place decides it.
version=$("$pc" --modversion libxdp) ||
    fail "'$pc --modversion libxdp' failed"
[ -n "$version" ] || fail "'$pc' reports an empty version for libxdp"

xdp_libdir=$("$pc" --variable=libdir libxdp) ||
    fail "'$pc --variable=libdir libxdp' failed"
xdp_pcdir=$("$pc" --variable=pcfiledir libxdp) ||
    fail "'$pc --variable=pcfiledir libxdp' failed"
bpf_pcdir=$("$pc" --variable=pcfiledir libbpf) ||
    fail "'$pc --variable=pcfiledir libbpf' failed"
[ -n "$xdp_libdir" ] || fail "'$pc' reports an empty libdir for libxdp"
[ -n "$xdp_pcdir" ] || fail "'$pc' reports an empty pcfiledir for libxdp"
[ -n "$bpf_pcdir" ] || fail "'$pc' reports an empty pcfiledir for libbpf"

xdp_archive=$xdp_libdir/libxdp.a
xdp_pc=$xdp_pcdir/libxdp.pc
bpf_pc=$bpf_pcdir/libbpf.pc
for file in "$xdp_archive" "$xdp_pc" "$bpf_pc"; do
    if [ ! -f "$file" ] || [ ! -r "$file" ]; then
        fail "$file is not a readable file"
    fi
done

# Hash each file separately and then hash that manifest, rather than piping their
# contents into one sha256sum: dash has no pipefail, so in the pipeline only
# sha256sum's status survived, and a `cat` that failed part way through — a file
# replaced under us, a read error — produced a perfectly well-formed digest over
# partial input. sha256sum with several operands fails if ANY of them cannot be read,
# and the readability check above is kept for its better message, not as the guard.
manifest=$(sha256sum -- "$xdp_archive" "$xdp_pc" "$bpf_pc") ||
    fail "sha256sum could not read every file"
sum=$(printf '%s\n' "$manifest" | sha256sum) ||
    fail "sha256sum failed"
stamp=$(printf '%.32s' "$sum")
case $stamp in
*[!0-9a-f]*) fail "sha256sum printed no digest: $sum" ;;
esac
[ "${#stamp}" -eq 32 ] || fail "sha256sum printed no digest: $sum"
printf '%s\n' "$stamp"
