"""Shell assertion for the versioned first-install runtime layout (#10771)."""

from __future__ import annotations


_BINS = "xpfd cli xpf-userspace-dp xpf-day0-config"


def seeded_runtime_layout_snippet(*, test_root: bool = False) -> str:
    """Return the image/guest check that all managed sbin links use versions/current.

    The opt-in root seam is used only by hermetic tests; production callers
    always inspect the real target or guest root.
    """
    prefix = (
        "root=${XPF_SEED_LAYOUT_ROOT:-}\n"
        if test_root else "root=\n"
    )
    return (
        "set -eu\n"
        + prefix
        + f'versions="${{root}}/var/lib/xpf/versions"\n'
        + f'current="$versions/current"\n'
        + f'sbin="${{root}}/usr/local/sbin"\n'
        + 'fatal() { echo "FATAL: #10771 seeded runtime layout: $*" >&2; exit 1; }\n'
        + '[ -L "$current" ] || fatal "versions/current is not a symlink"\n'
        + 'version_dir=$(readlink -f "$current") || fatal "cannot resolve versions/current"\n'
        + 'case "$version_dir" in "$versions"/*) ;; *) fatal "current resolves outside versions/: $version_dir" ;; esac\n'
        + 'version=${version_dir#"$versions"/}\n'
        + 'case "$version" in ""|*/*) fatal "current does not name one version directory: $version_dir" ;; esac\n'
        + f'for b in {_BINS}; do\n'
        + '    link="$sbin/$b"\n'
        + '    [ -L "$link" ] || fatal "sbin/$b is not a symlink"\n'
        + '    target=$(readlink "$link") || fatal "cannot read sbin/$b"\n'
        + '    [ "$target" = "$current/$b" ] || fatal "sbin/$b points to $target, not versions/current"\n'
        + '    resolved=$(readlink -f "$link") || fatal "sbin/$b does not resolve"\n'
        + '    [ "$resolved" = "$version_dir/$b" ] || fatal "sbin/$b resolves outside current: $resolved"\n'
        + '    [ -f "$resolved" ] && [ -x "$resolved" ] || fatal "versions/current/$b is not executable"\n'
        + 'done\n'
        + 'echo "#10771 seeded runtime layout OK: $version_dir"\n'
    )
