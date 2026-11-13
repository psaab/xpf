#!/usr/bin/env bash
# scripts/testguard-root-view.sh -- the throwaway whole-root view that a ROOT
# run of testguard-run.sh executes in (#19084). It is not run on its own.
#
# Usage, inside `unshare -m --propagation private`, i.e. a private mount
# namespace of real root created before any user namespace exists:
#
#   testguard-root-view.sh SCRATCH CWD [PASS-THROUGH ...] -- COMMAND [ARG ...]
#
# What it builds, in that mount namespace only:
#
#  - "/" itself becomes an overlay. The lower layer is the host's root
#    filesystem and the upper layer is a tmpfs mounted on SCRATCH, which
#    exists only in this namespace and is discarded with it. Every write,
#    unlink, rename or chmod on the root filesystem lands in the upper, by
#    whatever path or directory symlink it was reached (Codex F1 on
#    11eaccc637: a four-tree enumeration let /var/log/xpf -> /srv/... escape).
#  - Every other mount from the host's table is classified by filesystem type
#    and depth, and NOTHING is left writable by omission:
#      * /proc, /sys and /dev are bound in recursively (pseudo filesystems);
#        a mount below them is kept if it is a pseudo filesystem, overlaid if
#        it is storage (tmpfs such as /dev/shm), and otherwise refused;
#      * /run gets its own overlay. Host submounts below /run are NOT carried
#        into it: their mountpoints read as empty directories (R18 R3);
#      * any other storage mount (ext4, xfs, btrfs, tmpfs such as /tmp, ...)
#        is overlaid the same way as "/";
#      * filesystems overlayfs cannot use as a lower layer (vfat, as on
#        /boot/efi; read-only media) are bound in READ-ONLY;
#      * any other type is REFUSED (exit 2) before the command runs.
#  - The PASS-THROUGH directories (the checkout, the TMPDIR scratch, GOCACHE,
#    GOMODCACHE, GOTMPDIR; chosen by testguard-run.sh) are bound in from the
#    host, writable. They are the only writable host storage in the view, so
#    build output and t.TempDir() land on disk, not in the tmpfs upper.
#  - pivot_root into the view and detach the old root, so the host's root
#    filesystem is not attached anywhere in this mount namespace; then cd to
#    CWD inside the view, refusing if it is not reachable there (Codex F2).
#  - Close every inherited descriptor above 2 (Codex F2), run COMMAND, and
#    report the tmpfs upper's peak use (sampled every second) on stderr.
#
# Any setup failure exits 2 before COMMAND runs. Otherwise the exit status is
# COMMAND's.
set -u

refuse() {
	echo "testguard-run: REFUSED: $*; refusing a root run that could write host state (#19084)" >&2
	exit 2
}

(($# >= 3)) || refuse "usage: testguard-root-view.sh SCRATCH CWD [PASS-THROUGH ...] -- COMMAND ..."
S=$1
cwd=$2
shift 2
pass=()
while (($#)) && [[ $1 != -- ]]; do
	pass+=("$1")
	shift
done
[[ ${1:-} == -- ]] && shift || refuse "no -- before the command"
(($#)) || refuse "no command"

# Filesystem types by treatment. A type in none of these lists is refused.
pseudo_types=" proc sysfs devtmpfs devpts mqueue cgroup cgroup2 bpf tracefs debugfs securityfs configfs fusectl hugetlbfs pstore efivarfs binfmt_misc nsfs selinuxfs "
# Accepted only below /proc, /sys or /dev, where the recursive bind carries
# them (systemd's binfmt_misc automount). Elsewhere an automount can attach
# real storage, so it is refused.
tree_only_types=" autofs rpc_pipefs "
overlay_types=" ext2 ext3 ext4 xfs btrfs f2fs tmpfs overlay zfs "
readonly_types=" vfat msdos exfat iso9660 squashfs erofs udf "

# Paths go into overlayfs option strings (comma- and colon-separated) and
# into this script's own word lists: refuse anything that would need quoting.
plain_path() { [[ $1 == /* && $1 != *[,:\\[:space:]]* ]]; }

under() { # $1 path, $2 tree: is $1 the tree itself or below it?
	[[ $2 == / || $1 == "$2" || $1 == "$2"/* ]]
}

# The host's mount table as this namespace inherited it, read before SCRATCH
# is mounted: "depth mountpoint fstype", parents before children, and for a
# mountpoint listed twice (a mount stacked on another) the later, visible one.
mounts=$(awk '{
	for (i = 7; i <= NF; i++) if ($i == "-") break
	mp = $5; t = $(i + 1)
	if (!(mp in type)) order[++n] = mp
	type[mp] = t
} END {
	for (k = 1; k <= n; k++) {
		mp = order[k]; d = (mp == "/") ? 0 : gsub("/", "/", mp)
		print d, order[k], type[order[k]]
	}
}' /proc/self/mountinfo | sort -n -s -k1,1) || refuse "cannot read the mount table"
[[ -n $mounts ]] || refuse "empty mount table"

root_type=$(awk '$2 == "/" {print $3}' <<<"$mounts")
[[ $overlay_types == *" $root_type "* ]] || refuse "the root filesystem is $root_type, which overlayfs cannot cover"

for p in "${pass[@]}"; do
	plain_path "$p" && [[ $p != / ]] || refuse "pass-through path '$p' is not a plain absolute path below /"
done
plain_path "$S" || refuse "scratch path '$S' is not a plain absolute path"

mount -t tmpfs -o mode=0700 testguard-overlay "$S" || refuse "cannot mount the overlay scratch tmpfs on $S"
m=$S/merged
mkdir "$m" || refuse "cannot create $m"

n=0
overlay_onto() { # $1 lower (host path), $2 target in the view, $3 source tag
	n=$((n + 1))
	mkdir "$S/$n.upper" "$S/$n.work" || refuse "cannot create the upper for $1"
	mount -t overlay "$3" -o "lowerdir=$1,upperdir=$S/$n.upper,workdir=$S/$n.work" "$2" ||
		refuse "cannot cover $1 with a throwaway overlay"
}

overlay_onto / "$m" testguard-root

while read -r depth mp fstype; do
	[[ $mp == / ]] && continue
	skip=0
	for p in "${pass[@]}"; do under "$mp" "$p" && skip=1; done
	((skip)) && continue           # below a pass-through: the host's, by intent
	under "$mp" /run && [[ $mp != /run ]] && continue # hidden by /run's overlay (R18 R3)
	plain_path "$mp" || refuse "mountpoint '$mp' ($fstype) needs quoting; cannot place it in the view"
	case $mp in
	/proc | /sys | /dev)
		[[ $pseudo_types == *" $fstype "* ]] || refuse "$mp is $fstype, not a pseudo filesystem"
		mount --rbind "$mp" "$m$mp" || refuse "cannot bind $mp into the view"
		continue
		;;
	esac
	in_tree=0
	under "$mp" /proc || under "$mp" /sys || under "$mp" /dev && in_tree=1
	if [[ $pseudo_types == *" $fstype "* ]] || { ((in_tree)) && [[ $tree_only_types == *" $fstype "* ]]; }; then
		# Below /proc, /sys or /dev it came with the recursive bind.
		((in_tree)) && continue
		mount --bind "$mp" "$m$mp" || refuse "cannot bind $mp ($fstype) into the view"
	elif [[ $overlay_types == *" $fstype "* ]]; then
		overlay_onto "$mp" "$m$mp" "testguard-$fstype"
	elif [[ $readonly_types == *" $fstype "* ]]; then
		mount --bind "$mp" "$m$mp" && mount -o remount,bind,ro "$m$mp" ||
			refuse "cannot bind $mp ($fstype) into the view read-only"
	else
		refuse "$mp is $fstype, which this wrapper can neither overlay nor bind read-only"
	fi
done <<<"$mounts"

# The writable pass-through, parents before children.
while read -r p; do
	[[ -n $p ]] || continue
	mount --bind "$p" "$m$p" || refuse "cannot bind the pass-through $p into the view"
done < <(for p in "${pass[@]}"; do printf '%s %s\n' "$(tr -cd / <<<"$p" | wc -c)" "$p"; done | sort -n -s -k1,1 | cut -d' ' -f2-)

# Enter the view. pivot_root, not chroot: after the old root is detached the
# host's root filesystem is attached nowhere in this namespace, so neither a
# chroot escape nor detaching a mount inside the view can reach it. util-linux
# no longer ships pivot_root(8) on Debian, so the syscall comes from perl.
exec 8<"$S" || refuse "cannot hold the scratch tmpfs open"
mkdir "$m/.testguard-oldroot" || refuse "cannot create the old-root mountpoint"
cd "$m" || refuse "cannot enter $m"
perl -e 'require "syscall.ph"; syscall(&SYS_pivot_root, $ARGV[0], $ARGV[1]) == 0 or die "pivot_root: $!\n"' \
	. .testguard-oldroot || refuse "pivot_root into the view failed"
cd / || refuse "cannot cd to the view's root"
umount -l /.testguard-oldroot || refuse "cannot detach the host root from the view"
rmdir /.testguard-oldroot 2>/dev/null
cd -- "$cwd" 2>/dev/null || refuse "the working directory $cwd is not reachable inside the view"

used_kib() { # the scratch tmpfs's use, via the descriptor held open above
	local b
	read -ra b < <(stat -f -c '%b %f %S' /proc/self/fd/8 2>/dev/null) && ((${#b[@]} == 3)) || return 1
	echo $(((b[0] - b[1]) * b[2] / 1024))
}
(
	exec </dev/null >/dev/null 2>&1
	peak=0
	while u=$(used_kib); do
		((u > peak)) && peak=$u && echo "$peak" >/proc/self/fd/8/.peak-kib
		sleep 1
	done
) &
sampler=$!

# Run the command with no inherited descriptor above 2: a directory or file
# descriptor opened on the host before the view existed would still reach the
# host's storage (Codex F2).
(
	for fd in /proc/self/fd/*; do
		fd=${fd##*/}
		((fd > 2)) && eval "exec $fd>&-"
	done
	exec "$@"
) &
child=$!
trap 'kill -TERM "$child" 2>/dev/null' TERM INT HUP
while :; do
	wait "$child"
	rc=$?
	kill -0 "$child" 2>/dev/null || break
done
trap - TERM INT HUP
kill "$sampler" 2>/dev/null
wait "$sampler" 2>/dev/null
final=$(used_kib) || final=?
peak=$(cat /proc/self/fd/8/.peak-kib 2>/dev/null) || peak=0
[[ $final =~ ^[0-9]+$ ]] && ((final > peak)) && peak=$final
echo "testguard-run: root view: tmpfs upper peak ${peak} KiB (sampled every 1 s), ${final} KiB at exit (#19084)" >&2
exit "$rc"
