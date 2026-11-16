#!/bin/bash
# scripts/provision-testrunner.sh -- provision an xpf test-runner VM (#19035).
#
# Tests never run on the workstation; they run in these VMs on the lab hosts
# through scripts/vm-test-run.sh. To create a runner (example: udp):
#
#   incus init images:debian/14/cloud udp:xpf-testrunner --vm \
#       --storage default --network incusbr-udp \
#       -c limits.cpu=8 -c limits.memory=32GiB -c limits.cpu.priority=1 \
#       -c security.secureboot=false
#   incus config device set udp:xpf-testrunner root size=150GiB
#   incus start udp:xpf-testrunner
#   scripts/provision-testrunner.sh --runner udp:xpf-testrunner
#
# The low limits.cpu.priority keeps the lab firewall VMs ahead of test load,
# so gate measurement on the same host keeps priority.
#
# Run from the workstation, --runner derives the toolchain versions from this
# checkout, pushes this script into the VM, runs it there as root, and then
# checks that scripts/resolve-deadcode-go.sh resolves for the runner user:
#   - the build Go: go.mod's `toolchain` line if present, else its `go` line;
#   - the deadcode Go: DEADCODE_GO_VERSION in scripts/resolve-deadcode-go.sh.
#     The pinned deadcode analyser panics under other Go series, so it needs
#     this toolchain beside the build one. Without it, `make test-go`'s
#     deadcode leg on a runner was a silent NOT-EXAMINED (#19152).
#     It goes to /usr/lib/go-<version>, which the resolver finds for root
#     and runner alike, and /etc/profile.d/xpf-testrunner.sh exports
#     XPF_DEADCODE_REQUIRE=1, so on a provisioned runner a missing deadcode
#     toolchain is a FAIL, not a skip.
#
#   scripts/provision-testrunner.sh --runner <remote:instance> [--toolchains-only]
#   scripts/provision-testrunner.sh --print-versions
#
# --toolchains-only installs only the two Go toolchains and the profile entry,
# skipping apt, rustup and the account setup: use it to bring an already
# provisioned runner up to date. Each toolchain unpacks beside its target
# directory and is renamed into place, and an installed toolchain of the right
# version is left alone. A lane running on the runner is therefore unaffected
# unless the build Go version itself changes. --print-versions prints the
# derived versions and touches nothing. A runner that is not RUNNING (a FROZEN
# one is paused by a gate cell) is refused with exit 75 and left alone.
set -euo pipefail

# derive_versions: set go_ver and dc_ver from this checkout.
derive_versions() {
	local root
	root=$(cd "$(dirname "$0")/.." && pwd)
	go_ver=$(awk '$1 == "toolchain" { t = $2; sub(/^go/, "", t) } $1 == "go" { g = $2 } END { print (t != "" ? t : g) }' "$root/go.mod")
	dc_ver=$(sed -n 's/^DEADCODE_GO_VERSION=//p' "$root/scripts/resolve-deadcode-go.sh")
	local v
	for v in "$go_ver" "$dc_ver"; do
		if ! [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
			echo "provision-testrunner: cannot derive a full Go release from go.mod and scripts/resolve-deadcode-go.sh (got build '$go_ver', deadcode '$dc_ver')" >&2
			exit 2
		fi
	done
}

case "${1:-}" in
--print-versions)
	derive_versions
	echo "go $go_ver"
	echo "deadcode-go $dc_ver"
	exit 0
	;;
--runner)
	runner=${2:-}
	scope=full
	case "${3:-}" in
	"") ;;
	--toolchains-only) scope=toolchains ;;
	*) runner= ;;
	esac
	if [[ -z "$runner" ]]; then
		echo "usage: $0 --runner <remote:instance> [--toolchains-only] | --print-versions" >&2
		exit 2
	fi
	derive_versions
	status=$(incus info "$runner" 2>/dev/null | sed -n 's/^Status: //p')
	if [[ "$status" != RUNNING ]]; then
		echo "provision-testrunner: $runner is '${status:-unknown}', not RUNNING; refusing (a FROZEN runner is paused by a gate cell)" >&2
		exit 75
	fi
	echo "provision-testrunner: $runner ($scope): go $go_ver, deadcode go $dc_ver"
	incus file push "$0" "$runner/root/provision-testrunner.sh"
	incus exec "$runner" --env XPF_GO_VERSION="$go_ver" --env XPF_DEADCODE_GO_VERSION="$dc_ver" \
		--env XPF_PROVISION_SCOPE="$scope" -- bash /root/provision-testrunner.sh
	# The acceptance check, run the way vm-test-run.sh runs a lane: a login
	# shell as runner, so the profile entry applies.
	resolved=$(incus exec "$runner" -- su - runner -c 'sh -s' <"$(dirname "$0")/resolve-deadcode-go.sh")
	echo "provision-testrunner: $runner: the deadcode resolver picks $resolved"
	exit 0
	;;
esac

# In the VM, as root.
systemd-detect-virt --vm -q || { echo "provision-testrunner: refusing to run outside a VM" >&2; exit 2; }
go_ver=${XPF_GO_VERSION:?run this from the workstation as: scripts/provision-testrunner.sh --runner <remote:instance>}
dc_ver=${XPF_DEADCODE_GO_VERSION:?run this from the workstation as: scripts/provision-testrunner.sh --runner <remote:instance>}
scope=${XPF_PROVISION_SCOPE:-full}

# install_go <version> <dir>: install go<version> at <dir> unless it is already
# there. It unpacks beside <dir> and renames into place, so <dir> is never
# half-written.
install_go() {
	local ver=$1 dir=$2 tmp
	if "$dir/bin/go" version 2>/dev/null | grep -q " go$ver "; then
		return 0
	fi
	tmp=$(mktemp -d "$(dirname "$dir")/.go-$ver.XXXXXX")
	curl -fsSL "https://go.dev/dl/go${ver}.linux-amd64.tar.gz" | tar -C "$tmp" -xzf -
	rm -rf "$dir"
	mv "$tmp/go" "$dir"
	rmdir "$tmp"
}

if [[ "$scope" == full ]]; then
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -qq
	echo 'Acquire::Retries "5";' > /etc/apt/apt.conf.d/80-retries
	apt-get install -y -qq build-essential clang llvm lld libbpf-dev libxdp-dev libelf-dev zlib1g-dev libzstd-dev \
	  pkg-config git make python3 python3-venv iproute2 nftables ethtool tcpdump iperf3 bpftool kmod \
	  debhelper devscripts shellcheck jq curl ca-certificates protobuf-compiler rsync sudo util-linux \
	  "linux-headers-$(uname -r)" >/dev/null
	# The crate's build.rs pins libelf >= 0.195 (#9931, userspace-dp/build_support/libversions.rs);
	# Ubuntu 26.04 ships 0.194, so runners use Debian 14 (forky) like the deb-building workstation.
	elf_ver=$(dpkg-query -W -f='${Version}' libelf-dev | sed 's/-.*//')
	if ! dpkg --compare-versions "$elf_ver" ge 0.195; then
	  echo "provision-testrunner: libelf-dev $elf_ver < 0.195 (#9931); use a Debian 14 image" >&2
	  exit 2
	fi
fi
install_go "$go_ver" /usr/local/go
ln -sf /usr/local/go/bin/go /usr/local/bin/go; ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
# Some selftests pin PATH to "...:/usr/bin:/bin" (deploy-lib-selftest's
# clean-PATH make-deb guard), and the workstation's Go is in /usr/bin.
ln -sf /usr/local/go/bin/go /usr/bin/go; ln -sf /usr/local/go/bin/gofmt /usr/bin/gofmt
install_go "$dc_ver" "/usr/lib/go-$dc_ver"
cat > /etc/profile.d/xpf-testrunner.sh <<'PROFILE'
# Written by scripts/provision-testrunner.sh (#19152). This runner carries the
# deadcode toolchain (/usr/lib/go-<version>), so a missing one must FAIL the
# deadcode gates here, not skip them as NOT-EXAMINED (exit 77).
export XPF_DEADCODE_REQUIRE=1
PROFILE
if [[ "$scope" == full ]]; then
	id runner >/dev/null 2>&1 || useradd -m -s /bin/bash runner
	echo 'runner ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/runner
	su - runner -c 'command -v rustup >/dev/null 2>&1 || (curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.98.1 >/dev/null)'
	su - runner -c '. ~/.cargo/env; rustup toolchain install 1.98.1 --profile minimal -c rustfmt -c clippy >/dev/null; rustup default 1.98.1 >/dev/null; rustc --version; cargo --version'
	mkdir -p /work && chown runner:runner /work
	install -d -o runner -g runner /home/runner/.cache /home/runner/.cache/go-build
	install -d -m 1777 /wtgt
	echo "xpf-testrunner: provisioned $(date -u +%FT%TZ)" > /etc/xpf-testrunner
fi
go version
"/usr/lib/go-$dc_ver/bin/go" version
