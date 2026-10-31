#!/usr/bin/env bash
# Installs or upgrades sing-box-panel to the latest release (or the version given):
#
#   bash <(curl -fsSL https://raw.githubusercontent.com/chok8356/sing-box-panel/master/install.sh)
#   bash <(curl -fsSL https://raw.githubusercontent.com/chok8356/sing-box-panel/master/install.sh) v0.1.0
#
# Run as root. It downloads the panel binary for this machine, checks it
# against the release's SHA256SUMS and runs `sing-box-panel install`, which
# does the rest and stays on the server as the `sbp` command.
set -euo pipefail

repo=chok8356/sing-box-panel
die() { echo "Error: $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die 'run as root (sudo -i first)'
case $(uname -m) in
    x86_64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) die 'supported architectures: amd64, arm64' ;;
esac
if [[ ${1:-latest} == latest ]]; then
    base=https://github.com/$repo/releases/latest/download
else
    base=https://github.com/$repo/releases/download/$1
fi

dir=$(mktemp -d)
trap 'rm -rf -- "$dir"' EXIT
fetch() { curl --proto '=https' --tlsv1.2 -fsSL "$1" -o "$2"; }
fetch "$base/sing-box-panel_linux_$arch" "$dir/sing-box-panel"
fetch "$base/SHA256SUMS" "$dir/SHA256SUMS"

expected=$(awk -v file="sing-box-panel_linux_$arch" '$2 == file { print $1 }' "$dir/SHA256SUMS")
actual=$(sha256sum "$dir/sing-box-panel" | cut -d' ' -f1)
[[ -n $expected && $expected == "$actual" ]] || die 'downloaded binary does not match SHA256SUMS'

chmod 0755 "$dir/sing-box-panel"
"$dir/sing-box-panel" install
