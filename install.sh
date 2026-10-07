#!/bin/sh
# Installs the latest `why` for Linux from GitHub Releases:  curl -fsSL https://raw.githubusercontent.com/GladCubes/why/master/install.sh | sh
# Installs to /usr/local/bin if run as root, else to ~/.local/bin. Set WHY_VERSION=v0.1.0 for a specific version.
set -eu
repo=GladCubes/why
case "$(uname -s)" in Linux) ;; *) echo "this script is for Linux; on Windows download why.exe from https://github.com/$repo/releases" >&2; exit 1 ;; esac
case "$(uname -m)" in x86_64|amd64) arch=x86_64 ;; aarch64|arm64) arch=aarch64 ;; *) echo "unsupported CPU: $(uname -m)" >&2; exit 1 ;; esac
ver=${WHY_VERSION:-$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)}
[ -n "$ver" ] || { echo "could not find the latest release" >&2; exit 1; }
if [ "$(id -u)" = 0 ]; then dest=/usr/local/bin; else dest=${HOME}/.local/bin; mkdir -p "$dest"; fi
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
file="why-$ver-linux-$arch.tar.gz"
curl -fsSL "https://github.com/$repo/releases/download/$ver/$file" -o "$tmp/$file"
curl -fsSL "https://github.com/$repo/releases/download/$ver/SHA256SUMS" -o "$tmp/SHA256SUMS"
(cd "$tmp" && grep " $file\$" SHA256SUMS | sha256sum -c -) >/dev/null || { echo "checksum mismatch: not installing" >&2; exit 1; }
tar -xzf "$tmp/$file" -C "$tmp"
install -m 755 "$tmp/why" "$dest/why"
echo "installed why $ver to $dest/why"
case ":$PATH:" in *":$dest:"*) ;; *) echo "note: $dest is not in your PATH" ;; esac
