#!/bin/sh
set -eu

repo="null-select/null"
version="${NULL_VERSION:-latest}"
os_name=$(uname -s | tr '[:upper:]' '[:lower:]')
arch_name=$(uname -m)

case "$os_name" in
  darwin|linux) ;;
  *) echo "null: unsupported operating system: $os_name" >&2; exit 1 ;;
esac

case "$arch_name" in
  x86_64|amd64) arch_name="amd64" ;;
  arm64|aarch64) arch_name="arm64" ;;
  *) echo "null: unsupported architecture: $arch_name" >&2; exit 1 ;;
esac

asset="null_${os_name}_${arch_name}.tar.gz"
if [ "$version" = "latest" ]; then
  base_url="https://github.com/${repo}/releases/latest/download"
else
  case "$version" in v*) ;; *) version="v${version}" ;; esac
  base_url="https://github.com/${repo}/releases/download/${version}"
fi

temporary_directory=$(mktemp -d)
trap 'rm -rf "$temporary_directory"' EXIT INT TERM

curl --fail --location --silent --show-error "${base_url}/${asset}" --output "${temporary_directory}/${asset}"
curl --fail --location --silent --show-error "${base_url}/checksums.txt" --output "${temporary_directory}/checksums.txt"

expected=$(awk -v asset="$asset" '$2 == asset { print $1 }' "${temporary_directory}/checksums.txt")
if [ -z "$expected" ]; then
  echo "null: release checksum is missing for ${asset}" >&2
  exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "${temporary_directory}/${asset}" | awk '{ print $1 }')
else
  actual=$(shasum -a 256 "${temporary_directory}/${asset}" | awk '{ print $1 }')
fi
if [ "$actual" != "$expected" ]; then
  echo "null: checksum verification failed" >&2
  exit 1
fi

tar -xzf "${temporary_directory}/${asset}" -C "$temporary_directory" null
if [ -n "${NULL_INSTALL_DIR:-}" ]; then
  install_directory="$NULL_INSTALL_DIR"
else
  install_directory="${HOME}/.local/bin"
fi
mkdir -p "$install_directory"
install -m 0755 "${temporary_directory}/null" "${install_directory}/null"

echo "Installed null to ${install_directory}/null"
case ":${PATH}:" in
  *":${install_directory}:"*) ;;
  *) echo "Add ${install_directory} to PATH before running null." ;;
esac
