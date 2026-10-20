#!/usr/bin/env bash
# Download a small public port-scan capture into pcaps/sample.pcap.
#
# Source: Wireshark wiki sample captures, "NMap-Captures.zip"
#   https://wiki.wireshark.org/SampleCaptures
# We extract nmap_OS_scan_succesful: `nmap -O -Pn 192.168.100.101` from
# 192.168.100.103 (ICMP probes, SYN scan, NULL/Xmas probes), ~2k packets.
set -euo pipefail

URL="https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/NMap-Captures.zip"
SHA256="3fac3f99402b5b6a2bc819ce7c9ba4aab58756e3353412a7834bfce02f098305"
MEMBER="nmap_OS_scan_succesful"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT/pcaps/sample.pcap"

for cmd in curl unzip; do
  command -v "$cmd" >/dev/null || { echo "error: $cmd is required" >&2; exit 1; }
done

sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "Downloading $URL"
curl -fsSL --retry 3 -o "$tmp/captures.zip" "$URL"

actual="$(sha256 "$tmp/captures.zip")"
if [[ "$actual" != "$SHA256" ]]; then
  echo "error: checksum mismatch (expected $SHA256, got $actual)" >&2
  exit 1
fi

unzip -p "$tmp/captures.zip" "$MEMBER" > "$tmp/sample.pcap"
mkdir -p "$(dirname "$DEST")"
mv "$tmp/sample.pcap" "$DEST"
echo "Saved $DEST ($(wc -c < "$DEST" | tr -d ' ') bytes)"
