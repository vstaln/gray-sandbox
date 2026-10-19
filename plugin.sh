#!/bin/sh
here="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
sys="$(uname -s)"
case "$sys" in
MINGW* | MSYS* | CYGWIN*) rel="x86_64-pc-windows-msvc/gray-sandbox.exe" ;;
Darwin*)
    case "$(uname -m)" in
    arm64) rel="aarch64-apple-darwin/gray-sandbox" ;;
    *) rel="x86_64-apple-darwin/gray-sandbox" ;;
    esac ;;
*)
    case "$(uname -m)" in
    aarch64 | arm64) rel="aarch64-unknown-linux-musl/gray-sandbox" ;;
    *) rel="x86_64-unknown-linux-musl/gray-sandbox" ;;
    esac ;;
esac
if [ -x "$here/$rel" ]; then exec "$here/$rel" "$@"; fi
for cand in "$here/target/release/gray-sandbox.exe" "$here/target/release/gray-sandbox" "$here/target/debug/gray-sandbox.exe" "$here/target/debug/gray-sandbox"; do
    if [ -x "$cand" ]; then exec "$cand" "$@"; fi
done
echo "gray-sandbox binary not found in $here" >&2
exit 1
