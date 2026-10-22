#!/bin/sh
# Maintainer-only packaging; target, executable and output are explicit arguments.
set -eu
if [ "$#" -ne 3 ]; then echo "usage: package.sh TARGET BINARY NEW_OUTPUT_DIR" >&2; exit 1; fi
target=$1
binary=$2
out=$3
mkdir "$out"
root="$out/emudhra-trust-audit-$target"
mkdir "$root"
cp "$binary" "$root/"
cp LICENSE NOTICE README.md README.ja.md Cargo.lock "$root/"
cp -R data "$root/"
mkdir "$root/skills"
cargo fetch --locked
cargo run --locked --example maintenance -- licenses "$root/THIRD_PARTY_LICENSES"
for skill in endpoint-trust-audit project-trust-audit; do
  mkdir -p "$root/skills/$skill/bin"
  cp "skills/$skill/SKILL.md" "skills/$skill/run.sh" "skills/$skill/run.ps1" "$root/skills/$skill/"
  cp "$binary" "$root/skills/$skill/bin/"
  cp LICENSE NOTICE "$root/skills/$skill/"
  cp -R "$root/THIRD_PARTY_LICENSES" "$root/skills/$skill/"
done
tar -czf "$out/emudhra-trust-audit-$target.tar.gz" -C "$out" "emudhra-trust-audit-$target"
