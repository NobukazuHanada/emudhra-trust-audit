#!/bin/sh
set -eu
skill_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -n "${EMUDHRA_TRUST_AUDIT_BIN:-}" ]; then
  binary=$EMUDHRA_TRUST_AUDIT_BIN
  case "$binary" in /*|[A-Za-z]:/*|[A-Za-z]:\\*) ;; *) echo "EMUDHRA_TRUST_AUDIT_BIN must be an absolute trusted executable path." >&2; exit 3;; esac
elif [ -x "$skill_dir/bin/emudhra-trust-audit" ]; then
  binary="$skill_dir/bin/emudhra-trust-audit"
elif [ -x "$skill_dir/bin/emudhra-trust-audit.exe" ]; then
  binary="$skill_dir/bin/emudhra-trust-audit.exe"
else
  binary=$(command -v emudhra-trust-audit 2>/dev/null || true)
fi
if [ -z "$binary" ] || [ ! -f "$binary" ] || [ ! -x "$binary" ]; then
  echo "emudhra-trust-audit is missing. Install a verified binary from https://github.com/NobukazuHanada/emudhra-trust-audit/releases or build with Cargo. Set EMUDHRA_TRUST_AUDIT_BIN to its absolute path. Nothing was downloaded or executed." >&2
  exit 3
fi
exec "$binary" endpoint "$@"
