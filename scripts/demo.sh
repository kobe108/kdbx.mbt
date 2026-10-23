#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."
export KDBX_PASSWORD='K@g=UB#*2_84Z._FUO>|'
database=examples/demo.kdbx

echo "== info =="
moon run cmd/kdbx -- info "$database"

printf "\n== audit (Markdown) ==\n"
moon run cmd/kdbx -- audit "$database"

printf "\n== audit gate (expected exit 1) ==\n"
if moon run cmd/kdbx -- audit "$database" --format json --fail-on-findings; then
  echo "audit gate unexpectedly passed" >&2
  exit 1
else
  code=$?
  if [ "$code" -ne 1 ]; then
    echo "audit gate returned $code, expected 1" >&2
    exit 1
  fi
fi

printf "\n== export (passwords redacted) ==\n"
moon run cmd/kdbx -- export "$database" --format json
