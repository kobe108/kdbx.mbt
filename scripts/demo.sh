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

export KDBX_PASSWORD='Interop-2026!Strong'
check_case() {
  file=$1
  kdf=$2
  cipher=$3
  title=$4
  printf "\n== interop: %s + %s ==\n" "$kdf" "$cipher"
  info=$(moon run cmd/kdbx -- info "$file")
  printf "%s\n" "$info" | grep -F "KDF: $kdf" >/dev/null
  printf "%s\n" "$info" | grep -F "Cipher: $cipher" >/dev/null
  shown=$(moon run cmd/kdbx -- show "$file" "$title")
  printf "%s\n" "$shown" | grep -F "Title: $title" >/dev/null
}

check_case examples/interop/argon2id-aes.kdbx Argon2id AES-256-CBC "Argon2id AES"
check_case examples/interop/argon2d-chacha20.kdbx Argon2d ChaCha20 "ChaCha20"
