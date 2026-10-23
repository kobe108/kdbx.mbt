# Algorithm interoperability fixtures

Both databases were created with `pykeepass 4.2.0`, a separate KDBX
implementation, using only fictional credentials. Their KDF cost was reduced
to 1 MiB / 1 pass / 1 lane so CI stays fast.

| File | KDF | Outer cipher | Payload |
| --- | --- | --- | --- |
| `argon2id-aes.kdbx` | Argon2id | AES-256-CBC | gzip |
| `argon2d-chacha20.kdbx` | Argon2d | ChaCha20 | gzip |

Demo password for both files: `Interop-2026!Strong`.

`scripts/demo.ps1` and `scripts/demo.sh` open both files, verify the reported
algorithm pair and read a real entry from each.
