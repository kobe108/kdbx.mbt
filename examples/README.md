# Demo database

`demo.kdbx` is a KeePassXC 2.7 database created by this project for the
acceptance demo. It contains only fictional entries and uses the public demo
password:

```text
K@g=UB#*2_84Z._FUO>|
```

The database is KDBX 4.0 with Argon2d, AES-256-CBC and gzip. Its KDF cost was
reduced from 64 MiB / 81 rounds to 1 MiB / 1 round so the demo starts quickly;
the encrypted payload is otherwise the payload produced by KeePassXC.

Run the complete demo from the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/demo.ps1
```

```sh
sh scripts/demo.sh
```
