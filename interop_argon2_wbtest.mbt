///|
/// Argon2 with the exact parameters of the real KeePassXC file above (m = 1 MiB,
/// t = 2, p = 2, Argon2d, version 0x13) and its salt. The expected tag comes
/// from argon2-cffi, an independent implementation — the RFC 9106 vectors use
/// much smaller memory, so this pins the parameters seen in practice.
test "argon2 matches an independent implementation on kdbx parameters" {
  let params : Argon2Params = {
    salt: hex_literal(
      "56ac066d2d862ab0c50c00f6143a349df441f2e6910b297da88f50c3c302d9a5",
    ),
    secret: Bytes::makei(0, fn(_) { 0 }),
    associated_data: Bytes::makei(0, fn(_) { 0 }),
    iterations: 2,
    memory_kib: 1024,
    lanes: 2,
    tag_length: 32,
    version: 0x13,
    kind: Argon2d,
  }
  // The composite key of the password "t": SHA-256 of SHA-256 of the UTF-8 text.
  let composite = sha256(sha256(ascii_bytes("t")))
  assert_eq(
    to_hex(argon2_digest(params, composite)),
    "5ef06327c2aa395e04aa9a94fb837b58030cf202eddc61f408046070c256a2e8",
  )
}
