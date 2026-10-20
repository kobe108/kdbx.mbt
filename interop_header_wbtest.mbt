///|
/// A real file written by KeePassXC (tests/data/Format400.kdbx), with the
/// password "t" taken from their own TestKdbx4.cpp. It uses the KDBX 4.0 draft:
/// Argon2d, ChaCha20 and gzip.
///
/// The draft's payload layout differs from 4.1, so this test covers the part
/// that both share — and that part is the hard one: our Argon2d, key derivation
/// and ChaCha20 IV handling reproduce the header authentication of a file we did
/// not write.
test "a real keepassxc header authenticates" {
  let opened = open_header(
    real_format400(),
    MasterKey::new().with_password("t"),
  )
  assert_eq(opened.cipher().to_text(), "ChaCha20")
  assert_eq(opened.compression().to_text(), "gzip")
}
