///|
/// The RFC 7693 appendix A vector, cross-checked against Python's hashlib.
test "blake2b matches published vectors" {
  assert_eq(
    to_hex(blake2b(ascii_bytes("abc"), 64)),
    "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
  )
  // The empty input and a truncated digest, generated with hashlib.
  assert_eq(
    to_hex(blake2b(ascii_bytes(""), 64)),
    "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
  )
  assert_eq(
    to_hex(blake2b(ascii_bytes("abc"), 32)),
    "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
  )
}

///|
test "blake2b rejects impossible digest lengths" {
  try blake2b(ascii_bytes("abc"), 0) catch {
    Malformed(_) => ()
    e => fail("expected a length error, got: " + e.message())
  } noraise {
    _ => fail("expected a zero-length digest to be refused")
  }
}
