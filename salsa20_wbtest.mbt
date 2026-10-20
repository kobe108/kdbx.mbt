///|
/// A keystream vector generated with pycryptodome, an independent
/// implementation: key 00..1f, nonce 00..07, first 64 bytes of the stream.
test "salsa20 matches an independent keystream" {
  let stream = Salsa20::new(sequence_bytes(32, 1, 0), sequence_bytes(8, 1, 0))
  let block = stream.apply(zero_bytes_of(64))
  assert_eq(
    to_hex(block),
    "2ead0f5f185729ced672b3a928e454f72fdb44a87b9cd8d219e4ec14aef9c6bc77bf057f5659d7753848f8d3fe769ca5fdd8057d46326990e5f136e2fcb7bb7c",
  )
  let round_trip = Salsa20::new(
    sequence_bytes(32, 1, 0),
    sequence_bytes(8, 1, 0),
  ).apply(block)
  assert_eq(to_hex(round_trip), to_hex(zero_bytes_of(64)))
}

///|
test "salsa20 rejects wrong key and nonce sizes" {
  try Salsa20::new(sequence_bytes(16, 1, 0), sequence_bytes(8, 1, 0)) catch {
    Malformed(message) => assert_true(message.contains("32-byte key"))
    e => fail("expected a key size error, got: " + e.message())
  } noraise {
    _ => fail("expected a 16-byte key to be refused")
  }
  try Salsa20::new(sequence_bytes(32, 1, 0), sequence_bytes(4, 1, 0)) catch {
    Malformed(message) => assert_true(message.contains("8-byte nonce"))
    e => fail("expected a nonce size error, got: " + e.message())
  } noraise {
    _ => fail("expected a 4-byte nonce to be refused")
  }
}
