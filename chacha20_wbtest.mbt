///|
/// The outer cipher path: a 32-byte key, the 12-byte nonce from the header and
/// counter zero, streamed over the whole payload.
test "outer chacha20 round-trips and validates its nonce" {
  let key = sequence_bytes(32, 7, 3)
  let nonce = sequence_bytes(12, 5, 1)
  let plaintext = ascii_bytes("payload for the outer ChaCha20 path")
  let ciphertext = ChaCha20::new(key, nonce, 0).apply(plaintext)
  assert_eq(to_hex(chacha20_decrypt(key, nonce, ciphertext)), to_hex(plaintext))
  try chacha20_decrypt(key, sequence_bytes(8, 1, 0), ciphertext) catch {
    Malformed(message) => assert_true(message.contains("12-byte IV"))
    e => fail("expected an IV length error, got: " + e.message())
  } noraise {
    _ => fail("expected an 8-byte nonce to be refused")
  }
}

///|
/// A zero-filled buffer of `count` bytes, used to read raw keystream.
fn zeros(count : Int) -> Bytes {
  let out = ByteWriter::new()
  let mut i = 0
  while i < count {
    out.write_byte(0)
    i = i + 1
  }
  out.to_bytes()
}

///|
/// The block-function vector from RFC 8439, section 2.3.2: with counter 1 the
/// keystream must start with these bytes.
test "chacha20 matches the rfc 8439 block vector" {
  let key = sequence_bytes(32, 1, 0)
  let nonce = hex_literal("000000090000004a00000000")
  let stream = ChaCha20::new(key, nonce, 1)
  // 64 bytes of keystream is one block; a 65th byte would start the next.
  let block = stream.apply(zeros(64))
  assert_eq(
    to_hex(block),
    "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
  )
}

///|
/// The encryption vector from RFC 8439, section 2.4.2: the ciphertext is the
/// plaintext XOR the same keystream, so this pins the multi-block path.
test "chacha20 matches the rfc 8439 encryption vector" {
  let key = sequence_bytes(32, 1, 0)
  let nonce = hex_literal("000000000000004a00000000")
  let plaintext = ascii_bytes(
    "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
  )
  let cipher = ChaCha20::new(key, nonce, 1).apply(plaintext)
  assert_eq(
    to_hex(cipher),
    "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d",
  )
  // Applying the same stream twice returns the plaintext.
  let again = ChaCha20::new(key, nonce, 1).apply(cipher)
  assert_eq(to_hex(again), to_hex(plaintext))
}

///|
test "chacha20 rejects wrong key and nonce sizes" {
  try
    ChaCha20::new(
      sequence_bytes(16, 1, 0),
      hex_literal("000000000000004a00000000"),
      0,
    )
  catch {
    Malformed(message) => assert_true(message.contains("32-byte key"))
    e => fail("expected a key size error, got: " + e.message())
  } noraise {
    _ => fail("expected a 16-byte key to be rejected")
  }
  try
    ChaCha20::new(sequence_bytes(32, 1, 0), hex_literal("00112233"), 0)
  catch {
    Malformed(message) => assert_true(message.contains("12-byte nonce"))
    e => fail("expected a nonce size error, got: " + e.message())
  } noraise {
    _ => fail("expected an 4-byte nonce to be rejected")
  }
}
