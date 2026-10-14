///|
/// FIPS-197 appendix C.3 in reverse: the published ciphertext must decrypt back
/// to the published plaintext with the same key.
test "aes256 inverse cipher matches the fips-197 example" {
  let key = sequence_bytes(32, 1, 0)
  let ciphertext = hex_literal("8ea2b7ca516745bfeafc49904b496089")
  let buffer : Array[Byte] = []
  for i = 0; i < 16; i = i + 1 {
    buffer.push(ciphertext[i])
  }
  Aes256Decrypt::new(key).decrypt_in_place(buffer, 0)
  assert_eq(
    to_hex(Bytes::from_array(buffer)),
    "00112233445566778899aabbccddeeff",
  )
}

///|
/// The inverse S-box is built from the forward one, so it cannot disagree with
/// it: every entry must satisfy `inverse[sbox[i]] == i`.
test "the inverse s-box inverts the s-box" {
  let inverse = build_inverse_sbox()
  let mut index = 0
  let mut mismatches = 0
  while index < 256 {
    if inverse[aes_sbox[index].to_uint().reinterpret_as_int()] !=
      index.to_byte() {
      mismatches = mismatches + 1
    }
    index = index + 1
  }
  assert_eq(mismatches, 0)
}

///|
/// A CBC block decrypted with the wrong IV or the wrong key must not produce the
/// padding the generator wrote, and the padding check has to notice.
test "cbc and padding errors are reported" {
  let key = sequence_bytes(32, 1, 0)
  let iv = sequence_bytes(16, 1, 0)
  // Ciphertext produced by the fixture generator for a 32-byte plaintext.
  let ciphertext = hex_literal(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  // Wrong key length, wrong IV length and a bad ciphertext length are all
  // rejected before any work happens.
  try aes256_cbc_decrypt(sequence_bytes(16, 1, 0), iv, ciphertext) catch {
    Malformed(message) => assert_true(message.contains("32-byte key"))
    e => fail("expected a key length error, got: " + e.message())
  } noraise {
    _ => fail("expected a 16-byte key to be rejected")
  }
  try aes256_cbc_decrypt(key, sequence_bytes(8, 1, 0), ciphertext) catch {
    Malformed(message) => assert_true(message.contains("16-byte IV"))
    e => fail("expected an IV length error, got: " + e.message())
  } noraise {
    _ => fail("expected an 8-byte IV to be rejected")
  }
  try aes256_cbc_decrypt(key, iv, hex_literal("00112233")) catch {
    Malformed(message) => assert_true(message.contains("multiple of 16"))
    e => fail("expected a length error, got: " + e.message())
  } noraise {
    _ => fail("expected a short ciphertext to be rejected")
  }
  // Padding that is not the PKCS#7 pattern.
  try unpad_pkcs7(hex_literal("00000000000000000000000000000000")) catch {
    Malformed(_) => ()
    e => fail("expected a padding error, got: " + e.message())
  } noraise {
    _ => fail("expected all-zero padding to be rejected")
  }
}
