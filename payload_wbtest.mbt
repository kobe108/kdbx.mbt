///|
/// A complete KDBX 4.1 file produced by scripts/make_fixture.py: header, header
/// tags, an HMAC-protected block stream and an AES-256-CBC payload holding the
/// inner header (ChaCha20 random stream) plus a small XML document. Password
/// "correct horse battery staple", AES-KDF with 1000 rounds, no compression.
fn database() -> Bytes {
  hex_literal(
    "03d9a29a67fb4bb501000400021000000031c1f2e6bf714350be5805216afc5aff0304000000000000000420000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f0710000000101112131415161718191a1b1c1d1e1f0b5d00000000014205000000245555494410000000c9d9f39a628a4460bf740d08c18a4fea42010000005320000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f05010000005208000000e8030000000000000000040000000d0a0d0af5206f3f8783f00ba4e6c5932b0db51ae187c585fd3f9d6ff6577b7baee4da1fd611ca4c579161c6f9f10dda06a4b495d10f8d48df6823608de5cb6139a8e0139d4fed0de9b2d5e5e7faa99244054f517b91e0b5849a421602f40479c00120510000000000000000a00000001ff14c482aa6cc6307c4230a6fe549a1430ff6ecd8e0653090089009c67a25a0ae804e0c14f4f5c24fbf062f3bbf53c23648d034ee79dae98fd167eda1bf5444afb120950e997040a8be015b26cea03879f93a094ef72ee28bf31b325cfbf19026ea6cc26cce4064233d60a1eef9bbfca1431eef772943b8dc221b754861d762a69780e476e6538111dfc5fe6b2450f1d028901762a2b0985b1d396422178f335ab911bd588a86a23c54363c42aa91ecfc4fd02d298dd3d04bfa6953a6383fbb01000000000000000000000000",
  )
}

///|
/// The payload this fixture encrypts: the inner header followed by the XML
/// document, exactly as scripts/make_fixture.py generated it.
fn expected_payload() -> Bytes {
  hex_literal(
    "0104000000030000000240000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f003c4b65655061737346696c653e3c4d6574613e3c47656e657261746f723e6b6462782e6d627420666978747572653c2f47656e657261746f723e3c2f4d6574613e3c2f4b65655061737346696c653e",
  )
}

///|
/// End to end: authenticate the header, verify every block, decrypt, unpad.
/// The result must be byte-for-byte what the generator encrypted — the
/// generator is a separate implementation, so agreement here means the reading
/// path is right, not merely self-consistent.
test "a complete database decrypts to the expected payload" {
  let key = MasterKey::new().with_password("correct horse battery staple")
  let payload = decrypt_payload(database(), key)
  assert_eq(to_hex(payload), to_hex(expected_payload()))
  // The payload starts with the inner header: a ChaCha20 random stream id and a
  // 64-byte stream key, then a terminator.
  assert_eq(payload[0].to_uint(), 0x01)
  assert_eq(payload[5].to_uint(), 0x03)
  assert_eq(payload[9].to_uint(), 0x02)
  assert_eq(payload[9 + 1 + 4 + 64].to_uint(), 0x00)
  // ... and continues with the XML document.
  assert_eq(to_hex(Bytes::makei(5, fn(i) { payload[79 + i] })), "3c4b656550")
}

///|
/// A tampered block, a tampered tag and a wrong password all have to be refused.
test "a damaged payload is refused" {
  let key = MasterKey::new().with_password("correct horse battery staple")
  // One bit inside the first ciphertext block (the block stream starts at 271).
  let tampered_body = flip_byte(database(), 271 + 44 + 8)
  try decrypt_payload(tampered_body, key) catch {
    Malformed(message) => assert_true(message.contains("failed authentication"))
    e => fail("expected a block authentication failure, got: " + e.message())
  } noraise {
    _ => fail("expected a modified block to be refused")
  }
  // One bit inside the block tag.
  let tampered_tag = flip_byte(database(), 271)
  try decrypt_payload(tampered_tag, key) catch {
    Malformed(message) => assert_true(message.contains("failed authentication"))
    e => fail("expected a tag failure, got: " + e.message())
  } noraise {
    _ => fail("expected a modified tag to be refused")
  }
  // The wrong password never even reaches the blocks.
  let wrong = MasterKey::new().with_password("correct horse battery stapl")
  try decrypt_payload(database(), wrong) catch {
    Malformed(message) => assert_true(message.contains("header authentication"))
    e => fail("expected a header failure, got: " + e.message())
  } noraise {
    _ => fail("expected the wrong password to be refused")
  }
}
