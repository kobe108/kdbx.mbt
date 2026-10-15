///|
/// A vault with two protected fields, encrypted the way KeePass does it: one
/// shared stream, consumed field by field. The ciphertext is produced with the
/// very ChaCha20 that the RFC vectors pin, so what is under test here is the
/// key/nonce convention, the base64 layer and the stream order.
fn protected_document(key : Bytes) -> String raise KdbxError {
  let stream = ChaCha20::new(
    Bytes::makei(32, fn(i) { key[i] }),
    Bytes::makei(12, fn(i) { key[32 + i] }),
    0,
  )
  // Both values come from the same running stream, in this order.
  let first = @base64.encode(stream.apply(@utf8.encode("hunter2")))
  let second = @base64.encode(stream.apply(@utf8.encode("second secret")))
  let document = StringBuilder()
  document.write_string(
    "<KeePassFile><Meta><Generator>test</Generator></Meta><Root><Group><UUID>g</UUID><Name>G</Name><Entry><UUID>e</UUID><String><Key>Title</Key><Value>Plain</Value></String><String><Key>Password</Key><Value Protected='True'>",
  )
  document.write_string(first)
  document.write_string(
    "</Value></String><String><Key>Notes</Key><Value Protected='True'>",
  )
  document.write_string(second)
  document.write_string(
    "</Value></String></Entry></Group></Root></KeePassFile>",
  )
  document.to_string()
}

///|
fn inner_key() -> Bytes {
  sequence_bytes(64, 1, 0)
}

///|
/// An inner header that names ChaCha20 and carries the given key.
fn inner_header_with(key : Bytes) -> InnerHeader raise KdbxError {
  let payload = ByteWriter::new()
  payload.write_byte(1)
  payload.write_u32_le(4)
  payload.write_u32_le(3)
  payload.write_byte(2)
  payload.write_u32_le(key.length().reinterpret_as_uint())
  payload.write_bytes(key)
  payload.write_byte(0)
  split_payload(payload.to_bytes()).0
}

///|
/// Both protected values decrypt to their plaintext, which only holds if the
/// stream is shared and consumed in document order.
test "protected fields decrypt with the shared stream" {
  let key = inner_key()
  let vault = parse_vault(protected_document(key))
  assert_true(vault.entries()[0].1.fields()[1].is_protected())
  let opened = unprotect_vault(vault, inner_header_with(key))
  let fields = opened.entries()[0].1.fields()
  assert_eq(fields[0].value(), "Plain")
  assert_eq(fields[1].value(), "hunter2")
  assert_eq(fields[2].value(), "second secret")
  // The flag is cleared once the value really is plaintext.
  assert_true(!fields[1].is_protected())
}

///|
/// A key that is too short to feed the cipher must be refused rather than
/// producing garbage.
test "unsupported inner streams are refused" {
  let vault = parse_vault(protected_document(inner_key()))
  try
    unprotect_vault(vault, inner_header_with(sequence_bytes(16, 1, 0)))
  catch {
    Malformed(message) => assert_true(message.contains("44 bytes"))
    e => fail("expected a key length error, got: " + e.message())
  } noraise {
    _ => fail("expected a short inner key to be refused")
  }
}
