///|
/// A vault with two protected fields, encrypted the way KeePass does it: one
/// shared stream, consumed field by field. The ciphertext is produced with the
/// very ChaCha20 that the RFC vectors pin, so what is under test here is the
/// key/nonce convention, the base64 layer and the stream order.
fn protected_document(key : Bytes) -> String raise KdbxError {
  // The cipher inputs are derived from the random key, not taken from it.
  let derived = sha512(key)
  let stream = ChaCha20::new(
    Bytes::makei(32, fn(i) { derived[i] }),
    Bytes::makei(12, fn(i) { derived[32 + i] }),
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
fn inner_header_with(
  key : Bytes,
  stream_id : UInt,
) -> InnerHeader raise KdbxError {
  let payload = ByteWriter::new()
  payload.write_byte(1)
  payload.write_u32_le(4)
  payload.write_u32_le(stream_id)
  payload.write_byte(2)
  payload.write_u32_le(key.length().reinterpret_as_uint())
  payload.write_bytes(key)
  payload.write_byte(0)
  split_payload(payload.to_bytes(), 1).0
}

///|
/// Both protected values decrypt to their plaintext, which only holds if the
/// stream is shared and consumed in document order.
test "protected fields decrypt with the shared stream" {
  let key = inner_key()
  let vault = parse_vault(protected_document(key))
  assert_true(vault.entries()[0].1.fields()[1].is_protected())
  let opened = unprotect_vault(vault, inner_header_with(key, 3))
  let fields = opened.entries()[0].1.fields()
  assert_eq(fields[0].value(), "Plain")
  assert_eq(fields[1].value(), "hunter2")
  assert_eq(fields[2].value(), "second secret")
  // The flag is cleared once the value really is plaintext.
  // Decryption must not erase the sensitivity marker: a CLI that prints every
  // field by default would otherwise leak the password it just decrypted.
  assert_true(fields[1].is_protected())
}

///|
/// A stream this build does not implement must be refused with a clear message.
test "unsupported inner streams are refused" {
  let vault = parse_vault(protected_document(inner_key()))
  try unprotect_vault(vault, inner_header_with(inner_key(), 9)) catch {
    Unsupported(message) => assert_true(message.contains("9"))
    e => fail("expected an unsupported error, got: " + e.message())
  } noraise {
    _ => fail("expected an unknown inner stream to be refused")
  }
}
