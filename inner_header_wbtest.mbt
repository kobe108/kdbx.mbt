///|
/// The fixture's payload begins with the inner header the generator wrote: a
/// ChaCha20 stream identifier (3), a 64-byte stream key and a terminator,
/// followed by the XML document.
test "the inner header of the fixture parses into structure" {
  let (header, xml) = split_payload(expected_payload(), 1)
  assert_eq(header.random_stream_id(), 3)
  assert_eq(header.random_stream_key().length(), 64)
  assert_eq(
    to_hex(header.random_stream_key()),
    to_hex(sequence_bytes(64, 1, 0)),
  )
  assert_eq(header.binaries().length(), 0)
  assert_eq(header.byte_length(), 79)
  assert_eq(to_hex(Bytes::makei(5, fn(i) { xml[i] })), "3c4b656550")
  assert_eq(xml.length(), expected_payload().length() - 79)
}

///|
/// A stream that ends before the terminator, and one whose terminator carries a
/// payload, are both malformed.
test "malformed inner headers are reported" {
  try split_payload(hex_literal("010400000003000000"), 1) catch {
    Truncated(_) => ()
    e => fail("expected a Truncated error, got: " + e.message())
  } noraise {
    _ => fail("expected a stream without a terminator to be rejected")
  }
  try split_payload(hex_literal("0103000000030000"), 1) catch {
    Malformed(message) => assert_true(message.contains("4-byte"))
    e => fail("expected a Malformed error, got: " + e.message())
  } noraise {
    _ => fail("expected a short stream identifier to be rejected")
  }
}

///|
/// Unknown fields are skipped, so a file with a newer field still reads.
test "unknown inner header fields are skipped" {
  // stream id 3, an unknown field 0x7f with three bytes, then the terminator.
  let (header, rest) = split_payload(
    hex_literal("0104000000030000007f03000000aabbcc00"),
    1,
  )
  assert_eq(header.random_stream_id(), 3)
  assert_eq(rest.length(), 0)
  assert_eq(header.byte_length(), 18)
}
