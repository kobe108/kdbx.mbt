///|
/// Incompressible bytes derived from SHA-256, the input of the stored-block
/// vector. Reproducible here, so the test needs no embedded plaintext.
fn sha_derived(count : Int) -> Bytes {
  let out = ByteWriter::new()
  let mut i = 0
  while i < count / 32 {
    let word = ByteWriter::new()
    word.write_u32_le(i.reinterpret_as_uint())
    out.write_bytes(sha256(word.to_bytes()))
    i = i + 1
  }
  out.to_bytes()
}

///|
/// The compressible sample: one line repeated, which makes the compressor emit
/// copy distances and (for longer inputs) dynamic Huffman codes.
fn text_repeated(count : Int) -> Bytes {
  let line = @utf8.encode("the quick brown fox jumps over the lazy dog ")
  let out = ByteWriter::new()
  let mut i = 0
  while i < count {
    out.write_bytes(line)
    i = i + 1
  }
  out.to_bytes()
}

///|
/// One vector per DEFLATE block type, all produced by zlib. The block type is
/// part of the vector's name because a stream that silently used a different
/// code path would give false confidence: the first byte of each stream is
/// asserted to carry the expected type.
test "inflate handles stored, fixed and dynamic blocks" {
  let stored = hex_literal(
    "010002fffddf3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b8111967abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa45026b25d457597a7b0463f9620f666dd10aa2c4373a505967c7c8d70922a2d6ece9d9f290527a6be626a8f5985b26e19b237b44872b03631811df4416fc1713178fb5e512425fc9449316ec95969ebe71e2d576dbab833d61e2a5b9330fd70ee022594b6a92ebfb1c3312deb7d01c015fb95e9fbe9bd7bc6b527af07813ec7b9107aa8ca4a02506da9133d8f889678b76f716ce45d02e22fdb7b70a15e56a0eff8e8613f5a5bc9f9feeda32a8e7c80b69dd4878e47b6a91723fb15eb84236b6a2bdc765660b06ee03dd16fd7ca5b957e8c805161ac2c4af28c5a100ab2ab432ca19f076b7eb7fdc0311cd3208cdbbebbf8014dd3a05e35191c96947b358a362b40075de2b906dbd7066da008cab735bee896370154603579a50122f9b88545bd45cb30e91817239109ffd0a5870046e128f04619da80c7624d921162fdfe514f7642f4aeb81c1ef81f771f3de8abca9dcf66901c575530e7672e4b1146474ae65043c66c260828c9839f26474151db105481ff92f5e01377f75389d4ce3d2dd57401b4f6bd5d6a06a7b74a8565ceb4f845afe0ae96a0ac05cf5e86066bf7b538ec972b8373b897c65c4f631c6bdf2443d0d817a88f224b54d8e593fdcf32488d60",
  )
  assert_eq((stored[0].to_uint() >> 1) & 0x03, 0)
  let (stored_plain, consumed) = inflate(stored, 0)
  assert_eq(to_hex(stored_plain), to_hex(sha_derived(512)))
  assert_eq(consumed, stored.length())

  let fixed = hex_literal(
    "2bc94855282ccd4cce56482aca2fcf5348cbaf50c82acd2d2856c82f4b2d5228014ae72456552aa4e4a78339a36a47d50e26b500",
  )
  assert_eq((fixed[0].to_uint() >> 1) & 0x03, 1)
  let (fixed_plain, _) = inflate(fixed, 0)
  assert_eq(to_hex(fixed_plain), to_hex(text_repeated(16)))

  let dynamic = hex_literal(
    "edcad90d80201405d1566e6b8a28ae0f11dcaad7d885c97c4ee6e4e0b596de8daa931d8b5a3b3594396eb2dd27e5774fd57da9b1ee0b2c168bc562b1582cf6cff601",
  )
  assert_eq((dynamic[0].to_uint() >> 1) & 0x03, 2)
  let (dynamic_plain, _) = inflate(dynamic, 0)
  assert_eq(to_hex(dynamic_plain), to_hex(text_repeated(64)))
  assert_eq(dynamic_plain.length(), 2816)
}

///|
/// Malformed streams must be refused rather than producing garbage.
test "malformed deflate streams are refused" {
  // Reserved block type 3.
  try inflate(hex_literal("07"), 0) catch {
    Malformed(message) => assert_true(message.contains("reserved"))
    e => fail("expected a reserved-type error, got: " + e.message())
  } noraise {
    _ => fail("expected a reserved block type to be refused")
  }
  // A stored block whose length and complement disagree.
  try inflate(hex_literal("0104000000aabbccdd"), 0) catch {
    Malformed(message) => assert_true(message.contains("complement"))
    e => fail("expected a complement error, got: " + e.message())
  } noraise {
    _ => fail("expected a mismatched stored block length to be refused")
  }
  // A stream that stops in the middle of a code.
  try inflate(hex_literal("2b"), 0) catch {
    Malformed(_) => ()
    e => fail("expected a truncation error, got: " + e.message())
  } noraise {
    _ => fail("expected a truncated stream to be refused")
  }
}

///|
/// The gzip container around the same data, plus its integrity trailer.
test "gzip streams are unwrapped and verified" {
  let stream = hex_literal(
    "1f8b080050f8d06a02ff4bcecf2d284a2d2e4e4d512848acccc94f4c5148cb2f5228c94855c84e49aad0cb4d2a5128492d2e51282ecd2c490500dfb47a5e2e000000",
  )
  let plain = gunzip(stream)
  assert_eq(
    to_hex(plain),
    to_hex(ascii_bytes("compressed payload for the kdbx.mbt test suite")),
  )
  // A corrupted trailer has to be caught: this is the only integrity check the
  // container itself provides.
  let corrupted = flip_byte(stream, stream.length() - 5)
  try gunzip(corrupted) catch {
    Malformed(message) => assert_true(message.contains("CRC"))
    e => fail("expected a CRC error, got: " + e.message())
  } noraise {
    _ => fail("expected a corrupted trailer to be refused")
  }
  try gunzip(hex_literal("1f8b0900")) catch {
    Malformed(message) => assert_true(message.contains("compression method"))
    e => fail("expected a method error, got: " + e.message())
  } noraise {
    _ => fail("expected an unknown compression method to be refused")
  }
  try gunzip(hex_literal("414243")) catch {
    Malformed(message) => assert_true(message.contains("magic"))
    e => fail("expected a magic error, got: " + e.message())
  } noraise {
    _ => fail("expected a non-gzip stream to be refused")
  }
}
