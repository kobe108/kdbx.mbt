///|
/// `to_hex` / `bytes_from_hex` are the vocabulary of every other test here, so
/// they get checked first, against values taken from the specification.
test "hex helpers match the specification examples" {
  let bytes = hex_literal("31 c1 f2 e6 bf 71 43 50 be 58 05 21 6a fc 5a ff")
  assert_eq(bytes.length(), 16)
  assert_eq(to_hex(bytes), "31c1f2e6bf714350be5805216afc5aff")
  assert_eq(to_hex(hex_literal("0d0a0d0a")), "0d0a0d0a")
}

///|
/// Byte order is the single most error-prone part of a binary format, so the
/// little-endian specification example (`0x12345678`) is asserted directly.
test "integers are little-endian" {
  let out = ByteWriter::new()
  out.write_u32_le(0x12345678)
  assert_eq(to_hex(out.to_bytes()), "78563412")
  let reader = ByteReader::new(hex_literal("78563412"))
  assert_eq(reader.read_u32_le(), 0x12345678)
}

///|
/// Golden vector: the byte sequence of a two-item variant dictionary, written
/// out by hand from the `Variant Dictionary` section of the KDBX 4.1 spec.
test "variant dictionary encoding is byte-exact" {
  let dict = VariantDict::new()
  dict.set("S", VBytes(hex_literal("00010203")))
  dict.set("R", VUInt64(1000))
  // version 1.0 | byte-array value | name size | "S" | value size | value
  // | UInt64 value | name size | "R" | value size | 1000 (LE) | terminator
  let expected = "0001420100000053040000000001020305010000005208000000e80300000000000000"
  assert_eq(to_hex(encode_variant_dict(dict)), expected)
}

///|
test "variant dictionary round-trips through the wire format" {
  let dict = VariantDict::new()
  dict.set("$UUID", VBytes(hex_literal("c9d9f39a628a4460bf740d08c18a4fea")))
  dict.set("S", VBytes(hex_literal("00112233445566778899aabbccddeeff")))
  dict.set("R", VUInt64(6000000))
  dict.set("V", VUInt32(0x13))
  dict.set("bool", VBool(true))
  dict.set("name", VString("kdbx.mbt"))
  let decoded = decode_variant_dict(encode_variant_dict(dict))
  assert_eq(decoded.length(), 6)
  assert_eq(decoded.get_uint64("R"), Some(6000000))
  assert_eq(decoded.get_uint32("V"), Some(0x13))
  assert_eq(
    to_hex(decoded.get_bytes("$UUID").unwrap()),
    "c9d9f39a628a4460bf740d08c18a4fea",
  )
  assert_eq(decoded.get("bool").unwrap().to_text(), "true")
  assert_eq(decoded.get("name").unwrap().to_text(), "kdbx.mbt")
  // Re-encoding a decoded dictionary must reproduce the original bytes.
  assert_eq(
    to_hex(encode_variant_dict(decoded)),
    to_hex(encode_variant_dict(dict)),
  )
}

///|
/// Builds a minimal but spec-accurate KDBX 4.1 header. The helper is shared by
/// the header tests below.
fn sample_header() -> OuterHeader {
  let kdf = VariantDict::new()
  kdf.set("$UUID", VBytes(hex_literal("c9d9f39a628a4460bf740d08c18a4fea")))
  kdf.set("S", VBytes(hex_literal("00112233445566778899aabbccddeeff")))
  kdf.set("R", VUInt64(6000000))
  {
    version: 0x00040001,
    fields: [
      (cipher_field_id(), hex_literal("31c1f2e6bf714350be5805216afc5aff")),
      (field_compression, hex_literal("01000000")),
      (
        field_master_seed,
        hex_literal(
          "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        ),
      ),
      (field_encryption_iv, hex_literal("0f0e0d0c0b0a09080706050403020100")),
      (field_kdf_parameters, encode_variant_dict(kdf)),
    ],
    consumed: 0,
  }
}

///|
test "outer header round-trips and reports the right revision" {
  let encoded = sample_header().encode()
  let header = parse_outer_header(encoded)
  assert_eq(header.major(), 4)
  assert_eq(header.minor(), 1)
  assert_eq(header.revision(), "4.1")
  assert_eq(header.cipher().to_text(), "AES-256-CBC")
  assert_eq(header.cipher().iv_length(), 16)
  assert_eq(header.compression().to_text(), "gzip")
  assert_eq(header.master_seed().length(), 32)
  assert_eq(header.encryption_iv().length(), 16)
  assert_eq(header.kdf_parameters().get_uint64("R"), Some(6000000))
  // The parsed header must know its own length so that the caller can find the
  // header hash and the HMAC that follow it.
  assert_eq(header.consumed, encoded.length())
  assert_eq(to_hex(header.encode()), to_hex(encoded))
}

///|
/// The first bytes of a KDBX 4.1 file are fixed by the specification: the two
/// signature words and the version, all little-endian.
test "header prefix matches the specification" {
  let encoded = sample_header().encode()
  assert_eq(to_hex(encoded, limit=12), "03d9a29a67fb4bb501000400")
}

///|
test "truncated and foreign files are rejected with a typed error" {
  // A file that stops after the signature must be reported as truncated, not
  // as an out-of-bounds panic.
  try parse_outer_header(hex_literal("03d9a29a67fb4bb5")) catch {
    Truncated(_) => ()
    e => fail("expected Truncated, got: " + e.message())
  } noraise {
    _ => fail("expected a Truncated error")
  }
  // KeePass 1.x uses a different second signature word and is out of scope.
  try parse_outer_header(hex_literal("03d9a29a65fb4bb501000400")) catch {
    BadSignature => ()
    e => fail("expected BadSignature, got: " + e.message())
  } noraise {
    _ => fail("expected a BadSignature error")
  }
  // A future major revision must be rejected explicitly.
  try parse_outer_header(hex_literal("03d9a29a67fb4bb500000500")) catch {
    UnsupportedVersion(5) => ()
    e => fail("expected UnsupportedVersion(5), got: " + e.message())
  } noraise {
    _ => fail("expected an UnsupportedVersion error")
  }
}
