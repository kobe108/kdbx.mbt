///|
/// Turns an ASCII literal into bytes, so the published vectors below can be
/// written as the text they actually are instead of as hand-expanded hex.
fn ascii_bytes(text : String) -> Bytes {
  let out = ByteWriter::new()
  let mut i = 0
  while i < text.length() {
    out.write_byte(text[i].to_uint() & 0xFF)
    i = i + 1
  }
  out.to_bytes()
}

///|
/// FIPS 180-4 / NIST example vectors. These are published digests, so a failure
/// here means the implementation is wrong, not that the vector needs updating.
test "sha256 matches published vectors" {
  assert_eq(
    to_hex(sha256(ascii_bytes(""))),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  )
  assert_eq(
    to_hex(sha256(ascii_bytes("abc"))),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  )
  // 56 bytes: exercises a second block plus the padding length field.
  assert_eq(
    to_hex(
      sha256(
        ascii_bytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
      ),
    ),
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
  )
}

///|
/// A message of 1,000,000 bytes: the long-message vector from FIPS 180-4.
test "sha256 handles long messages" {
  let out = ByteWriter::new()
  let mut i = 0
  while i < 1000000 {
    out.write_byte(0x61)
    i = i + 1
  }
  assert_eq(
    to_hex(sha256(out.to_bytes())),
    "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
  )
}

///|
/// RFC 4231 test cases 1, 2, 4 and 6 for HMAC-SHA-256. Case 6 uses a key longer
/// than the 64-byte block size, which must be hashed before use.
test "hmac-sha256 matches RFC 4231 vectors" {
  assert_eq(
    to_hex(hmac_sha256(bytes_repeated(0x0B, 20), ascii_bytes("Hi There"))),
    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
  )
  assert_eq(
    to_hex(
      hmac_sha256(
        ascii_bytes("Jefe"),
        ascii_bytes("what do ya want for nothing?"),
      ),
    ),
    "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
  )
  assert_eq(
    to_hex(
      hmac_sha256(
        hex_literal("0102030405060708090a0b0c0d0e0f10111213141516171819"),
        bytes_repeated(0xCD, 50),
      ),
    ),
    "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
  )
  assert_eq(
    to_hex(
      hmac_sha256(
        bytes_repeated(0xAA, 131),
        ascii_bytes("Test Using Larger Than Block-Size Key - Hash Key First"),
      ),
    ),
    "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
  )
}

///|
/// FIPS 180-4 SHA-512 vectors, including a 112-byte message that fills two
/// blocks and the standard one-million-byte message.
test "sha512 matches published vectors" {
  assert_eq(
    to_hex(sha512(ascii_bytes(""))),
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
  )
  assert_eq(
    to_hex(sha512(ascii_bytes("abc"))),
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
  )
  let two_block = ascii_bytes(
    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
  )
  assert_eq(two_block.length(), 112)
  assert_eq(
    to_hex(sha512(two_block)),
    "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
  )
  assert_eq(
    to_hex(sha512(bytes_repeated(0x61, 1000000))),
    "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
  )
}

///|
/// Builds a byte buffer of `count` copies of one value, used by the vectors
/// above whose keys and messages are a single repeated byte.
fn bytes_repeated(value : UInt, count : Int) -> Bytes {
  let out = ByteWriter::new()
  let mut i = 0
  while i < count {
    out.write_byte(value)
    i = i + 1
  }
  out.to_bytes()
}
