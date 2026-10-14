///|
/// Builds a byte buffer from a list of small integers, for readability in the
/// vectors below.
fn ints_to_bytes(values : Array[Int]) -> Bytes {
  let out = ByteWriter::new()
  for value in values {
    out.write_byte(value.reinterpret_as_uint() & 0xFF)
  }
  out.to_bytes()
}

///|
/// Builds a byte buffer where byte `i` is `(i * multiplier + offset) % 256`.
fn sequence_bytes(count : Int, multiplier : Int, offset : Int) -> Bytes {
  let out = ByteWriter::new()
  let mut i = 0
  while i < count {
    out.write_byte(((i * multiplier + offset) % 256).reinterpret_as_uint())
    i = i + 1
  }
  out.to_bytes()
}

///|
/// Multiplication in GF(2^8) modulo the AES polynomial `x^8+x^4+x^3+x+1`.
fn gf_multiply(a : UInt, b : UInt) -> UInt {
  let mut product : UInt = 0
  let mut left = a
  let mut right = b
  let mut bit = 0
  while bit < 8 {
    if (right & 1) != 0 {
      product = product ^ left
    }
    let high = left & 0x80
    left = (left << 1) & 0xFF
    if high != 0 {
      left = left ^ 0x1B
    }
    right = right >> 1
    bit = bit + 1
  }
  product
}

///|
/// Reproduces the AES S-box from its definition: the multiplicative inverse in
/// GF(2^8), followed by the affine transform.
fn reference_sbox() -> Array[Byte] {
  let table : Array[Byte] = []
  let mut value = 0
  while value < 256 {
    let mut inverse : UInt = 0
    if value != 0 {
      let mut candidate = 1
      let mut found = false
      while candidate < 256 && !found {
        if gf_multiply(
            value.reinterpret_as_uint(),
            candidate.reinterpret_as_uint(),
          ) ==
          1 {
          inverse = candidate.reinterpret_as_uint()
          found = true
        }
        candidate = candidate + 1
      }
    }
    let r1 = (inverse << 1) | (inverse >> 7)
    let r2 = (inverse << 2) | (inverse >> 6)
    let r3 = (inverse << 3) | (inverse >> 5)
    let r4 = (inverse << 4) | (inverse >> 4)
    let rotated = r1 ^ r2 ^ r3 ^ r4
    table.push(((inverse ^ rotated ^ 0x63) & 0xFF).to_byte())
    value = value + 1
  }
  table
}

///|
/// A whole-table comparison is deliberate: spot-checking five entries hid one
/// wrong value (index 0x1b) during development, while recomputing all 256
/// entries from the definition is what actually catches a transcription error.
test "aes s-box matches its definition and the published examples" {
  assert_eq(aes_sbox[0x00].to_uint(), 0x63)
  assert_eq(aes_sbox[0x01].to_uint(), 0x7C)
  assert_eq(aes_sbox[0x10].to_uint(), 0xCA)
  assert_eq(aes_sbox[0x53].to_uint(), 0xED)
  assert_eq(aes_sbox[0xFF].to_uint(), 0x16)
  let reference = reference_sbox()
  let mut index = 0
  let mut mismatches = 0
  while index < 256 {
    if aes_sbox[index] != reference[index] {
      mismatches = mismatches + 1
    }
    index = index + 1
  }
  assert_eq(mismatches, 0)
}

///|
/// FIPS-197 appendix C.3, the AES-256 example, plus further vectors produced
/// with .NET's implementation (ECB, no padding) as an independent reference.
test "aes256 encryption matches reference vectors" {
  let fips_key = sequence_bytes(32, 1, 0)
  let fips_block = hex_literal("00112233445566778899aabbccddeeff")
  assert_eq(
    to_hex(Aes256::new(fips_key).encrypt_block(fips_block)),
    "8ea2b7ca516745bfeafc49904b496089",
  )
  let zero_key = Aes256::new(sequence_bytes(32, 0, 0))
  assert_eq(
    to_hex(
      zero_key.encrypt_block(hex_literal("00000000000000000000000000000000")),
    ),
    "dc95c078a2408989ad48a21492842087",
  )
  assert_eq(
    to_hex(
      zero_key.encrypt_block(hex_literal("ffffffffffffffffffffffffffffffff")),
    ),
    "acdace8078a32b1a182bfa4987ca1347",
  )
  let ones_key = Aes256::new(
    hex_literal(
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ),
  )
  assert_eq(
    to_hex(
      ones_key.encrypt_block(hex_literal("00000000000000000000000000000000")),
    ),
    "4bf85f1b5d54adbc307b0a048389adcb",
  )
  assert_eq(
    to_hex(
      Aes256::new(sequence_bytes(32, 7, 1)).encrypt_block(
        sequence_bytes(16, 11, 3),
      ),
    ),
    "62477ec2d2279099f0ad2726d883a415",
  )
  let last_bit_key = ints_to_bytes([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 1,
  ])
  assert_eq(
    to_hex(
      Aes256::new(last_bit_key).encrypt_block(
        hex_literal("00000000000000000000000000000000"),
      ),
    ),
    "6b6cfe160a6263631b292f879eeff926",
  )
}

///|
/// A wrong key or block length must be reported, not silently padded.
test "aes256 rejects wrong input sizes" {
  try Aes256::new(hex_literal("00112233445566778899aabbccddeeff")) catch {
    Malformed(_) => ()
    e => fail("expected Malformed for a 16-byte key, got: " + e.message())
  } noraise {
    _ => fail("expected an error for a 16-byte key")
  }
  let cipher = Aes256::new(sequence_bytes(32, 1, 0))
  try cipher.encrypt_block(hex_literal("0011223344556677")) catch {
    Malformed(_) => ()
    e => fail("expected Malformed for an 8-byte block, got: " + e.message())
  } noraise {
    _ => fail("expected an error for an 8-byte block")
  }
}
