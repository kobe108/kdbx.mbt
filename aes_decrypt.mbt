///|
/// AES-256 in the decryption direction (FIPS-197, section 5.3).
///
/// The inverse cipher is the forward one read backwards: the round keys are
/// applied in reverse order, and SubBytes, ShiftRows and MixColumns are replaced
/// by their inverses. Decryption happens once per file, so this side favours
/// obviousness over speed — the millions of rounds live in AES-KDF, which only
/// ever encrypts.
pub struct Aes256Decrypt {
  round_keys : Array[Byte]
  inverse_sbox : Array[Byte]
}

///|
pub fn Aes256Decrypt::new(key : Bytes) -> Aes256Decrypt raise KdbxError {
  let schedule = Aes256::new(key)
  { round_keys: schedule.round_keys, inverse_sbox: build_inverse_sbox(), }
}

///|
/// Builds the inverse S-box from the forward one, so the two cannot drift apart:
/// `inverse[sbox[i]] = i` by construction.
pub fn build_inverse_sbox() -> Array[Byte] {
  let table : Array[Byte] = []
  let mut i = 0
  while i < 256 {
    table.push(0)
    i = i + 1
  }
  let mut value = 0
  while value < 256 {
    table[aes_sbox[value].to_uint().reinterpret_as_int()] = value.to_byte()
    value = value + 1
  }
  table
}

///|
/// Decrypts the 16 bytes at `offset` in place.
pub fn Aes256Decrypt::decrypt_in_place(
  self : Aes256Decrypt,
  buffer : Array[Byte],
  offset : Int,
) -> Unit raise KdbxError {
  if offset < 0 || offset + 16 > buffer.length() {
    raise Malformed(
      "AES block at offset \{offset} does not fit in a \{buffer.length()}-byte buffer",
    )
  }
  inverse_add_round_key(buffer, offset, self.round_keys, aes256_rounds)
  inverse_shift_rows(buffer, offset)
  inverse_sub_bytes(buffer, offset, self.inverse_sbox)
  let mut round = aes256_rounds - 1
  while round >= 1 {
    inverse_add_round_key(buffer, offset, self.round_keys, round)
    inverse_mix_columns(buffer, offset)
    inverse_shift_rows(buffer, offset)
    inverse_sub_bytes(buffer, offset, self.inverse_sbox)
    round = round - 1
  }
  inverse_add_round_key(buffer, offset, self.round_keys, 0)
}

///|
fn inverse_add_round_key(
  buffer : Array[Byte],
  offset : Int,
  round_keys : Array[Byte],
  round : Int,
) -> Unit {
  let key_offset = round * 16
  for i = 0; i < 16; i = i + 1 {
    buffer[offset + i] = (buffer[offset + i].to_uint() ^
    round_keys[key_offset + i].to_uint()).to_byte()
  }
}

///|
fn inverse_sub_bytes(
  buffer : Array[Byte],
  offset : Int,
  inverse_sbox : Array[Byte],
) -> Unit {
  for i = 0; i < 16; i = i + 1 {
    buffer[offset + i] = inverse_sbox[buffer[offset + i]
      .to_uint()
      .reinterpret_as_int()]
  }
}

///|
/// Inverse of ShiftRows: row `r` is rotated right by `r`.
fn inverse_shift_rows(buffer : Array[Byte], offset : Int) -> Unit {
  let first = buffer[offset + 13]
  buffer[offset + 13] = buffer[offset + 9]
  buffer[offset + 9] = buffer[offset + 5]
  buffer[offset + 5] = buffer[offset + 1]
  buffer[offset + 1] = first
  let second = buffer[offset + 2]
  let sixth = buffer[offset + 6]
  buffer[offset + 2] = buffer[offset + 10]
  buffer[offset + 6] = buffer[offset + 14]
  buffer[offset + 10] = second
  buffer[offset + 14] = sixth
  let last = buffer[offset + 3]
  buffer[offset + 3] = buffer[offset + 7]
  buffer[offset + 7] = buffer[offset + 11]
  buffer[offset + 11] = buffer[offset + 15]
  buffer[offset + 15] = last
}

///|
/// Inverse of MixColumns: multiplies each column by the inverse matrix
/// (`0e, 0b, 0d, 09` in FIPS-197 section 5.3.3).
fn inverse_mix_columns(buffer : Array[Byte], offset : Int) -> Unit {
  let mut column = 0
  while column < 4 {
    let base = offset + column * 4
    let a0 = buffer[base].to_uint()
    let a1 = buffer[base + 1].to_uint()
    let a2 = buffer[base + 2].to_uint()
    let a3 = buffer[base + 3].to_uint()
    buffer[base] = (multiply(a0, 14) ^
    multiply(a1, 11) ^
    multiply(a2, 13) ^
    multiply(a3, 9)).to_byte()
    buffer[base + 1] = (multiply(a0, 9) ^
    multiply(a1, 14) ^
    multiply(a2, 11) ^
    multiply(a3, 13)).to_byte()
    buffer[base + 2] = (multiply(a0, 13) ^
    multiply(a1, 9) ^
    multiply(a2, 14) ^
    multiply(a3, 11)).to_byte()
    buffer[base + 3] = (multiply(a0, 11) ^
    multiply(a1, 13) ^
    multiply(a2, 9) ^
    multiply(a3, 14)).to_byte()
    column = column + 1
  }
}

///|
/// Multiplication in GF(2^8) by a small constant. Written as the schoolbook
/// shift-and-xor loop because the inverse cipher runs once per file.
fn multiply(value : UInt, constant : Int) -> UInt {
  let mut result : UInt = 0
  let mut left = value
  let mut bits = constant
  while bits != 0 {
    if (bits & 1) != 0 {
      result = result ^ left
    }
    left = xtime(left)
    bits = bits >> 1
  }
  result
}
