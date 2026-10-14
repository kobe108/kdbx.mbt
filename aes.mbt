///|
/// AES-256 block cipher (FIPS-197), encryption direction.
///
/// KDBX needs AES-256 twice: in CBC mode for the database body, and inside
/// AES-KDF, which re-encrypts the same 16-byte block millions of times. This
/// module therefore keeps the hot path table-driven and allocation-free.
///
/// Only encryption is implemented here; the decryption direction arrives with
/// CBC in the next milestone (see docs/ROADMAP.md, F9).

///|
/// The AES substitution box, generated from its definition (multiplicative
/// inverse in GF(2^8) followed by the affine transform) instead of being
/// transcribed by hand. `docs/ROADMAP.md` records how it is produced.
let aes_sbox : Array[Byte] = [
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
  0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf,
  0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5,
  0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
  0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e,
  0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
  0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef,
  0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff,
  0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d,
  0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
  0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
  0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5,
  0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e,
  0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
  0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55,
  0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
  0xb0, 0x54, 0xbb, 0x16,
]

///|
/// Round constants for AES-256 key expansion. With an eight-word key, a round
/// constant is consumed every eighth word, so only the first seven are needed.
let aes_rcon : Array[Byte] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40]

///|
/// AES-256 rounds; the key schedule holds `14 + 1` round keys of 16 bytes.
let aes256_rounds : Int = 14

///|
/// An AES-256 key schedule: the expanded round keys, four bytes per word and
/// four words per round, in column-major order as in FIPS-197.
pub struct Aes256 {
  round_keys : Array[Byte]
}

///|
/// Expands a 32-byte key into the AES-256 key schedule (FIPS-197, section 5.2).
pub fn Aes256::new(key : Bytes) -> Aes256 raise KdbxError {
  if key.length() != 32 {
    raise Malformed(
      "AES-256 needs a 32-byte key, got " + key.length().to_string(),
    )
  }
  let words : Array[Byte] = []
  for i = 0; i < 32; i = i + 1 {
    words.push(key[i])
  }
  let total_words = 4 * (aes256_rounds + 1)
  let mut index = 8
  while index < total_words {
    let base = index * 4
    let previous = base - 4
    if index % 8 == 0 {
      // temp = SubWord(RotWord(temp)) xor Rcon[index / 8]
      let rotated = [
        words[previous + 1],
        words[previous + 2],
        words[previous + 3],
        words[previous],
      ]
      let substituted = [
        aes_sbox[rotated[0].to_uint().reinterpret_as_int()],
        aes_sbox[rotated[1].to_uint().reinterpret_as_int()],
        aes_sbox[rotated[2].to_uint().reinterpret_as_int()],
        aes_sbox[rotated[3].to_uint().reinterpret_as_int()],
      ]
      let round_constant = aes_rcon[index / 8 - 1].to_uint()
      for j = 0; j < 4; j = j + 1 {
        let temp = if j == 0 {
          substituted[j].to_uint() ^ round_constant
        } else {
          substituted[j].to_uint()
        }
        let origin = base - 32 + j
        words.push((words[origin].to_uint() ^ temp).to_byte())
      }
    } else if index % 8 == 4 {
      // temp = SubWord(temp)
      for j = 0; j < 4; j = j + 1 {
        let substituted = aes_sbox[words[previous + j]
          .to_uint()
          .reinterpret_as_int()]
        words.push(
          (words[base - 32 + j].to_uint() ^ substituted.to_uint()).to_byte(),
        )
      }
    } else {
      for j = 0; j < 4; j = j + 1 {
        words.push(
          (words[base - 32 + j].to_uint() ^ words[previous + j].to_uint()).to_byte(),
        )
      }
    }
    index = index + 1
  }
  { round_keys: words, }
}

///|
/// Encrypts one 16-byte block (FIPS-197, section 5.1).
pub fn Aes256::encrypt_block(
  self : Aes256,
  block : Bytes,
) -> Bytes raise KdbxError {
  if block.length() != 16 {
    raise Malformed(
      "AES blocks are 16 bytes, got " + block.length().to_string(),
    )
  }
  let buffer : Array[Byte] = []
  for i = 0; i < 16; i = i + 1 {
    buffer.push(block[i])
  }
  self.encrypt_in_place(buffer, 0, zero_bytes(16))
  Bytes::from_array(buffer)
}

///|
/// Encrypts the 16 bytes at `offset` in place.
///
/// AES-KDF applies this transformation millions of times, so the caller brings
/// its own `scratch` buffer (16 bytes) and the inner loop allocates nothing.
pub fn Aes256::encrypt_in_place(
  self : Aes256,
  buffer : Array[Byte],
  offset : Int,
  scratch : Array[Byte],
) -> Unit raise KdbxError {
  if offset < 0 || offset + 16 > buffer.length() {
    raise Malformed(
      "AES block at offset \{offset} does not fit in a \{buffer.length()}-byte buffer",
    )
  }
  if scratch.length() < 16 {
    raise Malformed(
      "AES scratch buffer must hold 16 bytes, got \{scratch.length()}",
    )
  }
  add_round_key(buffer, offset, self.round_keys, 0)
  let mut round = 1
  while round < aes256_rounds {
    sub_bytes(buffer, offset)
    shift_rows(buffer, offset, scratch)
    mix_columns(buffer, offset)
    add_round_key(buffer, offset, self.round_keys, round)
    round = round + 1
  }
  sub_bytes(buffer, offset)
  shift_rows(buffer, offset, scratch)
  add_round_key(buffer, offset, self.round_keys, aes256_rounds)
}

///|
/// A zero-filled byte buffer of `count` bytes.
fn zero_bytes(count : Int) -> Array[Byte] {
  let out : Array[Byte] = []
  let mut i = 0
  while i < count {
    out.push(0)
    i = i + 1
  }
  out
}

///|
/// XORs the block at `offset` with the round key of `round` (column-major word
/// order, as in FIPS-197).
fn add_round_key(
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
fn sub_bytes(buffer : Array[Byte], offset : Int) -> Unit {
  for i = 0; i < 16; i = i + 1 {
    buffer[offset + i] = aes_sbox[buffer[offset + i]
      .to_uint()
      .reinterpret_as_int()]
  }
}

///|
/// Rotates each row left by its row index. The state is column-major, so row `r`
/// owns the indices `r, r + 4, r + 8, r + 12` of the block; `scratch` holds the
/// copy the rotation reads from.
fn shift_rows(
  buffer : Array[Byte],
  offset : Int,
  scratch : Array[Byte],
) -> Unit {
  for i = 0; i < 16; i = i + 1 {
    scratch[i] = buffer[offset + i]
  }
  let mut row = 1
  while row < 4 {
    let mut column = 0
    while column < 4 {
      buffer[offset + row + 4 * column] = scratch[row + 4 * ((column + row) % 4)]
      column = column + 1
    }
    row = row + 1
  }
}

///|
/// Mixes each column independently (FIPS-197, section 5.1.3).
fn mix_columns(buffer : Array[Byte], offset : Int) -> Unit {
  let mut column = 0
  while column < 4 {
    let base = offset + column * 4
    let a0 = buffer[base].to_uint()
    let a1 = buffer[base + 1].to_uint()
    let a2 = buffer[base + 2].to_uint()
    let a3 = buffer[base + 3].to_uint()
    buffer[base] = (xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3).to_byte()
    buffer[base + 1] = (a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3).to_byte()
    buffer[base + 2] = (a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3)).to_byte()
    buffer[base + 3] = (xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3)).to_byte()
    column = column + 1
  }
}

///|
/// Multiplication by two in GF(2^8) modulo the AES polynomial `x^8+x^4+x^3+x+1`.
fn xtime(value : UInt) -> UInt {
  let shifted = (value << 1) & 0xFF
  if (value & 0x80) != 0 {
    shifted ^ 0x1B
  } else {
    shifted
  }
}
