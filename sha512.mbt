///|
/// SHA-512 (FIPS 180-4).
///
/// KDBX derives its HMAC keys from SHA-512, so this digest is needed before any
/// file can be authenticated. The constant tables below are generated from the
/// definition in FIPS 180-4 (fractional parts of the cube roots of the first 80
/// primes) rather than transcribed by hand; see `docs/ROADMAP.md`.
pub fn sha512(data : Bytes) -> Bytes {
  let padded = sha512_pad(data)
  let state : Array[UInt64] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
  ]
  let mut offset = 0
  while offset < padded.length() {
    sha512_compress(state, padded, offset)
    offset = offset + 128
  }
  let out = ByteWriter::new()
  for i = 0; i < 8; i = i + 1 {
    out.write_u64_be(state[i])
  }
  out.to_bytes()
}

///|
/// SHA-512 round constants: the first 64 bits of the fractional parts of the
/// cube roots of the first 80 primes (FIPS 180-4, section 4.2.3).
let sha512_k : Array[UInt64] = [
  0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
  0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
  0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
  0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
  0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
  0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
  0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
  0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
  0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
  0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
  0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
  0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
  0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
  0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
  0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
  0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
  0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
  0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
  0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
  0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
]

///|
/// Rotate a 64-bit word right by `bits` (1..63).
fn rotr64(word : UInt64, bits : Int) -> UInt64 {
  (word >> bits) | (word << (64 - bits))
}

///|
/// Pads a message to a multiple of 128 bytes: a `1` bit, zeros, and the message
/// length in bits as a 128-bit big-endian integer.
fn sha512_pad(data : Bytes) -> Array[Byte] {
  let out : Array[Byte] = []
  for i = 0; i < data.length(); i = i + 1 {
    out.push(data[i])
  }
  out.push(0x80)
  while out.length() % 128 != 112 {
    out.push(0)
  }
  let bits = UInt64::extend_uint(data.length().reinterpret_as_uint()) * 8
  // The high 64 bits stay zero: this library never hashes a 2^61-bit message.
  let mut high_index = 0
  while high_index < 8 {
    out.push(0)
    high_index = high_index + 1
  }
  let length_writer = ByteWriter::new()
  length_writer.write_u64_be(bits)
  for i = 0; i < 8; i = i + 1 {
    out.push(length_writer.chunks[i])
  }
  out
}

///|
/// Processes one 128-byte block, updating the eight working words in place.
fn sha512_compress(
  state : Array[UInt64],
  block : Array[Byte],
  offset : Int,
) -> Unit {
  let w : Array[UInt64] = []
  let mut i = 0
  while i < 16 {
    let base = offset + i * 8
    let mut word : UInt64 = 0
    let mut j = 0
    while j < 8 {
      word = (word << 8) | block[base + j].to_uint64()
      j = j + 1
    }
    w.push(word)
    i = i + 1
  }
  while i < 80 {
    let x = w[i - 15]
    let y = w[i - 2]
    let s0 = rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> 7)
    let s1 = rotr64(y, 19) ^ rotr64(y, 61) ^ (y >> 6)
    w.push(w[i - 16] + s0 + w[i - 7] + s1)
    i = i + 1
  }
  let mut a = state[0]
  let mut b = state[1]
  let mut c = state[2]
  let mut d = state[3]
  let mut e = state[4]
  let mut f = state[5]
  let mut g = state[6]
  let mut h = state[7]
  let mut round = 0
  while round < 80 {
    let s1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41)
    let ch = (e & f) ^ (e.lnot() & g)
    let temp1 = h + s1 + ch + sha512_k[round] + w[round]
    let s0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39)
    let maj = (a & b) ^ (a & c) ^ (b & c)
    let temp2 = s0 + maj
    h = g
    g = f
    f = e
    e = d + temp1
    d = c
    c = b
    b = a
    a = temp1 + temp2
    round = round + 1
  }
  state[0] = state[0] + a
  state[1] = state[1] + b
  state[2] = state[2] + c
  state[3] = state[3] + d
  state[4] = state[4] + e
  state[5] = state[5] + f
  state[6] = state[6] + g
  state[7] = state[7] + h
}
