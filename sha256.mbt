///|
/// SHA-256 (FIPS 180-4).
///
/// KDBX needs SHA-256 in three places: the header integrity hash, the
/// composite master key, and HMAC-SHA-256. The implementation is one-shot and
/// deliberately direct, because the digest has to be verifiable against
/// published test vectors rather than clever.
pub fn sha256(data : Bytes) -> Bytes {
  let padded = sha256_pad(data)
  let state : Array[UInt] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
    0x5be0cd19,
  ]
  let mut offset = 0
  while offset < padded.length() {
    sha256_compress(state, padded, offset)
    offset = offset + 64
  }
  let out = ByteWriter::new()
  for i = 0; i < 8; i = i + 1 {
    out.write_u32_be(state[i])
  }
  out.to_bytes()
}

///|
/// SHA-256 round constants: the first 32 bits of the fractional parts of the
/// cube roots of the first 64 primes (FIPS 180-4, section 4.2.2).
let sha256_k : Array[UInt] = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
  0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
  0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
  0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
  0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
  0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
  0xc67178f2,
]

///|
/// Rotate a 32-bit word right by `bits` (1..31).
fn rotr32(word : UInt, bits : Int) -> UInt {
  (word >> bits) | (word << (32 - bits))
}

///|
/// Pads a message to a multiple of 64 bytes: a `1` bit, zeros, and the message
/// length in bits as a 64-bit big-endian integer.
fn sha256_pad(data : Bytes) -> Array[Byte] {
  let out : Array[Byte] = []
  for i = 0; i < data.length(); i = i + 1 {
    out.push(data[i])
  }
  out.push(0x80)
  while out.length() % 64 != 56 {
    out.push(0)
  }
  let bits = UInt64::extend_uint(data.length().reinterpret_as_uint()) * 8
  let length_writer = ByteWriter::new()
  length_writer.write_u64_be(bits)
  for i = 0; i < 8; i = i + 1 {
    out.push(length_writer.chunks[i])
  }
  out
}

///|
/// Processes one 64-byte block, updating the eight working words in place.
fn sha256_compress(
  state : Array[UInt],
  block : Array[Byte],
  offset : Int,
) -> Unit {
  let w : Array[UInt] = []
  let mut i = 0
  while i < 16 {
    let base = offset + i * 4
    let word = (block[base].to_uint() << 24) |
      (block[base + 1].to_uint() << 16) |
      (block[base + 2].to_uint() << 8) |
      block[base + 3].to_uint()
    w.push(word)
    i = i + 1
  }
  while i < 64 {
    let s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3)
    let s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10)
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
  while round < 64 {
    let s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)
    let ch = (e & f) ^ (e.lnot() & g)
    let temp1 = h + s1 + ch + sha256_k[round] + w[round]
    let s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)
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
