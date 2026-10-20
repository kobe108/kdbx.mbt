///|
/// BLAKE2b (RFC 7693), unkeyed with a configurable digest length.
///
/// Argon2 is built on it: the pre-hashing digest, the variable-length hash and
/// the block permutation all use BLAKE2b, so it is implemented first and pinned
/// by the RFC vector before Argon2 is written on top of it.

///|
let blake2b_iv : Array[UInt64] = [
  0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
  0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
]

///|
/// The message-word permutation, ten rows used cyclically over twelve rounds.
let blake2b_sigma : Array[Array[Int]] = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
]

///|
/// Hashes `data` and returns the first `out_len` bytes of the digest.
pub fn blake2b(data : Bytes, out_len : Int) -> Bytes raise KdbxError {
  if out_len < 1 || out_len > 64 {
    raise Malformed(
      "BLAKE2b digest length must be 1..64, got " + out_len.to_string(),
    )
  }
  let state = blake2b_iv.copy()
  // Parameter block: digest length, no key, fanout 1, depth 1.
  state[0] = state[0] ^ (0x01010000 ^ out_len.to_uint64())
  let total = data.length()
  let mut offset = 0
  // Every block except the last is compressed with the "not final" flag.
  while offset + 128 < total {
    let block = block_of(data, offset, 128)
    blake2b_compress(state, block, (offset + 128).to_uint64(), false)
    offset = offset + 128
  }
  let remaining = total - offset
  let block = block_of(data, offset, remaining)
  blake2b_compress(state, block, total.to_uint64(), true)
  let out = ByteWriter::new()
  for i = 0; i < 8; i = i + 1 {
    out.write_u64_le(state[i])
  }
  let digest = out.to_bytes()
  Bytes::makei(out_len, fn(i) { digest[i] })
}

///|
/// Builds a 128-byte block from `length` bytes at `offset`, zero padded.
fn block_of(data : Bytes, offset : Int, length : Int) -> Array[Byte] {
  let block : Array[Byte] = []
  let mut i = 0
  while i < 128 {
    block.push(if i < length { data[offset + i] } else { 0 })
    i = i + 1
  }
  block
}

///|
fn blake2b_compress(
  state : Array[UInt64],
  block : Array[Byte],
  counter : UInt64,
  last : Bool,
) -> Unit raise KdbxError {
  let message : Array[UInt64] = []
  let block_bytes = Bytes::from_array(block)
  let mut i = 0
  while i < 16 {
    message.push(read_u64_le(block_bytes, i * 8))
    i = i + 1
  }
  let v = state.copy()
  for word in blake2b_iv {
    v.push(word)
  }
  v[12] = v[12] ^ counter
  if last {
    v[14] = v[14].lnot()
  }
  let mut round = 0
  while round < 12 {
    let s = blake2b_sigma[round % 10]
    blake2b_mix(v, 0, 4, 8, 12, message[s[0]], message[s[1]])
    blake2b_mix(v, 1, 5, 9, 13, message[s[2]], message[s[3]])
    blake2b_mix(v, 2, 6, 10, 14, message[s[4]], message[s[5]])
    blake2b_mix(v, 3, 7, 11, 15, message[s[6]], message[s[7]])
    blake2b_mix(v, 0, 5, 10, 15, message[s[8]], message[s[9]])
    blake2b_mix(v, 1, 6, 11, 12, message[s[10]], message[s[11]])
    blake2b_mix(v, 2, 7, 8, 13, message[s[12]], message[s[13]])
    blake2b_mix(v, 3, 4, 9, 14, message[s[14]], message[s[15]])
    round = round + 1
  }
  i = 0
  while i < 8 {
    state[i] = state[i] ^ v[i] ^ v[i + 8]
    i = i + 1
  }
}

///|
fn blake2b_mix(
  v : Array[UInt64],
  a : Int,
  b : Int,
  c : Int,
  d : Int,
  x : UInt64,
  y : UInt64,
) -> Unit {
  v[a] = v[a] + v[b] + x
  v[d] = rotate_right_64(v[d] ^ v[a], 32)
  v[c] = v[c] + v[d]
  v[b] = rotate_right_64(v[b] ^ v[c], 24)
  v[a] = v[a] + v[b] + y
  v[d] = rotate_right_64(v[d] ^ v[a], 16)
  v[c] = v[c] + v[d]
  v[b] = rotate_right_64(v[b] ^ v[c], 63)
}

///|
fn rotate_right_64(value : UInt64, bits : Int) -> UInt64 {
  (value >> bits) | (value << (64 - bits))
}

///|
fn read_u64_le(data : Bytes, offset : Int) -> UInt64 raise KdbxError {
  if offset < 0 || offset + 8 > data.length() {
    raise Truncated("not enough bytes for a 64-bit word")
  }
  let slice = Bytes::makei(8, fn(i) { data[offset + i] })
  ByteReader::new(slice).read_u64_le()
}
