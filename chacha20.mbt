///|
/// ChaCha20 (RFC 8439), the cipher behind the inner random stream that protects
/// individual fields in a KDBX 4 file.
///
/// The stream is *shared*: KeePass derives one keystream from the key in the
/// inner header and consumes it field by field, in document order. So this type
/// is stateful — applying it to the fields in the wrong order yields plausible
/// but wrong plaintext.

///|
/// The ChaCha state constants, the ASCII string "expand 32-byte k".
let chacha_constants : Array[UInt] = [
  0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
]

///|
pub struct ChaCha20 {
  /// The original state: constants, key, counter, nonce.
  state : Array[UInt]
  /// Keystream bytes of the current block that have not been used yet.
  mut keystream : Array[Byte]
  mut used : Int
}

///|
pub fn ChaCha20::new(
  key : Bytes,
  nonce : Bytes,
  counter : UInt,
) -> ChaCha20 raise KdbxError {
  if key.length() != 32 {
    raise Malformed(
      "ChaCha20 needs a 32-byte key, got " + key.length().to_string(),
    )
  }
  if nonce.length() != 12 {
    raise Malformed(
      "ChaCha20 needs a 12-byte nonce, got " + nonce.length().to_string(),
    )
  }
  let state : Array[UInt] = []
  for word in chacha_constants {
    state.push(word)
  }
  let mut i = 0
  while i < 8 {
    state.push(word_at(key, i * 4))
    i = i + 1
  }
  state.push(counter)
  i = 0
  while i < 3 {
    state.push(word_at(nonce, i * 4))
    i = i + 1
  }
  { state, keystream: [], used: 0, }
}

///|
/// Reads four bytes as a little-endian word.
fn word_at(data : Bytes, offset : Int) -> UInt raise KdbxError {
  if offset < 0 || offset + 4 > data.length() {
    raise Truncated("not enough bytes for a ChaCha20 word")
  }
  let slice = Bytes::makei(4, fn(i) { data[offset + i] })
  ByteReader::new(slice).read_u32_le()
}

///|
/// XORs `data` with the next keystream bytes. Calling this repeatedly continues
/// the same stream, which is exactly how KeePass uses it.
pub fn ChaCha20::apply(self : ChaCha20, data : Bytes) -> Bytes {
  let out = ByteWriter::new()
  let mut i = 0
  while i < data.length() {
    if self.used >= self.keystream.length() {
      self.next_block()
    }
    out.write_byte(data[i].to_uint() ^ self.keystream[self.used].to_uint())
    self.used = self.used + 1
    i = i + 1
  }
  out.to_bytes()
}

///|
/// Generates the next 64-byte keystream block and advances the counter.
fn ChaCha20::next_block(self : ChaCha20) -> Unit {
  let working = self.state.copy()
  let mut round = 0
  while round < 10 {
    quarter_round(working, 0, 4, 8, 12)
    quarter_round(working, 1, 5, 9, 13)
    quarter_round(working, 2, 6, 10, 14)
    quarter_round(working, 3, 7, 11, 15)
    quarter_round(working, 0, 5, 10, 15)
    quarter_round(working, 1, 6, 11, 12)
    quarter_round(working, 2, 7, 8, 13)
    quarter_round(working, 3, 4, 9, 14)
    round = round + 1
  }
  let block : Array[Byte] = []
  let mut i = 0
  while i < 16 {
    let word = working[i] + self.state[i]
    block.push((word & 0xFF).to_byte())
    block.push(((word >> 8) & 0xFF).to_byte())
    block.push(((word >> 16) & 0xFF).to_byte())
    block.push(((word >> 24) & 0xFF).to_byte())
    i = i + 1
  }
  self.keystream = block
  self.used = 0
  // The counter is the thirteenth word of the state.
  self.state[12] = self.state[12] + 1
}

///|
fn rotate_left(value : UInt, bits : Int) -> UInt {
  (value << bits) | (value >> (32 - bits))
}

///|
/// The ChaCha quarter round, as defined in RFC 8439, section 2.1.
fn quarter_round(
  state : Array[UInt],
  a : Int,
  b : Int,
  c : Int,
  d : Int,
) -> Unit {
  state[a] = state[a] + state[b]
  state[d] = rotate_left(state[d] ^ state[a], 16)
  state[c] = state[c] + state[d]
  state[b] = rotate_left(state[b] ^ state[c], 12)
  state[a] = state[a] + state[b]
  state[d] = rotate_left(state[d] ^ state[a], 8)
  state[c] = state[c] + state[d]
  state[b] = rotate_left(state[b] ^ state[c], 7)
}
