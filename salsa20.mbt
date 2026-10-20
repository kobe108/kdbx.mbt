///|
/// Salsa20 (Bernstein), the older inner random stream of KDBX 4 files.
///
/// A KDBX 4 file may name either Salsa20 (id 2) or ChaCha20 (id 3). Both protect
/// individual fields with one shared keystream, so supporting only one of them
/// would make a valid database unreadable.

///|
pub struct Salsa20 {
  state : Array[UInt]
  mut keystream : Array[Byte]
  mut used : Int
}

///|
pub fn Salsa20::new(key : Bytes, nonce : Bytes) -> Salsa20 raise KdbxError {
  if key.length() != 32 {
    raise Malformed(
      "Salsa20 needs a 32-byte key, got " + key.length().to_string(),
    )
  }
  if nonce.length() != 8 {
    raise Malformed(
      "Salsa20 needs an 8-byte nonce, got " + nonce.length().to_string(),
    )
  }
  let state : Array[UInt] = [
    0x61707865,
    word_at(key, 0),
    word_at(key, 4),
    word_at(key, 8),
    word_at(key, 12),
    0x3320646e,
    word_at(nonce, 0),
    word_at(nonce, 4),
    0,
    0,
    0x79622d32,
    word_at(key, 16),
    word_at(key, 20),
    word_at(key, 24),
    word_at(key, 28),
    0x6b206574,
  ]
  { state, keystream: [], used: 0, }
}

///|
/// XORs `data` with the next keystream bytes, continuing the same stream.
pub fn Salsa20::apply(self : Salsa20, data : Bytes) -> Bytes {
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
fn Salsa20::next_block(self : Salsa20) -> Unit {
  let working = self.state.copy()
  let mut round = 0
  while round < 10 {
    // Column round, then row round.
    salsa_quarter(working, 0, 4, 8, 12)
    salsa_quarter(working, 5, 9, 13, 1)
    salsa_quarter(working, 10, 14, 2, 6)
    salsa_quarter(working, 15, 3, 7, 11)
    salsa_quarter(working, 0, 1, 2, 3)
    salsa_quarter(working, 5, 6, 7, 4)
    salsa_quarter(working, 10, 11, 8, 9)
    salsa_quarter(working, 15, 12, 13, 14)
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
  // Advance the 64-bit block counter (words 8 and 9).
  let low = self.state[8] + 1
  self.state[8] = low
  if low == 0 {
    self.state[9] = self.state[9] + 1
  }
}

///|
fn salsa_quarter(
  state : Array[UInt],
  a : Int,
  b : Int,
  c : Int,
  d : Int,
) -> Unit {
  state[b] = state[b] ^ rotate_left(state[a] + state[d], 7)
  state[c] = state[c] ^ rotate_left(state[b] + state[a], 9)
  state[d] = state[d] ^ rotate_left(state[c] + state[b], 13)
  state[a] = state[a] ^ rotate_left(state[d] + state[c], 18)
}
