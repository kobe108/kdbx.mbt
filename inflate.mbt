///|
/// DEFLATE decompression (RFC 1951), in pure MoonBit.
///
/// KeePass compresses the payload by default, so this is what stands between a
/// decrypted buffer and readable XML. The structure follows the reference
/// "puff" design: canonical Huffman tables described by code lengths, decoded
/// bit by bit. Decoding is not the hot path — a few megabytes once per file —
/// so clarity and provable correctness win over speed.

///|
/// Reads bits least-significant-bit first, which is how DEFLATE packs them.
priv struct BitReader {
  data : Bytes
  mut position : Int
  mut buffer : UInt
  mut count : Int
}

///|
fn BitReader::new(data : Bytes, start : Int) -> BitReader {
  { data, position: start, buffer: 0, count: 0, }
}

///|
/// Reads `count` bits (at most 24) and returns them right-aligned.
fn BitReader::bits(self : BitReader, count : Int) -> Int raise KdbxError {
  if count < 0 || count > 24 {
    raise Malformed("cannot read " + count.to_string() + " bits at once")
  }
  while self.count < count {
    if self.position >= self.data.length() {
      raise Malformed("deflate stream ended in the middle of a code")
    }
    self.buffer = self.buffer |
      (self.data[self.position].to_uint() << self.count)
    self.position = self.position + 1
    self.count = self.count + 8
  }
  let mask = ((1 << count) - 1).reinterpret_as_uint()
  let value = self.buffer & mask
  self.buffer = self.buffer >> count
  self.count = self.count - count
  value.reinterpret_as_int()
}

///|
/// Discards the rest of the current byte.
fn BitReader::align(self : BitReader) -> Unit {
  self.buffer = 0
  self.count = 0
}

///|
/// Reads a whole byte; only valid straight after `align`.
fn BitReader::aligned_byte(self : BitReader) -> Int raise KdbxError {
  if self.count != 0 {
    raise Malformed("internal error: byte read while not aligned")
  }
  if self.position >= self.data.length() {
    raise Malformed("deflate stream ended in the middle of a stored block")
  }
  let value = self.data[self.position].to_uint()
  self.position = self.position + 1
  value.reinterpret_as_int()
}

///|
/// A canonical Huffman table: how many codes exist per length, and the symbols
/// in canonical order.
priv struct Huffman {
  counts : Array[Int]
  symbols : Array[Int]
}

///|
/// Maximum code length DEFLATE allows.
let max_code_bits : Int = 15

///|
/// Builds a decoding table from code lengths, rejecting codes that are empty,
/// over-subscribed, or incomplete in a way that cannot happen in valid input.
fn build_huffman(
  lengths : Array[Int],
  symbol_count : Int,
) -> Huffman raise KdbxError {
  let counts : Array[Int] = []
  let mut i = 0
  while i <= max_code_bits {
    counts.push(0)
    i = i + 1
  }
  let mut symbol = 0
  while symbol < symbol_count {
    let length = lengths[symbol]
    if length < 0 || length > max_code_bits {
      raise Malformed("code length " + length.to_string() + " out of range")
    }
    counts[length] = counts[length] + 1
    symbol = symbol + 1
  }
  if counts[0] == symbol_count {
    raise Malformed("Huffman code with no symbols")
  }
  // Kraft's inequality: no prefix code may claim more than the code space.
  let mut left = 1
  let mut length = 1
  while length <= max_code_bits {
    left = left << 1
    left = left - counts[length]
    if left < 0 {
      raise Malformed("over-subscribed Huffman code")
    }
    length = length + 1
  }
  let offsets : Array[Int] = []
  let mut j = 0
  while j <= max_code_bits {
    offsets.push(0)
    j = j + 1
  }
  let mut k = 1
  while k < max_code_bits {
    offsets[k + 1] = offsets[k] + counts[k]
    k = k + 1
  }
  let symbols : Array[Int] = []
  let mut place = 0
  while place < symbol_count {
    symbols.push(0)
    place = place + 1
  }
  let mut item = 0
  while item < symbol_count {
    let code_length = lengths[item]
    if code_length != 0 {
      symbols[offsets[code_length]] = item
      offsets[code_length] = offsets[code_length] + 1
    }
    item = item + 1
  }
  { counts, symbols, }
}

///|
/// Decodes one symbol, following the canonical code bit by bit.
fn decode_symbol(reader : BitReader, table : Huffman) -> Int raise KdbxError {
  let mut code = 0
  let mut first = 0
  let mut index = 0
  let mut length = 1
  while length <= max_code_bits {
    code = code | reader.bits(1)
    let count = table.counts[length]
    if code - count < first {
      return table.symbols[index + (code - first)]
    }
    index = index + count
    first = first + count
    first = first << 1
    code = code << 1
    length = length + 1
  }
  raise Malformed("invalid Huffman code")
}

///|
/// Length and distance tables of RFC 1951, section 3.2.5.
let length_base : Array[Int] = [
  3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83,
  99, 115, 131, 163, 195, 227, 258,
]

///|
let length_extra : Array[Int] = [
  0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5,
  5, 0,
]

///|
let distance_base : Array[Int] = [
  1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769,
  1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
]

///|
let distance_extra : Array[Int] = [
  0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11,
  12, 12, 13, 13,
]

///|
/// The fixed literal/length code of RFC 1951, section 3.2.6.
fn fixed_literal_table() -> Huffman raise KdbxError {
  let lengths : Array[Int] = []
  let mut symbol = 0
  while symbol < 288 {
    let length = if symbol < 144 {
      8
    } else if symbol < 256 {
      9
    } else if symbol < 280 {
      7
    } else {
      8
    }
    lengths.push(length)
    symbol = symbol + 1
  }
  build_huffman(lengths, 288)
}

///|
/// The fixed distance code: 30 codes of five bits each.
fn fixed_distance_table() -> Huffman raise KdbxError {
  let lengths : Array[Int] = []
  let mut symbol = 0
  while symbol < 30 {
    lengths.push(5)
    symbol = symbol + 1
  }
  build_huffman(lengths, 30)
}

///|
/// Decompresses a DEFLATE stream that starts at `start`.
///
/// Returns the plaintext and how many bytes of input the stream consumed —
/// *not* the absolute end offset, which a container (gzip) would otherwise add
/// to `start` a second time.
pub fn inflate(data : Bytes, start : Int) -> (Bytes, Int) raise KdbxError {
  let reader = BitReader::new(data, start)
  let out : Array[Byte] = []
  let mut final_block = false
  while !final_block {
    final_block = reader.bits(1) == 1
    let block_type = reader.bits(2)
    match block_type {
      0 => {
        reader.align()
        let length = reader.aligned_byte() | (reader.aligned_byte() << 8)
        let complement = reader.aligned_byte() | (reader.aligned_byte() << 8)
        if (length ^ complement) != 0xFFFF {
          raise Malformed("stored block length and its complement disagree")
        }
        let mut copied = 0
        while copied < length {
          out.push(reader.aligned_byte().reinterpret_as_uint().to_byte())
          copied = copied + 1
        }
      }
      1 => {
        let literals = fixed_literal_table()
        let distances = fixed_distance_table()
        inflate_block(reader, out, literals, distances)
      }
      2 => {
        let (literals, distances) = dynamic_tables(reader)
        inflate_block(reader, out, literals, distances)
      }
      _ => raise Malformed("reserved DEFLATE block type")
    }
  }
  reader.align()
  (Bytes::from_array(out), reader.position - start)
}

///|
/// Reads the dynamic Huffman description that precedes a compressed block.
fn dynamic_tables(reader : BitReader) -> (Huffman, Huffman) raise KdbxError {
  let literal_count = reader.bits(5) + 257
  let distance_count = reader.bits(5) + 1
  let code_length_count = reader.bits(4) + 4
  // The code lengths of the code-length alphabet are stored in this order.
  let order : Array[Int] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
  ]
  let code_lengths : Array[Int] = []
  let mut i = 0
  while i < 19 {
    code_lengths.push(0)
    i = i + 1
  }
  let mut index = 0
  while index < code_length_count {
    code_lengths[order[index]] = reader.bits(3)
    index = index + 1
  }
  let alphabet = build_huffman(code_lengths, 19)
  let total = literal_count + distance_count
  let lengths : Array[Int] = []
  while lengths.length() < total {
    let symbol = decode_symbol(reader, alphabet)
    if symbol < 16 {
      lengths.push(symbol)
    } else if symbol == 16 {
      if lengths.length() == 0 {
        raise Malformed("code length repeat with nothing to repeat")
      }
      let previous = lengths[lengths.length() - 1]
      let repeat = 3 + reader.bits(2)
      let mut count = 0
      while count < repeat {
        lengths.push(previous)
        count = count + 1
      }
    } else if symbol == 17 {
      let repeat = 3 + reader.bits(3)
      let mut count = 0
      while count < repeat {
        lengths.push(0)
        count = count + 1
      }
    } else {
      let repeat = 11 + reader.bits(7)
      let mut count = 0
      while count < repeat {
        lengths.push(0)
        count = count + 1
      }
    }
    if lengths.length() > total {
      raise Malformed("Huffman code lengths run past the end of the alphabet")
    }
  }
  let literal_lengths = Bytes::makei(literal_count, fn(i) {
    lengths[i].to_byte()
  })
  let literal_array : Array[Int] = []
  for i = 0; i < literal_count; i = i + 1 {
    literal_array.push(literal_lengths[i].to_uint().reinterpret_as_int())
  }
  let distance_array : Array[Int] = []
  for i = 0; i < distance_count; i = i + 1 {
    distance_array.push(lengths[literal_count + i])
  }
  (
    build_huffman(literal_array, literal_count),
    build_huffman(distance_array, distance_count),
  )
}

///|
/// Decodes one Huffman-coded block, appending to `out`.
fn inflate_block(
  reader : BitReader,
  out : Array[Byte],
  literals : Huffman,
  distances : Huffman,
) -> Unit raise KdbxError {
  let mut done = false
  while !done {
    let symbol = decode_symbol(reader, literals)
    if symbol < 256 {
      out.push(symbol.to_byte())
    } else if symbol == 256 {
      done = true
    } else {
      let length_index = symbol - 257
      if length_index < 0 || length_index >= length_base.length() {
        raise Malformed("invalid length code " + symbol.to_string())
      }
      let length = length_base[length_index] +
        reader.bits(length_extra[length_index])
      let distance_symbol = decode_symbol(reader, distances)
      if distance_symbol >= distance_base.length() {
        raise Malformed("invalid distance code " + distance_symbol.to_string())
      }
      let distance = distance_base[distance_symbol] +
        reader.bits(distance_extra[distance_symbol])
      if distance > out.length() {
        raise Malformed("copy distance reaches before the start of the output")
      }
      let mut copied = 0
      while copied < length {
        // Re-read the index every time so overlapping copies (distance smaller
        // than the length) repeat the bytes just written.
        out.push(out[out.length() - distance])
        copied = copied + 1
      }
    }
  }
}
