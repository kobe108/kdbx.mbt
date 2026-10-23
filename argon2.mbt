///|
/// Argon2 (RFC 9106), the memory-hard function behind KeePass's default KDF.
///
/// KeePass stores the output of this function as the transformed master key, so
/// a KDBX file created by a current KeePassXC cannot be opened without it —
/// which is why the project treats it as a required capability rather than an
/// optional extra.

///|
pub enum Argon2Kind {
  Argon2d
  Argon2i
  Argon2id
}

///|
/// Argon2i's selector.
///
/// KDBX uses Argon2d and Argon2id, but `argon2_digest` implements all three RFC
/// 9106 modes. This accessor keeps the complete primitive usable as a library
/// API without widening the password-database format claim.
pub fn argon2i_kind() -> Argon2Kind {
  Argon2i
}

///|
/// Everything Argon2 needs apart from the password.
pub struct Argon2Params {
  salt : Bytes
  secret : Bytes
  associated_data : Bytes
  iterations : UInt
  memory_kib : UInt
  lanes : UInt
  tag_length : Int
  version : UInt
  kind : Argon2Kind
}

///|
fn argon2_kind_code(kind : Argon2Kind) -> UInt {
  match kind {
    Argon2d => 0
    Argon2i => 1
    Argon2id => 2
  }
}

///|
/// Computes the Argon2 tag for `password`.
pub fn argon2_digest(
  params : Argon2Params,
  password : Bytes,
) -> Bytes raise KdbxError {
  let lanes = params.lanes
  if lanes == 0 || lanes > 0xFFFFFF {
    raise Malformed("Argon2 lanes must be 1..2^24-1, got \{lanes}")
  }
  if params.iterations == 0 {
    raise Malformed("Argon2 needs at least one pass")
  }
  if params.memory_kib < 8 * lanes {
    raise Malformed("Argon2 needs at least 8 KiB per lane")
  }
  if params.tag_length < 4 || params.tag_length > 1024 * 1024 {
    raise Malformed("Argon2 tag length out of range")
  }
  if params.salt.length() < 8 {
    raise Malformed("Argon2 salt must be at least 8 bytes")
  }
  if params.version != 0x10 && params.version != 0x13 {
    raise Malformed(
      "unsupported Argon2 version 0x\{params.version.to_string(radix=16)}",
    )
  }
  // H0: the pre-hashing digest over all parameters and inputs.
  let prehash_input = ByteWriter::new()
  prehash_input.write_u32_le(lanes)
  prehash_input.write_u32_le(params.tag_length.reinterpret_as_uint())
  prehash_input.write_u32_le(params.memory_kib)
  prehash_input.write_u32_le(params.iterations)
  prehash_input.write_u32_le(params.version)
  prehash_input.write_u32_le(argon2_kind_code(params.kind))
  prehash_input.write_u32_le(password.length().reinterpret_as_uint())
  prehash_input.write_bytes(password)
  prehash_input.write_u32_le(params.salt.length().reinterpret_as_uint())
  prehash_input.write_bytes(params.salt)
  prehash_input.write_u32_le(params.secret.length().reinterpret_as_uint())
  prehash_input.write_bytes(params.secret)
  prehash_input.write_u32_le(
    params.associated_data.length().reinterpret_as_uint(),
  )
  prehash_input.write_bytes(params.associated_data)
  let h0 = blake2b(prehash_input.to_bytes(), 64)

  // Memory is rounded down to a multiple of 4 * lanes, as the specification
  // requires; the four sync points (slices) share the lane evenly.
  let lanes_i = lanes.reinterpret_as_int()
  let iterations_i = params.iterations.reinterpret_as_int()
  let memory_blocks = params.memory_kib.reinterpret_as_int() /
    (4 * lanes_i) *
    (4 * lanes_i)
  let lane_length = memory_blocks / lanes_i
  let segment_length = lane_length / 4
  let memory : Array[UInt64] = []
  let mut i = 0
  while i < memory_blocks * 128 {
    memory.push(0)
    i = i + 1
  }
  let x : Array[UInt64] = zeros(128)
  let y : Array[UInt64] = zeros(128)
  let out : Array[UInt64] = zeros(128)
  let scratch : Array[UInt64] = zeros(128)

  // Two initial blocks per lane.
  let mut lane = 0
  while lane < lanes_i {
    let block0 = argon2_block_input(h0, 0, lane)
    write_block(memory, lane * lane_length, argon2_h_prime(block0, 1024))
    let block1 = argon2_block_input(h0, 1, lane)
    write_block(memory, lane * lane_length + 1, argon2_h_prime(block1, 1024))
    lane = lane + 1
  }

  let mut pass = 0
  while pass < iterations_i {
    let mut slice = 0
    while slice < 4 {
      lane = 0
      while lane < lanes_i {
        let independent = match params.kind {
          Argon2i => true
          Argon2id => pass == 0 && slice < 2
          Argon2d => false
        }
        let address = zeros(128)
        let input = zeros(128)
        if independent {
          input[0] = pass.to_uint64()
          input[1] = lane.to_uint64()
          input[2] = slice.to_uint64()
          input[3] = memory_blocks.to_uint64()
          input[4] = iterations_i.to_uint64()
          input[5] = argon2_kind_code(params.kind).to_uint64()
          input[6] = 0
        }
        let starting = if pass == 0 && slice == 0 { 2 } else { 0 }
        let tmp = zeros(128)
        // RFC 9106 initializes an address block before a first slice that
        // starts at index 2. Without this, Argon2i/Argon2id would read zeros
        // for the first 126 blocks; the tiny RFC vectors skip this branch.
        if independent && starting > 0 {
          input[6] = input[6] + 1
          let zero = zeros(128)
          argon2_compress(zero, input, address, scratch)
          argon2_compress(zero, address, tmp, scratch)
          let mut word = 0
          while word < 128 {
            address[word] = tmp[word]
            word = word + 1
          }
        }
        let mut index = starting
        while index < segment_length {
          let current = lane * lane_length + slice * segment_length + index
          let previous = if current % lane_length == 0 {
            current + lane_length - 1
          } else {
            current - 1
          }
          let pseudo = if independent {
            if index % 128 == 0 {
              input[6] = input[6] + 1
              let zero = zeros(128)
              argon2_compress(zero, input, address, scratch)
              argon2_compress(zero, address, tmp, scratch)
              let mut word = 0
              while word < 128 {
                address[word] = tmp[word]
                word = word + 1
              }
            }
            address[index % 128]
          } else {
            memory[previous * 128]
          }
          let same_lane_only = pass == 0 && slice == 0
          let reference_lane = if same_lane_only {
            lane
          } else {
            // Take the high 32 bits as the lane selector. Reducing in UInt
            // space keeps it non-negative; reinterpreting first would allow a
            // negative remainder and an out-of-range block index.
            ((pseudo >> 32).to_uint() % lanes).reinterpret_as_int()
          }
          let reference_index = argon2_reference_index(
            pass,
            slice,
            index,
            reference_lane == lane,
            pseudo.to_uint(),
            lane_length,
            segment_length,
          )
          let reference = reference_lane * lane_length + reference_index
          copy_block(memory, previous, x)
          copy_block(memory, reference, y)
          let with_xor = pass > 0 && params.version == 0x13
          argon2_compress(x, y, out, scratch)
          let mut word = 0
          while word < 128 {
            let target = current * 128 + word
            memory[target] = if with_xor {
              memory[target] ^ out[word]
            } else {
              out[word]
            }
            word = word + 1
          }
          index = index + 1
        }
        lane = lane + 1
      }
      slice = slice + 1
    }
    pass = pass + 1
  }
  // XOR the last block of every lane, then hash it to the requested length.
  let final_state = zeros(128)
  lane = 0
  while lane < lanes_i {
    let last = lane * lane_length + lane_length - 1
    let mut word = 0
    while word < 128 {
      final_state[word] = final_state[word] ^ memory[last * 128 + word]
      word = word + 1
    }
    lane = lane + 1
  }
  argon2_h_prime(words_to_bytes(final_state), params.tag_length)
}

///|
/// Input for the two initial blocks of a lane: `H0 || LE32(index) || LE32(lane)`.
fn argon2_block_input(h0 : Bytes, index : Int, lane : Int) -> Bytes {
  let out = ByteWriter::new()
  out.write_bytes(h0)
  out.write_u32_le(index.reinterpret_as_uint())
  out.write_u32_le(lane.reinterpret_as_uint())
  out.to_bytes()
}

///|
/// `H'`: the variable-length hash of RFC 9106, section 3.3.
fn argon2_h_prime(input : Bytes, out_len : Int) -> Bytes raise KdbxError {
  let prefixed = ByteWriter::new()
  prefixed.write_u32_le(out_len.reinterpret_as_uint())
  prefixed.write_bytes(input)
  if out_len <= 64 {
    return blake2b(prefixed.to_bytes(), out_len)
  }
  let r = (out_len + 31) / 32 - 2
  let out = ByteWriter::new()
  let mut current = blake2b(prefixed.to_bytes(), 64)
  let mut index = 0
  while index < r - 1 {
    out.write_bytes(Bytes::makei(32, fn(i) { current[i] }))
    current = blake2b(current, 64)
    index = index + 1
  }
  out.write_bytes(Bytes::makei(32, fn(i) { current[i] }))
  out.write_bytes(blake2b(current, out_len - 32 * r))
  out.to_bytes()
}

///|
fn zeros(count : Int) -> Array[UInt64] {
  let out : Array[UInt64] = []
  let mut i = 0
  while i < count {
    out.push(0)
    i = i + 1
  }
  out
}

///|
fn write_block(
  memory : Array[UInt64],
  index : Int,
  data : Bytes,
) -> Unit raise KdbxError {
  if data.length() != 1024 {
    raise Malformed(
      "Argon2 blocks are 1024 bytes, got " + data.length().to_string(),
    )
  }
  let mut i = 0
  while i < 128 {
    memory[index * 128 + i] = read_u64_le(data, i * 8)
    i = i + 1
  }
}

///|
fn words_to_bytes(words : Array[UInt64]) -> Bytes {
  let out = ByteWriter::new()
  for word in words {
    out.write_u64_le(word)
  }
  out.to_bytes()
}

///|
fn copy_block(
  memory : Array[UInt64],
  index : Int,
  target : Array[UInt64],
) -> Unit {
  let mut i = 0
  while i < 128 {
    target[i] = memory[index * 128 + i]
    i = i + 1
  }
}

///|
/// `G`: the compression function of RFC 9106, section 3.5.
///
/// `x` and `y` are the two input blocks, `scratch` is working memory; the result
/// goes to `out`. Four blocks of 128 words are reused, so a multi-megabyte
/// memory fill does not allocate per block.
fn argon2_compress(
  a : Array[UInt64],
  b : Array[UInt64],
  out : Array[UInt64],
  scratch : Array[UInt64],
) -> Unit {
  let mut i = 0
  while i < 128 {
    scratch[i] = a[i] ^ b[i]
    i = i + 1
  }
  // 8 rows of 16 words, then 8 columns of 16 words with stride 2.
  let mut row = 0
  while row < 8 {
    argon2_round(scratch, row * 16, 1)
    row = row + 1
  }
  let mut column = 0
  while column < 8 {
    argon2_round_columns(scratch, column)
    column = column + 1
  }
  i = 0
  while i < 128 {
    out[i] = scratch[i] ^ a[i] ^ b[i]
    i = i + 1
  }
}

///|
/// The 16 words of a column group: two adjacent words per 16-word row.
fn argon2_column_index(column : Int, position : Int) -> Int {
  2 * column + 16 * (position / 2) + position % 2
}

///|
/// One round over a column group. The group is not evenly strided: positions
/// 0 and 1 are adjacent, then jump by 16, which is why this cannot reuse the
/// row routine's stride arithmetic.
fn argon2_round_columns(words : Array[UInt64], column : Int) -> Unit {
  argon2_g(
    words,
    argon2_column_index(column, 0),
    argon2_column_index(column, 4),
    argon2_column_index(column, 8),
    argon2_column_index(column, 12),
  )
  argon2_g(
    words,
    argon2_column_index(column, 1),
    argon2_column_index(column, 5),
    argon2_column_index(column, 9),
    argon2_column_index(column, 13),
  )
  argon2_g(
    words,
    argon2_column_index(column, 2),
    argon2_column_index(column, 6),
    argon2_column_index(column, 10),
    argon2_column_index(column, 14),
  )
  argon2_g(
    words,
    argon2_column_index(column, 3),
    argon2_column_index(column, 7),
    argon2_column_index(column, 11),
    argon2_column_index(column, 15),
  )
  argon2_g(
    words,
    argon2_column_index(column, 0),
    argon2_column_index(column, 5),
    argon2_column_index(column, 10),
    argon2_column_index(column, 15),
  )
  argon2_g(
    words,
    argon2_column_index(column, 1),
    argon2_column_index(column, 6),
    argon2_column_index(column, 11),
    argon2_column_index(column, 12),
  )
  argon2_g(
    words,
    argon2_column_index(column, 2),
    argon2_column_index(column, 7),
    argon2_column_index(column, 8),
    argon2_column_index(column, 13),
  )
  argon2_g(
    words,
    argon2_column_index(column, 3),
    argon2_column_index(column, 4),
    argon2_column_index(column, 9),
    argon2_column_index(column, 14),
  )
}

///|
/// One round of the permutation: eight `G` calls on sixteen words.
fn argon2_round(words : Array[UInt64], base : Int, stride : Int) -> Unit {
  argon2_g(
    words,
    base,
    base + 4 * stride,
    base + 8 * stride,
    base + 12 * stride,
  )
  argon2_g(
    words,
    base + stride,
    base + 5 * stride,
    base + 9 * stride,
    base + 13 * stride,
  )
  argon2_g(
    words,
    base + 2 * stride,
    base + 6 * stride,
    base + 10 * stride,
    base + 14 * stride,
  )
  argon2_g(
    words,
    base + 3 * stride,
    base + 7 * stride,
    base + 11 * stride,
    base + 15 * stride,
  )
  argon2_g(
    words,
    base,
    base + 5 * stride,
    base + 10 * stride,
    base + 15 * stride,
  )
  argon2_g(
    words,
    base + stride,
    base + 6 * stride,
    base + 11 * stride,
    base + 12 * stride,
  )
  argon2_g(
    words,
    base + 2 * stride,
    base + 7 * stride,
    base + 8 * stride,
    base + 13 * stride,
  )
  argon2_g(
    words,
    base + 3 * stride,
    base + 4 * stride,
    base + 9 * stride,
    base + 14 * stride,
  )
}

///|
/// The BlaMka mixing function used by Argon2's permutation.
fn blamka(a : UInt64, b : UInt64) -> UInt64 {
  a + b + 2 * (a & 0xFFFFFFFF) * (b & 0xFFFFFFFF)
}

///|
fn argon2_g(words : Array[UInt64], a : Int, b : Int, c : Int, d : Int) -> Unit {
  words[a] = blamka(words[a], words[b])
  words[d] = rotate_right_64(words[d] ^ words[a], 32)
  words[c] = blamka(words[c], words[d])
  words[b] = rotate_right_64(words[b] ^ words[c], 24)
  words[a] = blamka(words[a], words[b])
  words[d] = rotate_right_64(words[d] ^ words[a], 16)
  words[c] = blamka(words[c], words[d])
  words[b] = rotate_right_64(words[b] ^ words[c], 63)
}

///|
/// Reference index selection, following the reference implementation exactly
/// (RFC 9106, section 3.4.2). Getting this wrong produces a wrong but
/// plausible-looking key, so it is kept structurally identical.
fn argon2_reference_index(
  pass : Int,
  slice : Int,
  index : Int,
  same_lane : Bool,
  pseudo : UInt,
  lane_length : Int,
  segment_length : Int,
) -> Int {
  let area : Int = if pass == 0 {
    if slice == 0 {
      index - 1
    } else if same_lane {
      slice * segment_length + index - 1
    } else {
      slice * segment_length - (if index == 0 { 1 } else { 0 })
    }
  } else if same_lane {
    lane_length - segment_length + index - 1
  } else {
    lane_length - segment_length - (if index == 0 { 1 } else { 0 })
  }
  let pseudo64 = pseudo.to_uint64()
  let relative_pseudo = (pseudo64 * pseudo64) >> 32
  let area64 = area.to_uint64()
  let relative = area64 - 1 - ((area64 * relative_pseudo) >> 32)
  let start : Int = if pass != 0 && slice != 3 {
    (slice + 1) * segment_length
  } else {
    0
  }
  ((start.to_uint64() + relative) % lane_length.to_uint64()).to_int()
}
