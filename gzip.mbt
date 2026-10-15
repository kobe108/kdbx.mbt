///|
/// The gzip container (RFC 1952), which wraps the DEFLATE stream that KeePass
/// writes when the payload is compressed.

///|
/// Decompresses a gzip stream and verifies its integrity trailer.
pub fn gunzip(data : Bytes) -> Bytes raise KdbxError {
  let reader = ByteReader::new(data)
  if reader.read_byte() != 0x1F || reader.read_byte() != 0x8B {
    raise Malformed("not a gzip stream (bad magic)")
  }
  let compression_method = reader.read_byte()
  if compression_method != 8 {
    raise Malformed(
      "unsupported gzip compression method " + compression_method.to_string(),
    )
  }
  let flags = reader.read_byte()
  reader.read_u32_le() |> ignore // modification time, not needed
  reader.read_byte() |> ignore // extra flags
  reader.read_byte() |> ignore // operating system
  if (flags & 0x04) != 0 {
    let extra_length = reader.read_u16_le().reinterpret_as_int()
    reader.read_bytes(extra_length) |> ignore
  }
  if (flags & 0x08) != 0 {
    skip_zero_terminated(reader)
  }
  if (flags & 0x10) != 0 {
    skip_zero_terminated(reader)
  }
  if (flags & 0x02) != 0 {
    reader.read_bytes(2) |> ignore
  }
  let (plain, consumed) = inflate(data, reader.offset())
  let trailer = reader.offset() + consumed
  let stored_crc = read_u32_at(data, trailer)
  let stored_size = read_u32_at(data, trailer + 4)
  if crc32(plain) != stored_crc {
    raise Malformed("gzip CRC does not match the decompressed payload")
  }
  if plain.length().reinterpret_as_uint() != stored_size {
    raise Malformed("gzip length does not match the decompressed payload")
  }
  plain
}

///|
/// Consumes a zero-terminated string such as the file name in the header.
fn skip_zero_terminated(reader : ByteReader) -> Unit raise KdbxError {
  let mut done = false
  while !done {
    if reader.read_byte() == 0 {
      done = true
    }
  }
}

///|
fn read_u32_at(data : Bytes, offset : Int) -> UInt raise KdbxError {
  if offset < 0 || offset + 4 > data.length() {
    raise Truncated("gzip stream ends before its integrity trailer")
  }
  let slice = Bytes::makei(4, fn(i) { data[offset + i] })
  ByteReader::new(slice).read_u32_le()
}

///|
/// CRC-32 as gzip defines it: the reflected polynomial `0xEDB88320`, pre- and
/// post-inverted.
pub fn crc32(data : Bytes) -> UInt {
  let table : Array[UInt] = []
  let mut i = 0
  while i < 256 {
    let mut value = i.reinterpret_as_uint()
    let mut bit = 0
    while bit < 8 {
      value = if (value & 1) != 0 {
        (value >> 1) ^ 0xEDB88320
      } else {
        value >> 1
      }
      bit = bit + 1
    }
    table.push(value)
    i = i + 1
  }
  let mut crc : UInt = 0xFFFFFFFF
  for i = 0; i < data.length(); i = i + 1 {
    let index = ((crc ^ data[i].to_uint()) & 0xFF).reinterpret_as_int()
    crc = table[index] ^ (crc >> 8)
  }
  crc ^ 0xFFFFFFFF
}
