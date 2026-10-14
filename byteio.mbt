///|
/// A bounds-checked, little-endian reader over an immutable byte buffer.
///
/// Every `read_*` call first proves that enough bytes remain, so a malformed
/// file yields a `KdbxError` instead of an out-of-bounds panic.
pub struct ByteReader {
  data : Bytes
  mut offset : Int
}

///|
pub fn ByteReader::new(data : Bytes) -> ByteReader {
  { data, offset: 0, }
}

///|
pub fn ByteReader::offset(self : ByteReader) -> Int {
  self.offset
}

///|
pub fn ByteReader::remaining(self : ByteReader) -> Int {
  self.data.length() - self.offset
}

///|
pub fn ByteReader::at_end(self : ByteReader) -> Bool {
  self.offset >= self.data.length()
}

///|
fn ByteReader::need(self : ByteReader, count : Int) -> Unit raise KdbxError {
  if count < 0 {
    raise Malformed("negative read length: " + count.to_string())
  }
  if self.offset + count > self.data.length() {
    raise Truncated(
      "wanted \{count} byte(s) at offset \{self.offset}, but only \{self.remaining()} byte(s) are left",
    )
  }
}

///|
pub fn ByteReader::read_byte(self : ByteReader) -> UInt raise KdbxError {
  self.need(1)
  let value = self.data[self.offset].to_uint()
  self.offset = self.offset + 1
  value
}

///|
/// Reads `width` bytes as a little-endian unsigned integer (`width` <= 8).
pub fn ByteReader::read_uint_le(
  self : ByteReader,
  width : Int,
) -> UInt64 raise KdbxError {
  if width < 0 || width > 8 {
    raise Malformed("cannot read a " + width.to_string() + "-byte integer")
  }
  self.need(width)
  let mut value : UInt64 = 0
  let mut i = 0
  while i < width {
    value = value | (self.data[self.offset + i].to_uint64() << (8 * i))
    i = i + 1
  }
  self.offset = self.offset + width
  value
}

///|
pub fn ByteReader::read_u16_le(self : ByteReader) -> UInt raise KdbxError {
  self.read_uint_le(2).to_uint()
}

///|
pub fn ByteReader::read_u32_le(self : ByteReader) -> UInt raise KdbxError {
  self.need(4)
  let mut value : UInt = 0
  let mut i = 0
  while i < 4 {
    value = value | (self.data[self.offset + i].to_uint() << (8 * i))
    i = i + 1
  }
  self.offset = self.offset + 4
  value
}

///|
pub fn ByteReader::read_u64_le(self : ByteReader) -> UInt64 raise KdbxError {
  self.read_uint_le(8)
}

///|
/// Reads a 4-byte little-endian signed integer in two's complement.
pub fn ByteReader::read_int32_le(self : ByteReader) -> Int raise KdbxError {
  self.read_u32_le().reinterpret_as_int()
}

///|
/// Reads an 8-byte little-endian signed integer in two's complement.
pub fn ByteReader::read_int64_le(self : ByteReader) -> Int64 raise KdbxError {
  self.read_u64_le().reinterpret_as_int64()
}

///|
pub fn ByteReader::read_bytes(
  self : ByteReader,
  count : Int,
) -> Bytes raise KdbxError {
  self.need(count)
  let out = Bytes::makei(count, fn(i) { self.data[self.offset + i] })
  self.offset = self.offset + count
  out
}

///|
/// Reads the rest of the input, leaving the reader at the end of the buffer.
pub fn ByteReader::read_rest(self : ByteReader) -> Bytes raise KdbxError {
  self.read_bytes(self.remaining())
}

///|
/// An append-only, little-endian writer producing an immutable byte buffer.
pub struct ByteWriter {
  chunks : Array[Byte]
}

///|
pub fn ByteWriter::new() -> ByteWriter {
  { chunks: [], }
}

///|
pub fn ByteWriter::length(self : ByteWriter) -> Int {
  self.chunks.length()
}

///|
pub fn ByteWriter::write_byte(self : ByteWriter, value : UInt) -> Unit {
  self.chunks.push(value.to_byte())
}

///|
/// Writes the low `width` bytes of `value` in little-endian order.
pub fn ByteWriter::write_uint_le(
  self : ByteWriter,
  value : UInt64,
  width : Int,
) -> Unit {
  let mut i = 0
  while i < width {
    self.chunks.push((value >> (8 * i)).to_byte())
    i = i + 1
  }
}

///|
pub fn ByteWriter::write_u16_le(self : ByteWriter, value : UInt) -> Unit {
  self.write_uint_le(value.to_uint64(), 2)
}

///|
pub fn ByteWriter::write_u32_le(self : ByteWriter, value : UInt) -> Unit {
  self.write_uint_le(value.to_uint64(), 4)
}

///|
pub fn ByteWriter::write_u64_le(self : ByteWriter, value : UInt64) -> Unit {
  self.write_uint_le(value, 8)
}

///|
/// Writes a 32-bit value in big-endian order (needed by the hash functions,
/// whose input words are big-endian while KDBX itself is little-endian).
pub fn ByteWriter::write_u32_be(self : ByteWriter, value : UInt) -> Unit {
  self.write_byte((value >> 24) & 0xFF)
  self.write_byte((value >> 16) & 0xFF)
  self.write_byte((value >> 8) & 0xFF)
  self.write_byte(value & 0xFF)
}

///|
/// Writes a 64-bit value in big-endian order.
pub fn ByteWriter::write_u64_be(self : ByteWriter, value : UInt64) -> Unit {
  let mut i = 0
  while i < 8 {
    self.chunks.push((value >> ((7 - i) * 8)).to_byte())
    i = i + 1
  }
}

///|
/// Appends one byte buffer to another.
pub fn concat_bytes(first : Bytes, second : Bytes) -> Bytes {
  let out = ByteWriter::new()
  out.write_bytes(first)
  out.write_bytes(second)
  out.to_bytes()
}

///|
/// Writes a signed 32-bit value in two's complement little-endian order.
pub fn ByteWriter::write_int32_le(self : ByteWriter, value : Int) -> Unit {
  self.write_u32_le(value.reinterpret_as_uint())
}

///|
pub fn ByteWriter::write_bytes(self : ByteWriter, value : Bytes) -> Unit {
  for i = 0; i < value.length(); i = i + 1 {
    self.chunks.push(value[i])
  }
}

///|
pub fn ByteWriter::to_bytes(self : ByteWriter) -> Bytes {
  Bytes::from_array(self.chunks)
}
