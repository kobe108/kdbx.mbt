///|
/// The inner header that precedes the XML document (KDBX 4.1, "Inner Header").
///
/// It is encrypted along with the XML, and it carries what the reader needs
/// before the document can be understood: the random stream that protects
/// individual fields, and the attachments (which stay binary instead of being
/// base64-encoded inside the XML).

///|
/// Identifier of the random stream used to protect fields.
pub let inner_field_stream_id : UInt = 0x01

///|
pub let inner_field_stream_key : UInt = 0x02

///|
pub let inner_field_binary : UInt = 0x03

///|
pub struct InnerHeader {
  random_stream_id : UInt
  random_stream_key : Bytes
  binaries : Array[Bytes]
  byte_length : Int
}

///|
pub fn InnerHeader::random_stream_id(self : InnerHeader) -> UInt {
  self.random_stream_id
}

///|
pub fn InnerHeader::random_stream_key(self : InnerHeader) -> Bytes {
  self.random_stream_key
}

///|
/// Attachments, in file order. Each keeps the one-byte flags that precede the
/// payload stripped off.
pub fn InnerHeader::binaries(self : InnerHeader) -> Array[Bytes] {
  self.binaries.copy()
}

///|
/// Number of bytes the inner header occupies; the XML document follows.
pub fn InnerHeader::byte_length(self : InnerHeader) -> Int {
  self.byte_length
}

///|
/// Parses the inner header and returns it together with the XML that follows.
///
/// Unknown field identifiers are skipped rather than rejected: the format is
/// explicitly extensible, and a reader that refuses new fields cannot read new
/// files.
pub fn split_payload(payload : Bytes) -> (InnerHeader, Bytes) raise KdbxError {
  let reader = ByteReader::new(payload)
  let binaries : Array[Bytes] = []
  let mut random_stream_id : UInt = 0
  let mut random_stream_key : Bytes = Bytes::makei(0, fn(_) { 0 })
  let mut done = false
  while !done {
    let field = reader.read_byte()
    if field == 0 {
      // The terminator is a lone zero byte, not a zero-sized field.
      done = true
    } else {
      let size = reader.read_u32_le().reinterpret_as_int()
      match field {
        n if n == inner_field_stream_id =>
          if size != 4 {
            raise Malformed("random stream identifier is not a 4-byte integer")
          } else {
            random_stream_id = reader.read_u32_le()
          }
        n if n == inner_field_stream_key =>
          random_stream_key = reader.read_bytes(size)
        n if n == inner_field_binary => {
          // One byte of flags, then the attachment payload.
          let _flags = reader.read_byte()
          binaries.push(reader.read_bytes(size - 1))
        }
        _ => reader.read_bytes(size) |> ignore
      }
    }
  }
  (
    {
      random_stream_id,
      random_stream_key,
      binaries,
      byte_length: reader.offset(),
    },
    reader.read_rest(),
  )
}
