///|
/// The HMAC-protected block stream that carries the encrypted payload
/// (KDBX 4.1, "HMAC-Protected Block Stream").
///
/// Each block is a 32-byte tag, then the block index and the length, then the
/// ciphertext. The tag is computed over the index, the length and the
/// ciphertext with a key derived from the block index, so blocks cannot be
/// reordered, truncated or replayed without detection.

///|
/// Verifies every block and returns the concatenated ciphertext.
pub fn read_block_stream(
  data : Bytes,
  hmac_key_base : Bytes,
  with_index : Bool,
) -> Bytes raise KdbxError {
  if hmac_key_base.length() != 64 {
    raise Malformed(
      "HMAC key base must be 64 bytes, got " +
      hmac_key_base.length().to_string(),
    )
  }
  let reader = ByteReader::new(data)
  // The ciphertext is shorter than the stream that carries it, so one buffer of
  // the stream's length is always enough. It is filled by index and trimmed at
  // the end, which keeps the whole payload out of the allocator's way.
  let out : Array[Byte] = []
  let mut prepared = 0
  while prepared < data.length() {
    out.push(0)
    prepared = prepared + 1
  }
  let mut written = 0
  let mut index : UInt64 = 0
  let mut done = false
  while !done {
    let stored_tag = reader.read_bytes(32)
    // KDBX 4.1 stores the block index explicitly; KDBX 4.0 leaves it implicit
    // and only authenticates it.
    if with_index {
      let block_index = reader.read_u64_le()
      if block_index != index {
        raise Malformed(
          "block index \{block_index} where \{index} was expected",
        )
      }
    }
    let size = reader.read_u32_le()
    let payload = reader.read_bytes(size.reinterpret_as_int())
    let key = derive_block_hmac_key(hmac_key_base, index)
    let authenticated = ByteWriter::new()
    authenticated.write_u64_le(index)
    authenticated.write_u32_le(size)
    authenticated.write_bytes(payload)
    let expected = hmac_sha256(key, authenticated.to_bytes())
    if !constant_time_equal(expected, stored_tag) {
      raise Malformed("block " + index.to_string() + " failed authentication")
    }
    if size == 0 {
      done = true
    } else {
      let mut i = 0
      while i < payload.length() {
        out[written + i] = payload[i]
        i = i + 1
      }
      written = written + payload.length()
    }
    index = index + 1
  }
  Bytes::makei(written, fn(i) { out[i] })
}
