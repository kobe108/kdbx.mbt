///|
/// HMAC-SHA-256 (RFC 2104 with SHA-256).
///
/// KDBX authenticates both the header and every data block with HMAC-SHA-256,
/// so this is the primitive that decides whether a file can be trusted at all.
pub fn hmac_sha256(key : Bytes, message : Bytes) -> Bytes {
  let block_size = 64
  let normalized = if key.length() > block_size { sha256(key) } else { key }
  let inner_prefix = ByteWriter::new()
  let outer_prefix = ByteWriter::new()
  let mut i = 0
  while i < block_size {
    let byte = if i < normalized.length() { normalized[i].to_uint() } else { 0 }
    inner_prefix.write_byte(byte ^ 0x36)
    outer_prefix.write_byte(byte ^ 0x5C)
    i = i + 1
  }
  let inner = sha256(concat_bytes(inner_prefix.to_bytes(), message))
  sha256(concat_bytes(outer_prefix.to_bytes(), inner))
}
