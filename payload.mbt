///|
/// Reading the encrypted payload: block stream, cipher, padding.

///|
/// Opens a database far enough to return the decrypted payload.
///
/// This is the point where a database finally becomes data: the header has been
/// authenticated, the blocks are authentic, and the payload has been decrypted
/// and unpadded. Compression and the XML model are the remaining steps
/// (docs/ROADMAP.md, F9b and F11).
pub fn decrypt_payload(data : Bytes, key : MasterKey) -> Bytes raise KdbxError {
  let opened = open_header(data, key)
  match opened.cipher() {
    Aes256Cbc => ()
    ChaCha20 =>
      raise Unsupported(
        "ChaCha20 payloads are not implemented yet (docs/ROADMAP.md)",
      )
    Other(_) => raise Unsupported("unknown cipher engine in the header")
  }
  let body_start = opened.header_length() + 64
  let body = read_range(data, body_start, data.length() - body_start)
  let ciphertext = read_block_stream(body, opened.hmac_key_base())
  let plaintext = aes256_cbc_decrypt(
    opened.encryption_key(),
    opened.iv(),
    ciphertext,
  )
  match opened.compression() {
    None => plaintext
    Gzip =>
      raise Unsupported(
        "gzip-compressed payloads are not implemented yet (docs/ROADMAP.md, F9b)",
      )
  }
}
