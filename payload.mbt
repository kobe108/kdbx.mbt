///|
/// Reading the encrypted payload: block stream, cipher, padding.

///|
/// A fully opened database: the outer header, inner header and decoded vault.
///
/// The CLI and future report commands need the same complete path, so it is
/// assembled once here rather than repeated by every front end.
pub struct OpenedDatabase {
  outer_header : OuterHeader
  verification : HeaderVerification
  kdf_parameters : VariantDict
  inner_header : InnerHeader
  vault : Vault
}

///|
pub fn OpenedDatabase::outer_header(self : OpenedDatabase) -> OuterHeader {
  self.outer_header
}

///|
pub fn OpenedDatabase::verification(
  self : OpenedDatabase,
) -> HeaderVerification {
  self.verification
}

///|
pub fn OpenedDatabase::kdf_parameters(self : OpenedDatabase) -> VariantDict {
  self.kdf_parameters
}

///|
pub fn OpenedDatabase::inner_header(self : OpenedDatabase) -> InnerHeader {
  self.inner_header
}

///|
pub fn OpenedDatabase::vault(self : OpenedDatabase) -> Vault {
  self.vault
}

///|
/// Opens and authenticates every layer, returning the readable vault.
pub fn read_database(
  data : Bytes,
  key : MasterKey,
) -> OpenedDatabase raise KdbxError {
  let outer_header = parse_outer_header(data)
  let opened = open_header_with_outer(data, outer_header, key)
  let verification = opened.verification()
  let kdf_parameters = outer_header.kdf_parameters()
  let (inner_header, xml) = split_payload(
    decrypt_with_header(data, opened),
    opened.minor(),
  )
  let vault = unprotect_vault(parse_vault(utf8_text(xml)), inner_header)
  { outer_header, verification, kdf_parameters, inner_header, vault, }
}

///|
/// Opens a database and splits the plaintext into its two parts: the inner
/// header (random stream, attachments) and the XML document.
///
/// This is the shape the command line tool needs, and the shape the entry model
/// will consume, so it is exposed rather than repeated by every caller.
pub fn open_database(
  data : Bytes,
  key : MasterKey,
) -> (InnerHeader, Bytes) raise KdbxError {
  let opened = open_header(data, key)
  split_payload(decrypt_with_header(data, opened), opened.minor())
}

///|
/// Opens a database far enough to return the decrypted payload.
///
/// This is the point where a database finally becomes data: the header has been
/// authenticated, the blocks are authentic, and the payload has been decrypted
/// and unpadded. Compression is handled before this value is returned.
pub fn decrypt_payload(data : Bytes, key : MasterKey) -> Bytes raise KdbxError {
  let opened = open_header(data, key)
  decrypt_with_header(data, opened)
}

///|
fn decrypt_with_header(
  data : Bytes,
  opened : OpenedHeader,
) -> Bytes raise KdbxError {
  let body_start = opened.header_length() + 64
  let body = read_range(data, body_start, data.length() - body_start)
  let ciphertext = read_block_stream(
    body,
    opened.hmac_key_base(),
    opened.minor() >= 1,
  )
  // The cipher is selected by the UUID in the header; both use a 256-bit key.
  let plaintext = match opened.cipher() {
    Aes256Cbc =>
      aes256_cbc_decrypt(opened.encryption_key(), opened.iv(), ciphertext)
    ChaCha20 =>
      chacha20_decrypt(opened.encryption_key(), opened.iv(), ciphertext)
    Other(_) => raise Unsupported("unknown cipher engine in the header")
  }
  match opened.compression() {
    None => plaintext
    Gzip => gunzip(plaintext)
  }
}

///|
/// Decrypts a payload encrypted with ChaCha20 as KDBX uses it: a 32-byte key
/// derived from the master key, the 12-byte IV from the header as nonce, and the
/// block counter starting at zero. Being a stream cipher, there is no padding.
pub fn chacha20_decrypt(
  key : Bytes,
  nonce : Bytes,
  ciphertext : Bytes,
) -> Bytes raise KdbxError {
  if nonce.length() != 12 {
    raise Malformed(
      "ChaCha20 payloads need a 12-byte IV, got " + nonce.length().to_string(),
    )
  }
  ChaCha20::new(key, nonce, 0).apply(ciphertext)
}
