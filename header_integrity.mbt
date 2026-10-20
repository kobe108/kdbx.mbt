///|
/// Header authentication (KDBX 4.1, "Improved Header Authentication").
///
/// A KDBX 4 file stores two 32-byte values right after the outer header: a
/// SHA-256 of the header, and an HMAC-SHA-256 of the header keyed from the
/// master key. The first detects accidental corruption without any credentials;
/// the second is what makes the header trustworthy, and it is the first thing
/// that fails when the password is wrong.

///|
/// What verifying a header established about the database it belongs to.
pub struct HeaderVerification {
  revision : String
  cipher : Cipher
  compression : Compression
  kdf_rounds : UInt64
}

///|
pub fn HeaderVerification::revision(self : HeaderVerification) -> String {
  self.revision
}

///|
pub fn HeaderVerification::cipher(self : HeaderVerification) -> Cipher {
  self.cipher
}

///|
pub fn HeaderVerification::compression(
  self : HeaderVerification,
) -> Compression {
  self.compression
}

///|
pub fn HeaderVerification::kdf_rounds(self : HeaderVerification) -> UInt64 {
  self.kdf_rounds
}

///|
/// Everything the caller needs in order to keep reading a database: the facts
/// established about the header, plus the keys derived from the credentials.
pub struct OpenedHeader {
  verification : HeaderVerification
  iv : Bytes
  header_length : Int
  encryption_key : Bytes
  hmac_key_base : Bytes
}

///|
pub fn OpenedHeader::verification(self : OpenedHeader) -> HeaderVerification {
  self.verification
}

///|
pub fn OpenedHeader::cipher(self : OpenedHeader) -> Cipher {
  self.verification.cipher()
}

///|
pub fn OpenedHeader::compression(self : OpenedHeader) -> Compression {
  self.verification.compression()
}

///|
pub fn OpenedHeader::iv(self : OpenedHeader) -> Bytes {
  self.iv
}

///|
pub fn OpenedHeader::header_length(self : OpenedHeader) -> Int {
  self.header_length
}

///|
pub fn OpenedHeader::encryption_key(self : OpenedHeader) -> Bytes {
  self.encryption_key
}

///|
/// Key material for the HMAC-protected block stream.
pub fn OpenedHeader::hmac_key_base(self : OpenedHeader) -> Bytes {
  self.hmac_key_base
}

///|
/// Verifies the header and derives every key the payload needs.
///
/// Fails for a wrong password and for a modified header in the same way, on
/// purpose: telling those apart would tell an attacker which half of a guess was
/// right.
pub fn open_header(
  data : Bytes,
  key : MasterKey,
) -> OpenedHeader raise KdbxError {
  let header = parse_outer_header(data)
  let header_bytes = read_range(data, 0, header.byte_length())
  let stored_hash = read_range(data, header.byte_length(), 32)
  if !constant_time_equal(sha256(header_bytes), stored_hash) {
    raise Malformed("header hash mismatch: the file is corrupted")
  }
  let kdf = header.kdf_parameters()
  let transformed = transform_with_kdf(kdf, key.composite())
  let rounds = match kdf.get_uint64("R") {
    Some(value) => value
    None => 0UL
  }
  let master_seed = header.master_seed()
  let base = derive_hmac_key_base(master_seed, transformed)
  let header_key = derive_header_hmac_key(base)
  let stored_hmac = read_range(data, header.byte_length() + 32, 32)
  if !constant_time_equal(hmac_sha256(header_key, header_bytes), stored_hmac) {
    raise Malformed(
      "header authentication failed: wrong master key or modified header",
    )
  }
  let cipher = header.cipher()
  {
    verification: {
      revision: header.revision(),
      cipher,
      compression: header.compression(),
      kdf_rounds: rounds,
    },
    iv: header.encryption_iv(),
    header_length: header.byte_length(),
    encryption_key: derive_encryption_key(master_seed, transformed),
    hmac_key_base: base,
  }
}

///|
/// Verifies that the header of `data` is intact and authentic.
///
/// On success the caller knows the header was produced by someone holding the
/// master key, so every parameter read from it can be used. A wrong password
/// and a modified header fail the same check on purpose: distinguishing them
/// would tell an attacker which half of their guess was right.
pub fn verify_header(
  data : Bytes,
  key : MasterKey,
) -> HeaderVerification raise KdbxError {
  open_header(data, key).verification()
}

///|
/// Copies `count` bytes starting at `start`.
fn read_range(data : Bytes, start : Int, count : Int) -> Bytes raise KdbxError {
  if start < 0 || start + count > data.length() {
    raise Truncated("file ends before the header authentication data")
  }
  Bytes::makei(count, fn(i) { data[start + i] })
}

///|
/// Compares two byte strings without revealing where they first differ.
///
/// Comparing authentication tags with `==` would leak, through timing, how many
/// leading bytes were correct, which is exactly what an attacker needs to forge
/// a tag byte by byte. This loop always reads both inputs to the end.
pub fn constant_time_equal(a : Bytes, b : Bytes) -> Bool {
  if a.length() != b.length() {
    return false
  }
  let mut difference : UInt = 0
  for i = 0; i < a.length(); i = i + 1 {
    difference = difference | (a[i].to_uint() ^ b[i].to_uint())
  }
  difference == 0
}
