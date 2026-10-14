///|
/// First signature word of a KeePass 2.x database.
pub let kdbx_signature1 : UInt = 0x9AA2D903

///|
/// Second signature word. KeePass 1.x uses `0xB54BFB65`, which this build does
/// not accept.
pub let kdbx_signature2 : UInt = 0xB54BFB67

///|
/// Value stored in the end-of-header field, as required by the specification.
pub let kdbx_end_of_header_value : String = "0d0a0d0a"

///|
/// Outer header field identifiers of the KDBX 4.x format.
/// Identifiers 1, 5, 6, 8, 9 and 10 only exist in KDBX 3.1 files.
pub let field_compression : UInt = 3

///|
pub let field_master_seed : UInt = 4

///|
pub let field_encryption_iv : UInt = 7

///|
pub let field_kdf_parameters : UInt = 11

///|
pub let field_public_custom_data : UInt = 12

///|
/// Byte sequence identifying the AES-256-CBC cipher engine.
let uuid_aes256_cbc : String = "31c1f2e6bf714350be5805216afc5aff"

///|
/// Byte sequence identifying the ChaCha20 cipher engine (RFC 8439).
let uuid_chacha20 : String = "d6038a2b8b6f4cb5a524339a31dbb59a"

///|
/// The file cipher used for the encrypted body of a KDBX file.
pub enum Cipher {
  Aes256Cbc
  ChaCha20
  /// A cipher provided by a plugin; the raw 16-byte identifier is preserved.
  Other(Bytes)
}

///|
pub fn Cipher::from_uuid(id : Bytes) -> Cipher {
  let text = to_hex(id)
  if text == uuid_aes256_cbc {
    Aes256Cbc
  } else if text == uuid_chacha20 {
    ChaCha20
  } else {
    Other(id)
  }
}

///|
pub fn Cipher::to_text(self : Cipher) -> String {
  match self {
    Aes256Cbc => "AES-256-CBC"
    ChaCha20 => "ChaCha20"
    Other(id) => "plugin cipher 0x" + to_hex(id)
  }
}

///|
/// Expected IV/nonce length for the cipher, in bytes.
pub fn Cipher::iv_length(self : Cipher) -> Int {
  match self {
    Aes256Cbc => 16
    ChaCha20 => 12
    Other(_) => 16
  }
}

///|
/// Payload compression of the encrypted stream.
pub enum Compression {
  None
  Gzip
}

///|
pub fn Compression::from_flags(flags : UInt) -> Compression raise KdbxError {
  match flags {
    0 => None
    1 => Gzip
    _ => raise Unsupported("compression flag " + flags.to_string())
  }
}

///|
pub fn Compression::to_text(self : Compression) -> String {
  match self {
    None => "none"
    Gzip => "gzip"
  }
}

///|
/// The outer (unencrypted) header of a KDBX file: format version plus the raw
/// identifier/value fields, in file order.
pub struct OuterHeader {
  version : UInt
  fields : Array[(UInt, Bytes)]
  /// Number of bytes the header occupies, including the end-of-header field.
  consumed : Int
}

///|
pub fn parse_outer_header(data : Bytes) -> OuterHeader raise KdbxError {
  let reader = ByteReader::new(data)
  let signature1 = reader.read_u32_le()
  let signature2 = reader.read_u32_le()
  if signature1 != kdbx_signature1 || signature2 != kdbx_signature2 {
    raise BadSignature
  }
  let version = reader.read_u32_le()
  let major = (version >> 16) & 0xFFFF
  if major != 3 && major != 4 {
    raise UnsupportedVersion(major.reinterpret_as_int())
  }
  let fields : Array[(UInt, Bytes)] = []
  let mut done = false
  while !done {
    let id = reader.read_byte()
    let size = reader.read_u32_le()
    // The end-of-header field still carries its 4-byte marker value.
    let payload = reader.read_bytes(size.reinterpret_as_int())
    if id == 0 {
      if to_hex(payload) != kdbx_end_of_header_value {
        raise Malformed(
          "end-of-header marker is 0x\{to_hex(payload)} instead of 0x0d0a0d0a",
        )
      }
      done = true
    } else {
      fields.push((id, payload))
    }
  }
  { version, fields, consumed: reader.offset(), }
}

///|
pub fn OuterHeader::major(self : OuterHeader) -> Int {
  ((self.version >> 16) & 0xFFFF).reinterpret_as_int()
}

///|
pub fn OuterHeader::minor(self : OuterHeader) -> Int {
  (self.version & 0xFFFF).reinterpret_as_int()
}

///|
/// Human-readable format revision, e.g. `4.1`.
pub fn OuterHeader::revision(self : OuterHeader) -> String {
  "\{self.major()}.\{self.minor()}"
}

///|
pub fn OuterHeader::fields(self : OuterHeader) -> Array[(UInt, Bytes)] {
  self.fields.copy()
}

///|
pub fn OuterHeader::find(self : OuterHeader, id : UInt) -> Bytes? {
  let mut found : Bytes? = None
  let mut i = 0
  while i < self.fields.length() && found is None {
    let (field_id, payload) = self.fields[i]
    if field_id == id {
      found = Some(payload)
    }
    i = i + 1
  }
  found
}

///|
pub fn OuterHeader::cipher(self : OuterHeader) -> Cipher raise KdbxError {
  match self.find(cipher_field_id()) {
    Some(id) =>
      if id.length() != 16 {
        raise Malformed(
          "cipher identifier has " +
          id.length().to_string() +
          " bytes, expected 16",
        )
      } else {
        Cipher::from_uuid(id)
      }
    None => raise Malformed("header has no cipher identifier (field 2)")
  }
}

///|
pub fn OuterHeader::compression(
  self : OuterHeader,
) -> Compression raise KdbxError {
  match self.find(field_compression) {
    Some(payload) =>
      if payload.length() != 4 {
        raise Malformed("compression field is not a 4-byte integer")
      } else {
        Compression::from_flags(ByteReader::new(payload).read_u32_le())
      }
    None => raise Malformed("header has no compression field (field 3)")
  }
}

///|
pub fn OuterHeader::master_seed(self : OuterHeader) -> Bytes raise KdbxError {
  match self.find(field_master_seed) {
    Some(payload) =>
      if payload.length() != 32 {
        raise Malformed(
          "master seed has " +
          payload.length().to_string() +
          " bytes, expected 32",
        )
      } else {
        payload
      }
    None => raise Malformed("header has no master seed (field 4)")
  }
}

///|
pub fn OuterHeader::encryption_iv(self : OuterHeader) -> Bytes raise KdbxError {
  match self.find(field_encryption_iv) {
    Some(payload) => payload
    None => raise Malformed("header has no encryption IV (field 7)")
  }
}

///|
pub fn OuterHeader::kdf_parameters(
  self : OuterHeader,
) -> VariantDict raise KdbxError {
  match self.find(field_kdf_parameters) {
    Some(payload) => decode_variant_dict(payload)
    None => raise Malformed("header has no KDF parameters (field 11)")
  }
}

///|
/// Encodes the header in file order, appending the end-of-header marker.
pub fn OuterHeader::encode(self : OuterHeader) -> Bytes {
  let out = ByteWriter::new()
  out.write_u32_le(kdbx_signature1)
  out.write_u32_le(kdbx_signature2)
  out.write_u32_le(self.version)
  for entry in self.fields {
    let (id, payload) = entry
    out.write_byte(id)
    out.write_u32_le(payload.length().reinterpret_as_uint())
    out.write_bytes(payload)
  }
  // End-of-header field: identifier 0 and the 4-byte marker 0D 0A 0D 0A.
  out.write_byte(0)
  out.write_u32_le(4)
  out.write_byte(0x0D)
  out.write_byte(0x0A)
  out.write_byte(0x0D)
  out.write_byte(0x0A)
  out.to_bytes()
}

///|
/// Identifier of the file cipher field; exposed for the CLI and for tests.
pub fn cipher_field_id() -> UInt {
  2
}
