///|
/// Composite master key and key derivation (KDBX 4.1, "Computation of Keys").
///
/// The chain is: components -> composite key `R` -> KDF transform `T` ->
/// encryption key and HMAC keys. Every step is a pure function of the header
/// and the user's credentials, which is what makes a file verifiable at all.

///|
/// Identifier of the AES key derivation function.
let kdf_uuid_aes : String = "c9d9f39a628a4460bf740d08c18a4fea"

///|
/// Identifiers of the Argon2 variants. They are recognised so that a database
/// using them fails with a clear message instead of a wrong password error.
let kdf_uuid_argon2d : String = "ef636ddf8c29444b91f7a9a403e30a0c"

///|
let kdf_uuid_argon2id : String = "9e298b1956db4773b23dfc3ec6f0a1e6"

///|
/// The user's credentials, as a list of components concatenated before hashing.
///
/// KeePass accepts a password, a key file, a key provider or a Windows account
/// key, in that order. Components are kept in the order they were added, which
/// is what the specification requires.
pub struct MasterKey {
  components : Array[Bytes]
}

///|
pub fn MasterKey::new() -> MasterKey {
  { components: [], }
}

///|
/// Adds a password component: the SHA-256 of the UTF-8 encoded password.
pub fn MasterKey::with_password(
  self : MasterKey,
  password : String,
) -> MasterKey {
  {
    components: append_component(
      self.components,
      sha256(@utf8.encode(password)),
    ),
  }
}

///|
/// Adds an already-derived 32-byte component, for example the key read from a
/// key file. Key file formats themselves are a later milestone (docs/ROADMAP.md).
pub fn MasterKey::with_component(
  self : MasterKey,
  component : Bytes,
) -> MasterKey {
  { components: append_component(self.components, component), }
}

///|
/// Number of components added so far.
pub fn MasterKey::component_count(self : MasterKey) -> Int {
  self.components.length()
}

///|
/// `R`: the SHA-256 of the concatenated components.
pub fn MasterKey::composite(self : MasterKey) -> Bytes raise KdbxError {
  if self.components.length() == 0 {
    raise Malformed("master key needs at least one component")
  }
  let out = ByteWriter::new()
  for component in self.components {
    out.write_bytes(component)
  }
  sha256(out.to_bytes())
}

///|
fn append_component(
  components : Array[Bytes],
  component : Bytes,
) -> Array[Bytes] {
  let out = components.copy()
  out.push(component)
  out
}

///|
/// Parameters of the AES key derivation function, as stored in the header.
pub struct AesKdf {
  seed : Bytes
  rounds : UInt64
}

///|
/// Reads the AES-KDF parameters out of a header variant dictionary.
///
/// Unsupported functions are reported as such: the caller learns that the file
/// is fine but this build cannot open it, rather than getting a bogus
/// "wrong password".
pub fn aes_kdf_from_parameters(dict : VariantDict) -> AesKdf raise KdbxError {
  let uuid = match dict.get_bytes("$UUID") {
    Some(value) => to_hex(value)
    None => raise Malformed("KDF parameters have no $UUID")
  }
  if uuid != kdf_uuid_aes {
    if uuid == kdf_uuid_argon2d || uuid == kdf_uuid_argon2id {
      raise Unsupported(
        "Argon2 key derivation (0x" + uuid + ") is not implemented yet",
      )
    }
    raise Unsupported("unknown key derivation function 0x" + uuid)
  }
  let seed = match dict.get_bytes("S") {
    Some(value) => value
    None => raise Malformed("AES-KDF parameters have no seed (S)")
  }
  if seed.length() != 32 {
    raise Malformed(
      "AES-KDF seed must be 32 bytes, got " + seed.length().to_string(),
    )
  }
  let rounds = match dict.get_uint64("R") {
    Some(value) => value
    None => raise Malformed("AES-KDF parameters have no round count (R)")
  }
  { seed, rounds, }
}

///|
/// Number of rounds this KDF will run.
pub fn AesKdf::rounds(self : AesKdf) -> UInt64 {
  self.rounds
}

///|
/// `T`: the transformation of the composite key.
///
/// Each round encrypts both 16-byte halves of the buffer with AES-256 in ECB
/// mode, keyed by the seed from the header, and feeds the result back in. The
/// round count is what turns a password into something expensive to guess, so
/// this loop is the hot path of the whole program: it allocates nothing.
pub fn AesKdf::transform(
  self : AesKdf,
  composite : Bytes,
) -> Bytes raise KdbxError {
  if composite.length() != 32 {
    raise Malformed(
      "composite key must be 32 bytes, got " + composite.length().to_string(),
    )
  }
  let cipher = Aes256::new(self.seed)
  let buffer : Array[Byte] = []
  for i = 0; i < 32; i = i + 1 {
    buffer.push(composite[i])
  }
  let mut round : UInt64 = 0
  while round < self.rounds {
    cipher.encrypt_in_place(buffer, 0)
    cipher.encrypt_in_place(buffer, 16)
    round = round + 1
  }
  Bytes::from_array(buffer)
}

///|
/// The 256-bit file encryption key: `SHA-256(master seed  T)`.
pub fn derive_encryption_key(
  master_seed : Bytes,
  transformed : Bytes,
) -> Bytes raise KdbxError {
  require_32(master_seed, "master seed")
  require_32(transformed, "transformed key")
  sha256(concat_bytes(master_seed, transformed))
}

///|
/// The 64-byte base for the HMAC keys: `SHA-512(master seed  T  0x01)`.
pub fn derive_hmac_key_base(
  master_seed : Bytes,
  transformed : Bytes,
) -> Bytes raise KdbxError {
  require_32(master_seed, "master seed")
  require_32(transformed, "transformed key")
  let out = ByteWriter::new()
  out.write_bytes(master_seed)
  out.write_bytes(transformed)
  out.write_byte(0x01)
  sha512(out.to_bytes())
}

///|
/// Key that authenticates the header: `SHA-512(0xFF x8  base)`.
pub fn derive_header_hmac_key(base : Bytes) -> Bytes raise KdbxError {
  require_64(base, "HMAC key base")
  let out = ByteWriter::new()
  let mut i = 0
  while i < 8 {
    out.write_byte(0xFF)
    i = i + 1
  }
  out.write_bytes(base)
  sha512(out.to_bytes())
}

///|
/// Key that authenticates data block number `index`: `SHA-512(index  base)`.
///
/// The index is little-endian and the key is derived per block, so a block
/// cannot be silently reordered or replayed.
pub fn derive_block_hmac_key(
  base : Bytes,
  index : UInt64,
) -> Bytes raise KdbxError {
  require_64(base, "HMAC key base")
  let out = ByteWriter::new()
  out.write_u64_le(index)
  out.write_bytes(base)
  sha512(out.to_bytes())
}

///|
fn require_32(value : Bytes, what : String) -> Unit raise KdbxError {
  if value.length() != 32 {
    raise Malformed(
      what + " must be 32 bytes, got " + value.length().to_string(),
    )
  }
}

///|
fn require_64(value : Bytes, what : String) -> Unit raise KdbxError {
  if value.length() != 64 {
    raise Malformed(
      what + " must be 64 bytes, got " + value.length().to_string(),
    )
  }
}
