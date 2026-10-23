///|
/// Decrypting the fields that KeePass protects with the inner random stream.
///
/// The stream is shared and consumed in document order, so the walk order is
/// part of the format: decrypting fields out of order, or restarting the stream
/// per field, produces plausible nonsense rather than an error.

///|
/// The inner random stream described by the inner header.
///
/// KDBX 4 names either Salsa20 (id 2) or ChaCha20 (id 3). The key material is 64
/// bytes, of which the cipher takes 32 bytes of key and the next 12 as nonce,
/// starting at counter zero.
pub enum RandomStream {
  ChaCha(ChaCha20)
  Salsa(Salsa20)
}

///|
pub fn RandomStream::apply(self : RandomStream, data : Bytes) -> Bytes {
  match self {
    ChaCha(stream) => stream.apply(data)
    Salsa(stream) => stream.apply(data)
  }
}

///|
pub fn inner_random_stream(
  header : InnerHeader,
) -> RandomStream raise KdbxError {
  let key = header.random_stream_key()
  let id = header.random_stream_id()
  match id {
    // KeePass derives the cipher inputs from the random key: SHA-512 of the
    // key gives 32 bytes of key followed by a 12-byte nonce. Using the raw
    // key bytes instead (as the specification's wording might suggest)
    // decrypts every protected value to garbage.
    3 => {
      let derived = sha512(key)
      ChaCha(
        ChaCha20::new(
          Bytes::makei(32, fn(i) { derived[i] }),
          Bytes::makei(12, fn(i) { derived[32 + i] }),
          0,
        ),
      )
    }
    2 =>
      // Salsa20 uses SHA-256 of the random key and a fixed nonce.
      Salsa(Salsa20::new(sha256(key), hex_literal("e830094b97205d2a")))
    _ =>
      raise Unsupported(
        "inner random stream " + id.to_string() + " is not implemented",
      )
  }
}

///|
/// Decrypts every protected field of a vault, in document order.
pub fn unprotect_vault(
  vault : Vault,
  header : InnerHeader,
) -> Vault raise KdbxError {
  let stream = inner_random_stream(header)
  let groups : Array[VaultGroup] = []
  for group in vault.groups() {
    groups.push(unprotect_group(group, stream))
  }
  { groups, generator: vault.generator(), }
}

///|
fn unprotect_group(
  group : VaultGroup,
  stream : RandomStream,
) -> VaultGroup raise KdbxError {
  let entries : Array[VaultEntry] = []
  for entry in group.entries() {
    entries.push(unprotect_entry(entry, stream))
  }
  let children : Array[VaultGroup] = []
  for child in group.groups() {
    children.push(unprotect_group(child, stream))
  }
  { name: group.name(), uuid: group.uuid(), groups: children, entries, }
}

///|
fn unprotect_entry(
  entry : VaultEntry,
  stream : RandomStream,
) -> VaultEntry raise KdbxError {
  let fields : Array[VaultField] = []
  for field in entry.fields() {
    let value = if field.is_protected() {
      utf8_text(stream.apply(decode_base64(field.value())))
    } else {
      field.value()
    }
    fields.push({ key: field.key(), value, is_encrypted: field.is_protected(), })
  }
  {
    uuid: entry.uuid(),
    fields,
    last_modified: entry.last_modified().unwrap_or(""),
    expiry_time: entry.expiry_time().unwrap_or(""),
    expires: entry.expires(),
  }
}

///|
/// Decodes a protected value, which KeePass stores base64-encoded.
fn decode_base64(text : String) -> Bytes raise KdbxError {
  try @base64.decode(text) catch {
    _ => raise Malformed("protected value is not valid base64")
  } noraise {
    bytes => bytes
  }
}
