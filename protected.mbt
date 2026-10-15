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
pub fn inner_random_stream(header : InnerHeader) -> ChaCha20 raise KdbxError {
  let key = header.random_stream_key()
  let id = header.random_stream_id()
  if id != 3 {
    raise Unsupported(
      "inner random stream " +
      id.to_string() +
      " is not implemented yet (only ChaCha20, id 3)",
    )
  }
  if key.length() < 44 {
    raise Malformed(
      "inner random stream key must hold at least 44 bytes, got \{key.length()}",
    )
  }
  ChaCha20::new(
    Bytes::makei(32, fn(i) { key[i] }),
    Bytes::makei(12, fn(i) { key[32 + i] }),
    0,
  )
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
  stream : ChaCha20,
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
  stream : ChaCha20,
) -> VaultEntry raise KdbxError {
  let fields : Array[VaultField] = []
  for field in entry.fields() {
    let value = if field.is_protected() {
      utf8_text(stream.apply(decode_base64(field.value())))
    } else {
      field.value()
    }
    fields.push({ key: field.key(), value, is_encrypted: false, })
  }
  { uuid: entry.uuid(), fields, }
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
