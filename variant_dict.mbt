///|
/// A value that can appear in a KDBX variant dictionary.
///
/// The variant tags mirror the wire types defined by the KDBX 4.1
/// specification (`Variant Dictionary` section): `0x04` UInt32, `0x05` UInt64,
/// `0x08` Boolean, `0x0C` Int32, `0x0D` Int64, `0x18` String, `0x42` Byte[].
pub enum VariantValue {
  VUInt32(UInt)
  VUInt64(UInt64)
  VBool(Bool)
  VInt32(Int)
  VInt64(Int64)
  VString(String)
  VBytes(Bytes)
}

///|
/// Stable, human-readable rendering used by diagnostics, tests and the CLI.
pub fn VariantValue::to_text(self : VariantValue) -> String {
  match self {
    VUInt32(v) => v.to_string()
    VUInt64(v) => v.to_string()
    VBool(v) => v.to_string()
    VInt32(v) => v.to_string()
    VInt64(v) => v.to_string()
    VString(v) => v
    VBytes(v) => "0x" + to_hex(v)
  }
}

///|
/// Wire type code of a variant value, as defined by the specification.
fn VariantValue::type_code(self : VariantValue) -> UInt {
  match self {
    VUInt32(_) => 0x04
    VUInt64(_) => 0x05
    VBool(_) => 0x08
    VInt32(_) => 0x0C
    VInt64(_) => 0x0D
    VString(_) => 0x18
    VBytes(_) => 0x42
  }
}

///|
/// Little-endian payload of the value, excluding type code and length prefix.
fn VariantValue::payload(self : VariantValue) -> Bytes {
  let out = ByteWriter::new()
  match self {
    VUInt32(v) => out.write_u32_le(v)
    VUInt64(v) => out.write_u64_le(v)
    VBool(v) => out.write_byte(if v { 1 } else { 0 })
    VInt32(v) => out.write_int32_le(v)
    VInt64(v) => out.write_u64_le(v.reinterpret_as_uint64())
    VString(v) => out.write_bytes(@utf8.encode(v))
    VBytes(v) => out.write_bytes(v)
  }
  out.to_bytes()
}

///|
/// An insertion-ordered name/value dictionary.
///
/// KDBX uses variant dictionaries for the KDF parameters (header field 11) and
/// for plugin data (field 12). Insertion order is preserved so that a decoded
/// header can be re-encoded byte-for-byte, which keeps the header HMAC check
/// meaningful for round-trip tests.
pub struct VariantDict {
  entries : Array[(String, VariantValue)]
}

///|
pub fn VariantDict::new() -> VariantDict {
  { entries: [], }
}

///|
pub fn VariantDict::length(self : VariantDict) -> Int {
  self.entries.length()
}

///|
pub fn VariantDict::entries(
  self : VariantDict,
) -> Array[(String, VariantValue)] {
  self.entries.copy()
}

///|
/// Inserts or replaces an entry, keeping the position of an existing name.
/// Renders the dictionary as `name=value` lines, in insertion order.
pub fn VariantDict::to_text(self : VariantDict) -> String {
  let out = StringBuilder()
  for entry in self.entries {
    let (name, value) = entry
    out.write_string(name)
    out.write_string("=")
    out.write_string(value.to_text())
    out.write_string("\n")
  }
  out.to_string()
}

///|
pub fn VariantDict::set(
  self : VariantDict,
  name : String,
  value : VariantValue,
) -> Unit {
  let mut i = 0
  let mut replaced = false
  while i < self.entries.length() && !replaced {
    let (key, _) = self.entries[i]
    if key == name {
      self.entries[i] = (name, value)
      replaced = true
    }
    i = i + 1
  }
  if !replaced {
    self.entries.push((name, value))
  }
}

///|
pub fn VariantDict::get(self : VariantDict, name : String) -> VariantValue? {
  let mut found : VariantValue? = None
  let mut i = 0
  while i < self.entries.length() && found is None {
    let (key, value) = self.entries[i]
    if key == name {
      found = Some(value)
    }
    i = i + 1
  }
  found
}

///|
pub fn VariantDict::get_uint64(self : VariantDict, name : String) -> UInt64? {
  match self.get(name) {
    Some(VUInt64(v)) => Some(v)
    Some(VUInt32(v)) => Some(v.to_uint64())
    _ => None
  }
}

///|
pub fn VariantDict::get_uint32(self : VariantDict, name : String) -> UInt? {
  match self.get(name) {
    Some(VUInt32(v)) => Some(v)
    _ => None
  }
}

///|
pub fn VariantDict::get_bytes(self : VariantDict, name : String) -> Bytes? {
  match self.get(name) {
    Some(VBytes(v)) => Some(v)
    _ => None
  }
}

///|
/// Version 1.0 of the variant dictionary format: major in the high byte.
let variant_dict_version : UInt = 0x0100

///|
/// Decodes a variant dictionary, raising `KdbxError` on truncated or
/// inconsistent input.
pub fn decode_variant_dict(data : Bytes) -> VariantDict raise KdbxError {
  let reader = ByteReader::new(data)
  let version = reader.read_u16_le()
  let major = version >> 8
  if major != 1 {
    raise Unsupported(
      "variant dictionary major version " +
      major.to_string() +
      " (this build knows 1)",
    )
  }
  let dict = VariantDict::new()
  let mut done = false
  while !done {
    let type_code = reader.read_byte()
    if type_code == 0 {
      done = true
    } else {
      let name_size = reader.read_int32_le()
      let name = utf8_text(reader.read_bytes(name_size))
      let value_size = reader.read_int32_le()
      let payload = reader.read_bytes(value_size)
      dict.set(name, decode_variant_value(type_code, payload))
    }
  }
  dict
}

///|
fn decode_variant_value(
  type_code : UInt,
  payload : Bytes,
) -> VariantValue raise KdbxError {
  let reader = ByteReader::new(payload)
  match type_code {
    0x04 => VUInt32(reader.read_u32_le())
    0x05 => VUInt64(reader.read_u64_le())
    0x08 => VBool(reader.read_byte() != 0)
    0x0C => VInt32(reader.read_int32_le())
    0x0D => VInt64(reader.read_int64_le())
    0x18 => VString(utf8_text(payload))
    0x42 => VBytes(payload)
    _ =>
      raise Unsupported(
        "variant dictionary value type 0x" + type_code.to_string(radix=16),
      )
  }
}

///|
/// Decodes a UTF-8 string, mapping a malformed sequence to `KdbxError` so that
/// corrupted input never silently loses bytes.
fn utf8_text(bytes : Bytes) -> String raise KdbxError {
  try @utf8.decode(bytes) catch {
    _ => raise Malformed("invalid UTF-8 in variant dictionary string")
  } noraise {
    text => text
  }
}

///|
/// Encodes a variant dictionary in the byte-exact form described by the
/// specification: version, items, then a null terminator.
pub fn encode_variant_dict(dict : VariantDict) -> Bytes {
  let out = ByteWriter::new()
  out.write_u16_le(variant_dict_version)
  for entry in dict.entries() {
    let (name, value) = entry
    let payload = value.payload()
    let name_bytes = @utf8.encode(name)
    out.write_byte(value.type_code())
    out.write_int32_le(name_bytes.length())
    out.write_bytes(name_bytes)
    out.write_int32_le(payload.length())
    out.write_bytes(payload)
  }
  out.write_byte(0)
  out.to_bytes()
}
