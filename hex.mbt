///|
/// Decodes a hexadecimal string, optionally grouped by spaces, tabs, newlines
/// or underscores. Returns `None` when the input is not valid hexadecimal.
///
/// The scan is written by hand instead of using `String::replace`, which only
/// replaces the first occurrence of a pattern in MoonBit.
fn decode_hex(text : String) -> Bytes? {
  let out : Array[Byte] = []
  let mut high : Int? = None
  let mut i = 0
  let mut ok = true
  while i < text.length() && ok {
    let code = text[i]
    if is_hex_digit(code) {
      match high {
        None => high = Some(hex_value(code).unwrap())
        Some(hi) => {
          out.push((hi * 16 + hex_value(code).unwrap()).to_byte())
          high = None
        }
      }
    } else if !is_separator(code) {
      ok = false
    }
    i = i + 1
  }
  if ok && high is None {
    Some(Bytes::from_array(out))
  } else {
    None
  }
}

///|
/// Whether a code unit represents a hexadecimal digit.
fn is_hex_digit(code : UInt16) -> Bool {
  let c = code.to_int()
  (c >= 0x30 && c <= 0x39) ||
  (c >= 0x61 && c <= 0x66) ||
  (c >= 0x41 && c <= 0x46)
}

///|
/// Whether a code unit may appear between hexadecimal digits.
fn is_separator(code : UInt16) -> Bool {
  let c = code.to_int()
  c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D || c == 0x5F
}

///|
/// Decodes a hexadecimal string into bytes, raising `KdbxError` on malformed
/// input. Used for command line input and for data read from a file.
pub fn bytes_from_hex(text : String) -> Bytes raise KdbxError {
  match decode_hex(text) {
    Some(bytes) => bytes
    None => raise Malformed("not valid hexadecimal: " + text)
  }
}

///|
/// Decodes a hexadecimal string that is known to be valid at compile time:
/// specification excerpts, test vectors and constant tables. A malformed
/// literal aborts the program, because it is a bug in this repository.
pub fn hex_literal(text : String) -> Bytes {
  match decode_hex(text) {
    Some(bytes) => bytes
    None => abort("malformed hexadecimal literal in source: " + text)
  }
}

///|
/// Value of a single hexadecimal digit, in `0..16`.
///
/// Indexing a `String` yields a UTF-16 code unit, so digits are matched by
/// code point rather than by character literal.
fn hex_value(code : UInt16) -> Int? {
  let c = code.to_int()
  if c >= 0x30 && c <= 0x39 {
    Some(c - 0x30)
  } else if c >= 0x61 && c <= 0x66 {
    Some(c - 0x61 + 10)
  } else if c >= 0x41 && c <= 0x46 {
    Some(c - 0x41 + 10)
  } else {
    None
  }
}

///|
/// Lowercase hexadecimal rendering of a byte buffer.
///
/// `limit` renders only the first bytes, which keeps diagnostics readable when
/// a field such as a master seed is dumped.
pub fn to_hex(bytes : Bytes, limit? : Int) -> String {
  let count = match limit {
    Some(n) => if n < bytes.length() { n } else { bytes.length() }
    None => bytes.length()
  }
  let out = StringBuilder()
  for i = 0; i < count; i = i + 1 {
    let byte = bytes[i].to_uint()
    out.write_string(hex_digits[(byte >> 4).reinterpret_as_int()])
    out.write_string(hex_digits[(byte & 0xF).reinterpret_as_int()])
  }
  out.to_string()
}

///|
let hex_digits : Array[String] = [
  "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f",
]
