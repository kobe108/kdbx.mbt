///|
/// Errors raised by the KDBX container layer.
///
/// The variants are intentionally narrow: every failure mode a caller can act
/// on (wrong file, unsupported revision, truncated input) has its own case so
/// that the CLI can map them to exit codes and hints.
pub suberror KdbxError {
  /// The input is shorter than the structure being decoded.
  Truncated(String)
  /// The 8-byte file signature is not a KeePass 2.x database.
  BadSignature
  /// The major format version is not supported by this build.
  UnsupportedVersion(Int)
  /// The file is well-formed but uses a feature this build does not implement.
  Unsupported(String)
  /// The file contradicts the KDBX specification.
  Malformed(String)
}

///|
/// Renders an error as a single stable line, used by the CLI and by tests.
pub fn KdbxError::message(self : KdbxError) -> String {
  match self {
    Truncated(what) => "truncated input: " + what
    BadSignature => "not a KeePass 2.x database (bad signature)"
    UnsupportedVersion(major) =>
      "unsupported KDBX major version: " + major.to_string()
    Unsupported(what) => "unsupported feature: " + what
    Malformed(what) => "malformed file: " + what
  }
}
