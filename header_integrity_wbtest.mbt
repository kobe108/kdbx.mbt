///|
/// A KDBX 4.1 file prefix produced by scripts/make_fixture.py: the outer
/// header, its SHA-256 and its HMAC-SHA-256. Password
/// "correct horse battery staple", AES-KDF with 1000 rounds, no compression.
/// The encrypted body is omitted because header authentication does not depend
/// on it: this fixture is 207 bytes of header plus 64 bytes of tags.
fn fixture() -> Bytes {
  hex_literal(
    "03d9a29a67fb4bb501000400021000000031c1f2e6bf714350be5805216afc5aff0304000000000000000420000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f0710000000101112131415161718191a1b1c1d1e1f0b5d00000000014205000000245555494410000000c9d9f39a628a4460bf740d08c18a4fea42010000005320000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f05010000005208000000e8030000000000000000040000000d0a0d0af5206f3f8783f00ba4e6c5932b0db51ae187c585fd3f9d6ff6577b7baee4da1fd611ca4c579161c6f9f10dda06a4b495d10f8d48df6823608de5cb6139a8e013",
  )
}

///|
/// Length of the header inside the fixture; the 64 bytes after it are the two
/// authentication tags.
let fixture_header_length : Int = 207

///|
fn fixture_password() -> MasterKey {
  MasterKey::new().with_password("correct horse battery staple")
}

///|
fn flip_byte(data : Bytes, index : Int) -> Bytes {
  let out = ByteWriter::new()
  for i = 0; i < data.length(); i = i + 1 {
    if i == index {
      out.write_byte(data[i].to_uint() ^ 0x01)
    } else {
      out.write_byte(data[i].to_uint())
    }
  }
  out.to_bytes()
}

///|
fn replace_range(data : Bytes, start : Int, replacement : Bytes) -> Bytes {
  let out = ByteWriter::new()
  for i = 0; i < data.length(); i = i + 1 {
    if i >= start && i < start + replacement.length() {
      out.write_byte(replacement[i - start].to_uint())
    } else {
      out.write_byte(data[i].to_uint())
    }
  }
  out.to_bytes()
}

///|
fn prefix(data : Bytes, count : Int) -> Bytes {
  Bytes::makei(count, fn(i) { data[i] })
}

///|
/// The happy path: the header authenticates, and everything the caller needs in
/// order to continue reading can be taken from it.
test "a generated kdbx 4.1 file authenticates its header" {
  let info = verify_header(fixture(), fixture_password())
  assert_eq(info.revision(), "4.1")
  assert_eq(info.cipher().to_text(), "AES-256-CBC")
  assert_eq(info.compression().to_text(), "none")
  assert_eq(info.kdf_rounds(), 1000)
}

///|
/// A wrong password must fail as an authentication failure, and a *modified*
/// header must fail the same way: saying which of the two happened would tell an
/// attacker whether a guessed password was right.
test "a wrong password fails authentication" {
  let wrong = MasterKey::new().with_password("correct horse battery stapl")
  try verify_header(fixture(), wrong) catch {
    Malformed(message) => assert_true(message.contains("authentication"))
    e => fail("expected a Malformed error, got: " + e.message())
  } noraise {
    _ => fail("expected the wrong password to fail authentication")
  }
}

///|
/// Corruption, tampering and truncation each have to be caught.
test "tampering is detected" {
  // One flipped byte inside the header.
  try verify_header(flip_byte(fixture(), 40), fixture_password()) catch {
    Malformed(message) => assert_true(message.contains("hash mismatch"))
    e => fail("expected a hash mismatch, got: " + e.message())
  } noraise {
    _ => fail("expected a modified header to be rejected")
  }
  // One flipped byte inside the stored hash.
  try
    verify_header(
      flip_byte(fixture(), fixture_header_length),
      fixture_password(),
    )
  catch {
    Malformed(message) => assert_true(message.contains("hash mismatch"))
    e => fail("expected a hash mismatch, got: " + e.message())
  } noraise {
    _ => fail("expected a modified hash to be rejected")
  }
  // One flipped byte inside the stored HMAC.
  try
    verify_header(
      flip_byte(fixture(), fixture().length() - 1),
      fixture_password(),
    )
  catch {
    Malformed(message) => assert_true(message.contains("authentication"))
    e => fail("expected an authentication failure, got: " + e.message())
  } noraise {
    _ => fail("expected a modified HMAC to be rejected")
  }
  // The interesting case: tamper with the header *and* repair the hash. The
  // hash check is satisfied, so only the HMAC can catch it.
  let tampered = flip_byte(fixture(), 40)
  let repaired = replace_range(
    tampered,
    fixture_header_length,
    sha256(prefix(tampered, fixture_header_length)),
  )
  try verify_header(repaired, fixture_password()) catch {
    Malformed(message) => assert_true(message.contains("authentication"))
    e =>
      fail("expected the HMAC to catch a repaired header, got: " + e.message())
  } noraise {
    _ => fail("expected a repaired header to still fail authentication")
  }
  // A file that ends in the middle of the authentication data.
  try
    verify_header(
      prefix(fixture(), fixture_header_length + 32 + 8),
      fixture_password(),
    )
  catch {
    Truncated(_) => ()
    e => fail("expected a Truncated error, got: " + e.message())
  } noraise {
    _ => fail("expected a truncated file to be rejected")
  }
}

///|
test "constant time comparison agrees with equality" {
  assert_true(
    constant_time_equal(hex_literal("00112233"), hex_literal("00112233")),
  )
  assert_true(
    !constant_time_equal(hex_literal("00112233"), hex_literal("00112234")),
  )
  assert_true(
    !constant_time_equal(hex_literal("00112233"), hex_literal("001122")),
  )
}

///|
/// KDBX 3.1 files are a different layout: field lengths are two bytes wide and
/// the header is hashed rather than authenticated. Reading one with the KDBX 4
/// parser would produce nonsense, so it must be refused with a clear reason.
test "kdbx 3.1 files are refused explicitly" {
  try parse_outer_header(hex_literal("03d9a29a67fb4bb501000300")) catch {
    Unsupported(message) => assert_true(message.contains("3.1"))
    e => fail("expected an Unsupported error, got: " + e.message())
  } noraise {
    _ => fail("expected KDBX 3.1 to be refused")
  }
}
