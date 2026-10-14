///|
/// Builds AES-KDF parameters the way they appear in a header: a variant
/// dictionary carrying the AES-KDF identifier, the seed and the round count.
fn sample_kdf(seed : Bytes, rounds : UInt64) -> AesKdf raise KdbxError {
  let dict = VariantDict::new()
  dict.set("$UUID", VBytes(hex_literal("c9d9f39a628a4460bf740d08c18a4fea")))
  dict.set("S", VBytes(seed))
  dict.set("R", VUInt64(rounds))
  aes_kdf_from_parameters(dict)
}

///|
/// The password component and the composite key, checked against the value
/// produced by two independent implementations (Python hashlib/SHA-256 and
/// .NET's SHA256).
test "composite master key matches the reference" {
  let password = "correct horse battery staple"
  assert_eq(
    to_hex(sha256(@utf8.encode(password))),
    "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a",
  )
  let key = MasterKey::new().with_password(password)
  assert_eq(key.component_count(), 1)
  assert_eq(
    to_hex(key.composite()),
    "b867db875479bcc0287352cdaa4a1755689b8338777d0915e9acd9f6edbc96cb",
  )
  // A password plus a key-file component: the components are concatenated in
  // the order they were added.
  let two = MasterKey::new()
    .with_password(password)
    .with_component(sequence_bytes(32, 1, 0))
  assert_eq(
    to_hex(two.composite()),
    "83d5af005a82839ef2336d0d4d48f817d818f05a16bc9762e06d03028ff5c662",
  )
}

///|
/// AES-KDF vectors. Round counts stay small on purpose: a real database uses
/// millions of rounds, and the correctness of the loop does not depend on how
/// many times it runs. The same inputs were run through Python and through
/// .NET, and both produced exactly these values.
test "aes-kdf transform matches the reference vectors" {
  let composite = MasterKey::new()
    .with_password("correct horse battery staple")
    .composite()
  let seed = sequence_bytes(32, 1, 0)
  assert_eq(
    to_hex(sample_kdf(seed, 1).transform(composite)),
    "fdc47a0e03b8ee294ffcc0d165b4186cc5d14f5aa4e45e24bf1d05539c1988f1",
  )
  assert_eq(
    to_hex(sample_kdf(seed, 2).transform(composite)),
    "11003e9bd18c67a2409fb7b4d1f3bf81b2491d01515a9959858ff87cc80a186e",
  )
  assert_eq(
    to_hex(sample_kdf(seed, 10).transform(composite)),
    "0096b38f506402af69cc88a36bfb55b06baa7f8a6b59f6bdc77b7083ad2d63cd",
  )
  assert_eq(
    to_hex(sample_kdf(seed, 1000).transform(composite)),
    "1cc9e9edb4cfd32ae8d2410c752f51fe90169a786cfd8e1d4cdff0a0e0fc895c",
  )
  let two = MasterKey::new()
    .with_password("correct horse battery staple")
    .with_component(sequence_bytes(32, 1, 0))
    .composite()
  assert_eq(
    to_hex(sample_kdf(seed, 64).transform(two)),
    "ffa3f128f7f2041cde25616df08696d942e36a5e6ed2a4c6f06aef2c95b76202",
  )
}

///|
/// The keys derived from the transformed key. The header key protects the
/// header, and each block key is bound to its block index.
test "derived keys match the reference vectors" {
  let composite = MasterKey::new()
    .with_password("correct horse battery staple")
    .composite()
  let transformed = sample_kdf(sequence_bytes(32, 1, 0), 1000).transform(
    composite,
  )
  let master_seed = sequence_bytes(32, 1, 16)
  assert_eq(
    to_hex(derive_encryption_key(master_seed, transformed)),
    "82e1c09bd3159d4468ba86f7dcfffebc9716c018db282a167b5af8553cf7e652",
  )
  let base = derive_hmac_key_base(master_seed, transformed)
  assert_eq(
    to_hex(base),
    "866927ab5cc31ff6ad7d46a8c4d092b2b81d95d5b2a3ed63a2bc25de1bb444c38529d455d30e976534140f4da9f9c26c6ab45d1d6903cfebd574c1f6eb41cb41",
  )
  assert_eq(
    to_hex(derive_header_hmac_key(base)),
    "81fabd5d20a4a9927de0c0df2b64da962594628d5c27d06a7f0e93ac2a84bc431ef42ea666538a979cb083cbbfd90f086a8f8da4e1f12c8498190512c6a57daf",
  )
  assert_eq(
    to_hex(derive_block_hmac_key(base, 0)),
    "354703e3403af7e8f05d0222fda5e355d360c2237c9366881cbc317558eb5733cf1985957b3215e8c0c90c8a1964f4b36bc70793da12cdba38a913a0c1e421e8",
  )
  assert_eq(
    to_hex(derive_block_hmac_key(base, 1)),
    "7b76f4ac1239f62f8afdc4ba6aa2c058992eabf84c2e9bc3a2cb10e3b6e4e2a3f5638b62a52c255e1687a5c0ee9816592e331c37dee869786738d92087fc4b84",
  )
}

///|
/// A database this build cannot open must say so, instead of reporting a wrong
/// password: Argon2 is the default KDF of recent KeePass versions.
test "unsupported and malformed kdf parameters are reported" {
  let argon2 = VariantDict::new()
  argon2.set("$UUID", VBytes(hex_literal("ef636ddf8c29444b91f7a9a403e30a0c")))
  try aes_kdf_from_parameters(argon2) catch {
    Unsupported(message) => assert_true(message.contains("Argon2"))
    e => fail("expected an Unsupported error, got: " + e.message())
  } noraise {
    _ => fail("expected Argon2 to be reported as unsupported")
  }
  let short_seed = VariantDict::new()
  short_seed.set(
    "$UUID",
    VBytes(hex_literal("c9d9f39a628a4460bf740d08c18a4fea")),
  )
  short_seed.set("S", VBytes(hex_literal("00112233")))
  short_seed.set("R", VUInt64(10))
  try aes_kdf_from_parameters(short_seed) catch {
    Malformed(message) => assert_true(message.contains("32 bytes"))
    e => fail("expected a Malformed error, got: " + e.message())
  } noraise {
    _ => fail("expected a short seed to be rejected")
  }
  let no_rounds = VariantDict::new()
  no_rounds.set(
    "$UUID",
    VBytes(hex_literal("c9d9f39a628a4460bf740d08c18a4fea")),
  )
  no_rounds.set("S", VBytes(sequence_bytes(32, 1, 0)))
  try aes_kdf_from_parameters(no_rounds) catch {
    Malformed(message) => assert_true(message.contains("round"))
    e => fail("expected a Malformed error, got: " + e.message())
  } noraise {
    _ => fail("expected a missing round count to be rejected")
  }
  try MasterKey::new().composite() catch {
    Malformed(_) => ()
    e =>
      fail("expected an empty master key to be rejected, got: " + e.message())
  } noraise {
    _ => fail("expected an empty master key to be rejected")
  }
}
