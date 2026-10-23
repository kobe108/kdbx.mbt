///|
/// The KDBX parameter mapping: memory is stored in bytes, Argon2 counts KiB, and
/// the UUID decides between Argon2d and Argon2id.
test "argon2 parameters dispatch from the header" {
  let dict = VariantDict::new()
  dict.set("$UUID", VBytes(hex_literal("ef636ddf8c29444b91f7a9a403e30a0c")))
  dict.set("V", VUInt32(0x13))
  dict.set("I", VUInt64(3))
  dict.set("M", VUInt64(32 * 1024))
  dict.set("P", VUInt32(4))
  dict.set("S", VBytes(bytes_repeated(0x02, 16)))
  let composite = bytes_repeated(0x01, 32)
  // The same parameters through the direct path, with no secret and no
  // associated data, which is what a database uses.
  let direct = argon2_digest(
    {
      salt: bytes_repeated(0x02, 16),
      secret: Bytes::makei(0, fn(_) { 0 }),
      associated_data: Bytes::makei(0, fn(_) { 0 }),
      iterations: 3,
      memory_kib: 32,
      lanes: 4,
      tag_length: 32,
      version: 0x13,
      kind: Argon2d,
    },
    composite,
  )
  assert_eq(to_hex(transform_with_kdf(dict, composite)), to_hex(direct))
  // Argon2id is selected by its own UUID and yields a different key.
  dict.set("$UUID", VBytes(hex_literal("9e298b1956db4773b23dfc3ec6f0a1e6")))
  assert_true(to_hex(transform_with_kdf(dict, composite)) != to_hex(direct))
}

///|
/// The three test vectors of RFC 9106, section 5: 32 KiB, 3 passes, 4 lanes,
/// 32-byte password of 0x01, 16-byte salt of 0x02, 8-byte secret of 0x03 and
/// 12-byte associated data of 0x04.
fn rfc9106_params(kind : Argon2Kind) -> Argon2Params {
  {
    salt: bytes_repeated(0x02, 16),
    secret: bytes_repeated(0x03, 8),
    associated_data: bytes_repeated(0x04, 12),
    iterations: 3,
    memory_kib: 32,
    lanes: 4,
    tag_length: 32,
    version: 0x13,
    kind,
  }
}

///|
/// The three published tags. These exercise the data-dependent and the
/// data-independent index schedules, and the hybrid that switches between them.
test "argon2 matches the rfc 9106 vectors" {
  let password = bytes_repeated(0x01, 32)
  assert_eq(
    to_hex(argon2_digest(rfc9106_params(Argon2d), password)),
    "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb",
  )
  assert_eq(
    to_hex(argon2_digest(rfc9106_params(Argon2i), password)),
    "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8",
  )
  assert_eq(
    to_hex(argon2_digest(rfc9106_params(Argon2id), password)),
    "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
  )
}

///|
/// Cross-check Argon2id against a database written by pykeepass. This is the
/// real-header parameter set that the RFC vectors alone did not cover: 1 MiB,
/// one pass, one lane and a 32-byte salt.
test "argon2id matches real kdbx parameters" {
  let dict = VariantDict::new()
  dict.set("$UUID", VBytes(hex_literal("9e298b1956db4773b23dfc3ec6f0a1e6")))
  dict.set("V", VUInt32(0x13))
  dict.set("I", VUInt64(1))
  dict.set("M", VUInt64(1048576))
  dict.set("P", VUInt32(1))
  dict.set(
    "S",
    VBytes(
      hex_literal(
        "deed43296e18b301fa23210292049ec02e1102510b6e172b183136fb4a59a08a",
      ),
    ),
  )
  let composite = hex_literal(
    "8a89836051fdc07b0657c46a4c3e37b7be1ccfefe298fe64413154696210892e",
  )
  assert_eq(
    to_hex(transform_with_kdf(dict, composite)),
    "d8aff534a02e81ef312a5503b43b458df011653effbd3264ffeadc2a7c6e7d34",
  )
}

///|
/// Parameter validation: the way a wrong header becomes a clear error rather
/// than a silent wrong key.
test "argon2 rejects impossible parameters" {
  let password = bytes_repeated(0x01, 32)
  let short_salt = {
    salt: bytes_repeated(0x02, 4),
    secret: Bytes::makei(0, fn(_) { 0 }),
    associated_data: Bytes::makei(0, fn(_) { 0 }),
    iterations: 1,
    memory_kib: 32,
    lanes: 1,
    tag_length: 32,
    version: 0x13,
    kind: Argon2id,
  }
  try argon2_digest(short_salt, password) catch {
    Malformed(message) => assert_true(message.contains("salt"))
    e => fail("expected a salt error, got: " + e.message())
  } noraise {
    _ => fail("expected a short salt to be refused")
  }
  let no_memory = {
    salt: bytes_repeated(0x02, 16),
    secret: Bytes::makei(0, fn(_) { 0 }),
    associated_data: Bytes::makei(0, fn(_) { 0 }),
    iterations: 1,
    memory_kib: 4,
    lanes: 2,
    tag_length: 32,
    version: 0x13,
    kind: Argon2id,
  }
  try argon2_digest(no_memory, password) catch {
    Malformed(message) => assert_true(message.contains("KiB"))
    e => fail("expected a memory error, got: " + e.message())
  } noraise {
    _ => fail("expected too little memory to be refused")
  }
}
