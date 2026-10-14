///|
/// AES-256 in CBC mode with PKCS#7 padding, the default cipher of KDBX.

///|
/// Decrypts a CBC ciphertext and removes the PKCS#7 padding.
///
/// The padding is validated strictly, including in constant time, because it is
/// the classic padding-oracle surface: a caller must never learn from timing
/// whether a wrong key produced valid-looking padding.
pub fn aes256_cbc_decrypt(
  key : Bytes,
  iv : Bytes,
  ciphertext : Bytes,
) -> Bytes raise KdbxError {
  if key.length() != 32 {
    raise Malformed(
      "AES-256 needs a 32-byte key, got " + key.length().to_string(),
    )
  }
  if iv.length() != 16 {
    raise Malformed("CBC needs a 16-byte IV, got " + iv.length().to_string())
  }
  if ciphertext.length() == 0 || ciphertext.length() % 16 != 0 {
    raise Malformed(
      "CBC ciphertext must be a non-empty multiple of 16 bytes, got \{ciphertext.length()}",
    )
  }
  let cipher = Aes256Decrypt::new(key)
  // The plaintext is exactly as long as the ciphertext, so the output buffer is
  // allocated once instead of growing while a multi-megabyte payload is
  // appended block by block.
  let plaintext : Array[Byte] = []
  let mut prepared = 0
  while prepared < ciphertext.length() {
    plaintext.push(0)
    prepared = prepared + 1
  }
  let previous : Array[Byte] = []
  for i = 0; i < 16; i = i + 1 {
    previous.push(iv[i])
  }
  let block : Array[Byte] = []
  for i = 0; i < 16; i = i + 1 {
    block.push(0)
  }
  let mut offset = 0
  while offset < ciphertext.length() {
    for i = 0; i < 16; i = i + 1 {
      block[i] = ciphertext[offset + i]
    }
    cipher.decrypt_in_place(block, 0)
    // The plaintext of a block is its decrypted value XOR the previous
    // ciphertext block (the IV for the first block).
    for i = 0; i < 16; i = i + 1 {
      plaintext[offset + i] = (block[i].to_uint() ^ previous[i].to_uint()).to_byte()
    }
    for i = 0; i < 16; i = i + 1 {
      previous[i] = ciphertext[offset + i]
    }
    offset = offset + 16
  }
  unpad_pkcs7(Bytes::from_array(plaintext))
}

///|
/// Removes PKCS#7 padding after validating every padding byte.
pub fn unpad_pkcs7(data : Bytes) -> Bytes raise KdbxError {
  let length = data.length()
  if length == 0 || length % 16 != 0 {
    raise Malformed(
      "padded plaintext must be a non-empty multiple of 16 bytes, got \{length}",
    )
  }
  let padding = data[length - 1].to_uint()
  if padding == 0 || padding > 16 {
    raise Malformed("invalid PKCS#7 padding length " + padding.to_string())
  }
  // Every one of the last `padding` bytes has to equal `padding`. The loop
  // always inspects 16 bytes so that the check does not branch, and the count
  // of mismatches is accumulated instead of failed on early.
  let mut mismatches : UInt = 0
  let mut i = 0
  while i < 16 {
    if i.reinterpret_as_uint() < padding {
      mismatches = mismatches | (data[length - 1 - i].to_uint() ^ padding)
    }
    i = i + 1
  }
  if mismatches != 0 {
    raise Malformed("invalid PKCS#7 padding bytes")
  }
  Bytes::makei(length - padding.reinterpret_as_int(), fn(i) { data[i] })
}
